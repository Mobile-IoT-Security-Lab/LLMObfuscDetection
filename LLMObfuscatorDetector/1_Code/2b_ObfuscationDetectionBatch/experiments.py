#!/usr/bin/env python3
from pathlib import Path
from dotenv  import load_dotenv
import argparse
import datetime
import json
import openai
import sys
import time
import traceback

# Custom Imports
scriptDir   = Path(__file__).resolve().parent
codeDir     = scriptDir.parent
projectRoot = codeDir.parent
sys.path.append(str(codeDir))
import AppUtils
import LLMUtils
from AnalysisUtils import AnalysisUtils, ObfuscationDetectionAnalysisUtils

##### PARAMETERS #####
# Context Window Size
CONTEXT_WINDOW_SIZE = 128000
CONTEXT_THRESHOLD   = 0.8 * CONTEXT_WINDOW_SIZE

# To computer the minimum number of classes for statistically significant random sample
CONFIDENCE_LEVEL = 95
ERROR_MARGIN     = 5

# Threshold for obfuscation detection
OBFUSCATION_THRESHOLD = 0.3

# Filtering [None | "system" | "tp" | "both" | "pkgNameOnly"]
FILTERING = "both"

# Sampling
RANDOM_SEED    = 4316

# LLM Robustness
NUM_ITERATIONS = 3
MAX_RETRIES    = 3

# Logging
SILENT_MODE = False

# TMP folder for decompilation and intermediate files (will be automatically created if not exists)
TMP_PATH = projectRoot / "0_Data" / "TMP"

# Prompts to be used
PROMPTS_PATH = codeDir / "prompt.yaml"
DEFAULT_PROMPT_ID = "ObfuscationDetectionV2"

# Batch API parameters
BATCH_ENDPOINT = "/v1/chat/completions"
BATCH_COMPLETION_WINDOW = "24h"
BATCH_MAX_REQUESTS = 50000
BATCH_MAX_FILE_BYTES = 190 * 1024 * 1024


try:
	sys.stdout.reconfigure(line_buffering=True)
	sys.stderr.reconfigure(line_buffering=True)
except AttributeError:
	pass


class FriendlyArgumentParser(argparse.ArgumentParser):
	def error(self, message):
		self.print_usage(sys.stderr)
		self.exit(2, "\n--- ❌ Argument error: {}\n--- 💡 Use --help for the full CLI reference.\n".format(message))


def buildArgumentParser():
	parser = FriendlyArgumentParser(
		description="Run binary obfuscation detection campaigns using the OpenAI Batch API.",
		formatter_class=argparse.RawTextHelpFormatter,
		epilog=(
			"Example:\n"
			"  python experiments.py \\\n"
			"    --input-root ../../0_Data/InputApks \\\n"
			"    --models gpt-5-mini \\\n"
			"    --prompt-ids ObfuscationDetectionV1 ObfuscationDetectionV2 \\\n"
			"    --output-folder ../../0_Data/Results\n"
		)
	)
	parser.add_argument("--input-root", required=True, help="Folder containing one subfolder per obfuscation technique.")
	parser.add_argument("--models", nargs="+", required=True, help="OpenAI model IDs to include in the shared Batch campaign.")
	parser.add_argument("--prompt-ids", nargs="+", required=True, help="Prompt IDs from prompt.yaml to include in the shared Batch campaign.")
	parser.add_argument("--output-folder", required=True, help="Base folder where PROMPT_ID/TECHNIQUE/results_<MODEL>.json/csv will be written.")
	parser.add_argument("--poll-interval", type=int, default=60, help="Seconds between Batch API status checks. Default: 60.")
	return parser


def validateArgs(args):
	inputRoot = Path(args.input_root).expanduser().resolve()
	outputFolder = Path(args.output_folder).expanduser().resolve()

	if not inputRoot.exists():
		raise ValueError("INPUT_ROOT does not exist: {}".format(inputRoot))
	if not inputRoot.is_dir():
		raise ValueError("INPUT_ROOT must be a directory: {}".format(inputRoot))
	if not PROMPTS_PATH.exists():
		raise ValueError("prompt.yaml not found: {}".format(PROMPTS_PATH))
	if args.poll_interval <= 0:
		raise ValueError("--poll-interval must be > 0")
	for model in args.models:
		if not LLMUtils.isOpenAiModel(model):
			raise ValueError("OpenAI Batch mode only supports OpenAI models. Got: {}".format(model))

	techniqueDirs = sorted([path for path in inputRoot.iterdir() if path.is_dir()])
	if len(techniqueDirs) == 0:
		raise ValueError("No obfuscation technique folders found inside {}".format(inputRoot))

	return {
		"inputRoot": inputRoot,
		"outputFolder": outputFolder,
		"techniqueDirs": techniqueDirs
	}


def ensureTmpFolder():
	TMP_PATH.mkdir(parents=True, exist_ok=True)


def modelFileName(model):
	return model.replace(":", "_").replace("/", "_")


def derivePkgName(apkPath):
	apkStem = apkPath.stem
	if apkStem.endswith("_obfuscated"):
		apkStem = apkStem[:-len("_obfuscated")]
	if "_" in apkStem:
		prefix, suffix = apkStem.rsplit("_", 1)
		if suffix.isdigit():
			return prefix
	return apkStem


def loadApkRecords(inputPath):
	techniqueName = inputPath.name
	apkRecords = []

	print("\n--- ⭕ Loading APKs...")
	for apkPath in sorted(inputPath.iterdir()):
		if not apkPath.is_file() or apkPath.suffix.lower() != ".apk":
			continue
		apkRecords.append({
			"sha256": AppUtils.App.computeFileSha256(str(apkPath)),
			"pkgName": derivePkgName(apkPath),
			"obfuscationTechnique": techniqueName,
			"alreadyDownloadedPath": str(apkPath)
		})

	print("--- 🔹 Input APKs Path        : {}".format(inputPath))
	print("--- 🔹 Obfuscation Technique  : {}".format(techniqueName))
	print("--- #️⃣  Number of Apps        : {}".format(len(apkRecords)))
	return apkRecords


def initOpenAiClient():
	print("\n--- ⭕ OpenAI Batch Init ...")
	client = openai.OpenAI()
	print("--- 🔸 Client ready. Requests will be submitted through the Batch API.")
	return client


def applyFiltering(app):
	print("\n--- ⭕ Filtering Smali Classes...")
	print("--- 🔹 Filtering Strategy: {}".format(FILTERING))
	if FILTERING is None:
		print("--- 🔹 No filtering applied.")
		return
	if FILTERING == "system":
		app.filterOutSystemLibraries()
		app.filterOutClassesContainingDollarSign()
	elif FILTERING == "tp":
		app.filterOutThirdPartyLibraries()
		app.filterOutClassesContainingDollarSign()
	elif FILTERING == "both":
		app.filterOutSystemLibraries()
		app.filterOutThirdPartyLibraries()
		app.filterOutClassesContainingDollarSign()
	elif FILTERING == "pkgNameOnly":
		app.filterByPkgName()
		app.filterOutClassesContainingDollarSign()
	else:
		raise ValueError("Unsupported FILTERING mode: {}".format(FILTERING))


def computeSampleSize(app):
	print("\n--- ⭕ Computing Random Sample size [confidence={}%, error margin={}%] ...".format(CONFIDENCE_LEVEL, ERROR_MARGIN))
	numSmaliClassesAnalyzed = AnalysisUtils.computeRandomSampleSize(app.numSmaliClasses, CONFIDENCE_LEVEL, ERROR_MARGIN)
	print("--- #️⃣  Random Sample Size: {}".format(numSmaliClassesAnalyzed))
	return numSmaliClassesAnalyzed


def resultNoSmali(appRecord, numSmaliClasses):
	return AnalysisUtils.createResultsObject(
		sha256=appRecord["sha256"],
		pkgName=appRecord["pkgName"],
		obfuscationTechnique=appRecord["obfuscationTechnique"],
		status="NO_SMALI_CLASSES",
		numSmaliClasses=numSmaliClasses,
		numSmaliClassesAnalyzed=0,
		pctSmaliClassesObfuscated=0.0,
		llmFinalLabel=None
	)


def resultNoContext(appRecord, numSmaliClasses):
	return AnalysisUtils.createResultsObject(
		sha256=appRecord["sha256"],
		pkgName=appRecord["pkgName"],
		obfuscationTechnique=appRecord["obfuscationTechnique"],
		status="NO_SMALI_CLASSES_WITHIN_CONTEXT_THRESHOLD",
		numSmaliClasses=numSmaliClasses,
		numSmaliClassesAnalyzed=0,
		pctSmaliClassesObfuscated=0.0,
		llmFinalLabel=None
	)


def resultError(appRecord, status, numSmaliClasses=0):
	return AnalysisUtils.createResultsObject(
		sha256=appRecord["sha256"],
		pkgName=appRecord["pkgName"],
		obfuscationTechnique=appRecord["obfuscationTechnique"],
		status=status,
		numSmaliClasses=numSmaliClasses,
		numSmaliClassesAnalyzed=0,
		pctSmaliClassesObfuscated=0.0,
		llmFinalLabel=None
	)


def getRunKey(promptID, model, techniqueName):
	return "{}||{}||{}".format(promptID, model, techniqueName)


def getRunOutputPaths(outputRoot, promptID, model, techniqueName):
	outputFolder = outputRoot / promptID / techniqueName
	outputFolder.mkdir(parents=True, exist_ok=True)
	fileModel = modelFileName(model)
	return {
		"folder": outputFolder,
		"json": outputFolder / "results_{}.json".format(fileModel),
		"csv": outputFolder / "results_{}.csv".format(fileModel)
	}


def saveRunResults(runState):
	AnalysisUtils.saveResults(runState["results"], str(runState["outputJson"]))
	AnalysisUtils.saveResultsAsCsv(runState["results"], str(runState["outputCsv"]))


def prepareSampledClasses(appRecord):
	app = None
	promptTokenizer = LLMUtils.OpenAiTokenizer()
	sha256 = appRecord["sha256"]

	try:
		print("\n--- 🔑 Preparing App SHA256  : {}".format(sha256))
		print("--- 📦 App pkgName           : {}".format(appRecord["pkgName"]))
		print("--- 🧪 obfuscationTechnique  : {}".format(appRecord["obfuscationTechnique"]))

		app = AppUtils.App(sha256, appRecord["pkgName"], str(TMP_PATH) + "/", downloadedApkPath=appRecord["alreadyDownloadedPath"])
		app.decompileWithApktool()
		manifestPkgName = app.getPkgNameFromManifest()
		if manifestPkgName is not None and manifestPkgName != app.pkgName:
			print("--- 🔄 pkgName refreshed from manifest: {} -> {}".format(app.pkgName, manifestPkgName))
			app.pkgName = manifestPkgName
			appRecord["pkgName"] = manifestPkgName

		app.collectSmaliClasses()
		applyFiltering(app)

		if app.numSmaliClasses == 0:
			return {
				"status": "NO_SMALI_CLASSES",
				"appRecord": dict(appRecord),
				"numSmaliClasses": app.numSmaliClasses,
				"sampledClasses": [],
				"promptTokenizer": promptTokenizer
			}

		numSmaliClassesAnalyzed = computeSampleSize(app)
		sampledClasses = AnalysisUtils.getRandomSample(app.smaliClasses, numSmaliClassesAnalyzed, RANDOM_SEED)
		return {
			"status": "READY",
			"appRecord": dict(appRecord),
			"numSmaliClasses": app.numSmaliClasses,
			"requestedClassCount": numSmaliClassesAnalyzed,
			"sampledClasses": sampledClasses,
			"promptTokenizer": promptTokenizer
		}
	except Exception:
		errorTrace = traceback.format_exc().replace("\n", " | ")
		return {
			"status": "ERROR",
			"result": resultError(appRecord, "ERROR - {}".format(errorTrace), 0 if app is None else app.numSmaliClasses)
		}
	finally:
		if app is not None:
			app.deleteAPK()
			app.deleteAll()


def queueRequestsForRunApp(runState, sampledApp):
	appRecord = dict(sampledApp["appRecord"])
	appStateKey = "{}||{}".format(runState["runKey"], appRecord["sha256"])
	promptTemplate = runState["promptTemplate"]

	if sampledApp["status"] == "NO_SMALI_CLASSES":
		runState["results"].append(resultNoSmali(appRecord, sampledApp["numSmaliClasses"]))
		saveRunResults(runState)
		return []
	if sampledApp["status"] == "ERROR":
		runState["results"].append(sampledApp["result"])
		saveRunResults(runState)
		return []

	appState = {
		"runKey": runState["runKey"],
		"appRecord": appRecord,
		"numSmaliClasses": sampledApp["numSmaliClasses"],
		"effectiveNumSmaliClassesAnalyzed": sampledApp["requestedClassCount"],
		"numSkippedForContextThreshold": 0,
		"classes": {},
		"failedRequestKeys": []
	}
	requests = []

	for smaliIdx, smaliClass in enumerate(sampledApp["sampledClasses"]):
		prompt = ObfuscationDetectionAnalysisUtils.buildObfuscationPrompt(promptTemplate, smaliClass)
		promptNumTokens = sampledApp["promptTokenizer"].getNumTokens(prompt)
		if promptNumTokens > CONTEXT_THRESHOLD:
			appState["effectiveNumSmaliClassesAnalyzed"] -= 1
			appState["numSkippedForContextThreshold"] += 1
			print("--- ⏭️ Skipping {} | Prompt too large ({} tokens > {}).".format(smaliClass["className"], promptNumTokens, CONTEXT_THRESHOLD))
			continue

		classKey = "{}||class{}".format(appStateKey, smaliIdx)
		appState["classes"][classKey] = {
			"className": smaliClass["className"],
			"labels": []
		}
		for iterationIdx in range(NUM_ITERATIONS):
			requests.append({
				"requestKey": None,
				"runKey": runState["runKey"],
				"appStateKey": appStateKey,
				"classKey": classKey,
				"iterationIdx": iterationIdx,
				"body": {
					"model": runState["model"],
					"messages": [{"role": "user", "content": prompt}]
				}
			})

	if appState["effectiveNumSmaliClassesAnalyzed"] == 0:
		runState["results"].append(resultNoContext(appRecord, sampledApp["numSmaliClasses"]))
		saveRunResults(runState)
		return []

	runState["appStates"][appStateKey] = appState
	return requests


def assignRequestKeys(requests):
	for idx, request in enumerate(requests):
		request["requestKey"] = "req_{:09d}".format(idx)


def buildBatchInputLine(request, attemptIdx):
	line = {
		"custom_id": "{}::try{}".format(request["requestKey"], attemptIdx),
		"method": "POST",
		"url": BATCH_ENDPOINT,
		"body": request["body"]
	}
	return json.dumps(line) + "\n"


def getBatchInputLineSizeBytes(request, attemptIdx):
	return len(buildBatchInputLine(request, attemptIdx).encode("utf-8"))


def writeBatchInputFile(batchWorkFolder, batchName, requests, attemptIdx):
	batchInputPath = batchWorkFolder / "{}_attempt{}.jsonl".format(batchName, attemptIdx)
	with open(batchInputPath, "w", encoding="utf-8") as batchInputFile:
		for request in requests:
			batchInputFile.write(buildBatchInputLine(request, attemptIdx))
	return batchInputPath


def downloadOpenAiFile(client, fileID, outputPath):
	content = client.files.content(fileID)
	if hasattr(content, "write_to_file"):
		content.write_to_file(str(outputPath))
		return
	data = content.read() if hasattr(content, "read") else content.content
	with open(outputPath, "wb") as outputFile:
		outputFile.write(data)


def submitAndWaitForBatch(client, batchInputPath, batchName, attemptIdx, pollInterval):
	print("\n--- ⭕ Uploading Batch Input: {}".format(batchInputPath))
	with open(batchInputPath, "rb") as inputFile:
		batchInputFile = client.files.create(file=inputFile, purpose="batch")

	print("--- ⭕ Creating OpenAI Batch...")
	batch = client.batches.create(
		input_file_id=batchInputFile.id,
		endpoint=BATCH_ENDPOINT,
		completion_window=BATCH_COMPLETION_WINDOW,
		metadata={"name": batchName, "attempt": str(attemptIdx)}
	)
	print("--- 🆔 Batch ID: {}".format(batch.id))

	terminalStatuses = {"completed", "failed", "expired", "cancelled"}
	while batch.status not in terminalStatuses:
		print("--- ⏳ Batch status: {} | sleeping {}s".format(batch.status, pollInterval))
		time.sleep(pollInterval)
		batch = client.batches.retrieve(batch.id)

	print("--- 🏁 Batch terminal status: {}".format(batch.status))
	if batch.status not in {"completed", "expired"}:
		raise RuntimeError("Batch {} ended with status {}".format(batch.id, batch.status))
	return batch


def requestKeyFromCustomID(customID):
	return customID.rsplit("::try", 1)[0]


def readBatchResults(outputPath):
	results = {}
	if outputPath is None or not outputPath.exists():
		return results
	with open(outputPath, "r", encoding="utf-8") as outputFile:
		for line in outputFile:
			if line.strip() == "":
				continue
			parsedLine = json.loads(line)
			results[requestKeyFromCustomID(parsedLine["custom_id"])] = parsedLine
	return results


def extractReplyFromBatchLine(line):
	response = line.get("response")
	if response is None:
		raise ValueError("Missing response object: {}".format(line))
	if response.get("status_code") != 200:
		raise ValueError("Non-200 response: {}".format(response))
	body = response.get("body", {})
	choices = body.get("choices", [])
	if len(choices) == 0:
		raise ValueError("Missing choices in response body: {}".format(body))
	return choices[0].get("message", {}).get("content", "")


def formatBytes(numBytes):
	return "{:.1f} MiB".format(numBytes / (1024 * 1024))


def chunkRequests(requests, maxRequests, maxFileBytes, attemptIdx):
	currentChunk = []
	currentSizeBytes = 0

	for request in requests:
		lineSizeBytes = getBatchInputLineSizeBytes(request, attemptIdx)
		if lineSizeBytes > maxFileBytes:
			raise ValueError(
				"Single Batch request {} is {} and exceeds max input chunk size {}.".format(
					request["requestKey"],
					formatBytes(lineSizeBytes),
					formatBytes(maxFileBytes)
				)
			)

		wouldExceedRequestLimit = len(currentChunk) >= maxRequests
		wouldExceedFileLimit = len(currentChunk) > 0 and currentSizeBytes + lineSizeBytes > maxFileBytes
		if wouldExceedRequestLimit or wouldExceedFileLimit:
			yield currentChunk, currentSizeBytes
			currentChunk = []
			currentSizeBytes = 0

		currentChunk.append(request)
		currentSizeBytes += lineSizeBytes

	if len(currentChunk) > 0:
		yield currentChunk, currentSizeBytes


def runBatchAttempts(client, batchWorkFolder, batchName, requests, requestByKey, runStates, pollInterval):
	pendingRequests = list(requests)
	successfulLabels = {}
	failedReasons = {}
	exhaustedFailures = {}

	for attemptIdx in range(1, MAX_RETRIES + 1):
		if len(pendingRequests) == 0:
			break

		print("\n--- 🔁 Shared Batch Attempt {}/{} | Requests: {}".format(attemptIdx, MAX_RETRIES, len(pendingRequests)))
		nextPendingRequests = []

		for chunkIdx, (requestChunk, chunkSizeBytes) in enumerate(chunkRequests(pendingRequests, BATCH_MAX_REQUESTS, BATCH_MAX_FILE_BYTES, attemptIdx), start=1):
			chunkBatchName = "{}_part{}".format(batchName, chunkIdx)
			print("--- 📦 Attempt {} Chunk {} | Requests: {} | Size: {}".format(attemptIdx, chunkIdx, len(requestChunk), formatBytes(chunkSizeBytes)))
			batchInputPath = writeBatchInputFile(batchWorkFolder, chunkBatchName, requestChunk, attemptIdx)
			batch = submitAndWaitForBatch(client, batchInputPath, chunkBatchName, attemptIdx, pollInterval)

			outputPath = None
			if getattr(batch, "output_file_id", None) is not None:
				outputPath = batchWorkFolder / "{}_attempt{}_output.jsonl".format(chunkBatchName, attemptIdx)
				downloadOpenAiFile(client, batch.output_file_id, outputPath)
				print("--- 💾 Batch output saved : {}".format(outputPath))

			errorPath = None
			if getattr(batch, "error_file_id", None) is not None:
				errorPath = batchWorkFolder / "{}_attempt{}_errors.jsonl".format(chunkBatchName, attemptIdx)
				downloadOpenAiFile(client, batch.error_file_id, errorPath)
				print("--- 💾 Batch errors saved : {}".format(errorPath))

			outputLinesByKey = readBatchResults(outputPath)
			for request in requestChunk:
				requestKey = request["requestKey"]
				line = outputLinesByKey.get(requestKey)
				if line is None:
					failedReasons[requestKey] = "Missing output line"
					if attemptIdx < MAX_RETRIES:
						nextPendingRequests.append(request)
					else:
						exhaustedFailures[requestKey] = failedReasons[requestKey]
					continue

				try:
					rawReply = extractReplyFromBatchLine(line)
					label = ObfuscationDetectionAnalysisUtils.parseLlmBoolean(rawReply)
					successfulLabels[requestKey] = {
						"label": label,
						"rawReply": rawReply,
						"numTries": attemptIdx
					}
				except Exception as exc:
					failedReasons[requestKey] = str(exc)
					if attemptIdx < MAX_RETRIES:
						nextPendingRequests.append(request)
					else:
						exhaustedFailures[requestKey] = failedReasons[requestKey]

		print("--- ✅ Valid Replies: {} / {}".format(len(successfulLabels), len(requests)))
		print("--- 🔁 Pending Retries: {}".format(len(nextPendingRequests)))
		pendingRequests = nextPendingRequests

	for requestKey, labelInfo in successfulLabels.items():
		request = requestByKey[requestKey]
		appState = runStates[request["runKey"]]["appStates"][request["appStateKey"]]
		appState["classes"][request["classKey"]]["labels"].append(labelInfo)

	for requestKey, reason in exhaustedFailures.items():
		request = requestByKey[requestKey]
		appState = runStates[request["runKey"]]["appStates"][request["appStateKey"]]
		appState["failedRequestKeys"].append("{} ({})".format(requestKey, reason))


def aggregateAppResult(appState):
	appRecord = appState["appRecord"]
	if len(appState["failedRequestKeys"]) > 0:
		return resultError(
			appRecord,
			"ERROR - OpenAI Batch request(s) failed after {} retries: {}".format(MAX_RETRIES, " ; ".join(appState["failedRequestKeys"][:10])),
			appState["numSmaliClasses"]
		)

	numSmaliClassesObfuscated = 0
	for classInfo in appState["classes"].values():
		trueCount = sum(1 for labelInfo in classInfo["labels"] if labelInfo["label"] is True)
		falseCount = sum(1 for labelInfo in classInfo["labels"] if labelInfo["label"] is False)
		if trueCount + falseCount != NUM_ITERATIONS:
			return resultError(appRecord, "ERROR - Incomplete Batch replies for class {}".format(classInfo["className"]), appState["numSmaliClasses"])
		majorityLabel = trueCount > falseCount
		if trueCount == falseCount:
			majorityLabel = classInfo["labels"][-1]["label"]
		if majorityLabel:
			numSmaliClassesObfuscated += 1

	effectiveNumSmaliClassesAnalyzed = appState["effectiveNumSmaliClassesAnalyzed"]
	pctSmaliClassesObfuscated = numSmaliClassesObfuscated / effectiveNumSmaliClassesAnalyzed
	llmFinalLabel = pctSmaliClassesObfuscated >= OBFUSCATION_THRESHOLD

	return AnalysisUtils.createResultsObject(
		sha256=appRecord["sha256"],
		pkgName=appRecord["pkgName"],
		obfuscationTechnique=appRecord["obfuscationTechnique"],
		status="SUCCESS",
		numSmaliClasses=appState["numSmaliClasses"],
		numSmaliClassesAnalyzed=effectiveNumSmaliClassesAnalyzed,
		pctSmaliClassesObfuscated=pctSmaliClassesObfuscated,
		llmFinalLabel=llmFinalLabel
	)


def printResultsSummary(results):
	stats = ObfuscationDetectionAnalysisUtils.computeResultsStatistics(results)
	print("\n--- 📊 Dataset Statistics")
	print("--- 🔹 Total Apps              : {}".format(stats["totalApps"]))
	print("--- 🔹 Success                 : {} [{:.2%}]".format(stats["numSuccess"], stats["pctSuccess"]))
	print("--- 🔹 Error                   : {} [{:.2%}]".format(stats["numError"], stats["pctError"]))
	print("--- 🔹 Zero Smali Classes      : {} [{:.2%}]".format(stats["numZeroSmaliClasses"], stats["pctZeroSmaliClasses"]))
	print("--- 🔹 Obfuscated Apps [True]  : {} [{:.2%}] (out of SUCCESS)".format(stats["numObfuscatedAppsTrue"], stats["pctObfuscatedAppsTrue"]))
	print("--- 🔹 Obfuscated Apps [False] : {} [{:.2%}] (out of SUCCESS)".format(stats["numObfuscatedAppsFalse"], stats["pctObfuscatedAppsFalse"]))


def buildRunStates(args, paths, prompts):
	runStates = {}
	totalRuns = len(paths["techniqueDirs"]) * len(args.prompt_ids) * len(args.models)
	runIdx = 0

	for techniqueDir in paths["techniqueDirs"]:
		apkRecords = loadApkRecords(techniqueDir)
		if len(apkRecords) == 0:
			print("--- ⚠️ No APK files found in {}".format(techniqueDir))
			continue

		for promptID in args.prompt_ids:
			promptInfo = AnalysisUtils.getPromptById(prompts, promptID)
			for model in args.models:
				runIdx += 1
				runKey = getRunKey(promptID, model, techniqueDir.name)
				outputPaths = getRunOutputPaths(paths["outputFolder"], promptID, model, techniqueDir.name)
				results = AnalysisUtils.loadExistingResults(str(outputPaths["json"]))
				completedSha256Set = {result["sha256"] for result in results}
				pendingApkRecords = [record for record in apkRecords if record["sha256"] not in completedSha256Set]

				print("\n--- ▶️ Run {}/{}".format(runIdx, totalRuns))
				print("--- 📝 Prompt    : {}".format(promptID))
				print("--- 🤖 Model     : {}".format(model))
				print("--- 📁 Technique : {}".format(techniqueDir.name))
				print("--- 🔄 Existing Results: {}/{}".format(len(results), len(apkRecords)))

				runStates[runKey] = {
					"runKey": runKey,
					"promptID": promptID,
					"promptTemplate": promptInfo["promptTemplate"],
					"model": model,
					"techniqueName": techniqueDir.name,
					"results": results,
					"pendingApkRecords": pendingApkRecords,
					"outputJson": outputPaths["json"],
					"outputCsv": outputPaths["csv"],
					"appStates": {}
				}

	return runStates


def main():
	print("⚡ START OPENAI SHARED BATCH: {} ⚡".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
	initTime = datetime.datetime.now()

	parser = buildArgumentParser()
	args = parser.parse_args()
	paths = validateArgs(args)
	load_dotenv()
	ensureTmpFolder()
	client = initOpenAiClient()

	print("\n--- ⭕ Loading Prompts...")
	prompts = AnalysisUtils.loadPrompts(str(PROMPTS_PATH))
	for promptID in args.prompt_ids:
		promptInfo = AnalysisUtils.getPromptById(prompts, promptID)
		print("--- 📝 {}: {}".format(promptInfo["promptID"], promptInfo["promptDescription"]))

	runStates = buildRunStates(args, paths, prompts)
	allRequests = []

	print("\n\n" + "==" * 10 + " ⭐ PREPARE SHARED BATCH REQUESTS ⭐ " + "==" * 10 + "\n")
	sampledCache = {}
	for runState in runStates.values():
		for appRecord in runState["pendingApkRecords"]:
			cacheKey = "{}||{}".format(runState["techniqueName"], appRecord["sha256"])
			if cacheKey not in sampledCache:
				sampledCache[cacheKey] = prepareSampledClasses(dict(appRecord))
			allRequests.extend(queueRequestsForRunApp(runState, sampledCache[cacheKey]))

	assignRequestKeys(allRequests)
	print("\n--- 🧾 Total Shared Batch Requests: {}".format(len(allRequests)))

	if len(allRequests) > 0:
		batchWorkFolder = paths["outputFolder"] / "OpenAiBatchWork"
		batchWorkFolder.mkdir(parents=True, exist_ok=True)
		batchName = "ObfuscationDetectionBatch_{}".format(datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
		requestByKey = {request["requestKey"]: request for request in allRequests}

		print("\n\n" + "==" * 10 + " ⭐ START OPENAI SHARED BATCH ⭐ " + "==" * 10 + "\n")
		runBatchAttempts(client, batchWorkFolder, batchName, allRequests, requestByKey, runStates, args.poll_interval)
	else:
		print("--- ✅ No pending requests to submit.")

	for runState in runStates.values():
		for appState in runState["appStates"].values():
			runState["results"].append(aggregateAppResult(appState))
		saveRunResults(runState)
		print("\n--- 💾 Reports saved: prompt={} | model={} | technique={}".format(runState["promptID"], runState["model"], runState["techniqueName"]))
		print("--- 💾 JSON Report saved : {}".format(runState["outputJson"]))
		print("--- 💾 CSV Report saved  : {}".format(runState["outputCsv"]))
		printResultsSummary(runState["results"])

	endTime = datetime.datetime.now()
	totalTime = endTime - initTime
	hours = totalTime.total_seconds() // 3600
	minutes = (totalTime.total_seconds() % 3600) // 60
	print("\n--- 🔚 END: {} 🔚".format(endTime.strftime("%Y-%m-%d %H:%M:%S")))
	print("--- ⏱️  Time: {:02d} hours and {:02d} minutes [{:02d} seconds] ⏱️".format(int(hours), int(minutes), int(totalTime.total_seconds())))


if __name__ == "__main__":
	try:
		main()
	except Exception as exc:
		print("\n--- ❌ Fatal error: {}".format(exc), file=sys.stderr)
		sys.exit(1)
