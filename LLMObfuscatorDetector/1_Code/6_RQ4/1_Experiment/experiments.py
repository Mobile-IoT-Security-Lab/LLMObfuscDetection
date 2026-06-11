#!/usr/bin/env python3
from pathlib import Path
import argparse
import datetime
import json
import os
import pandas as pd
import shutil
import sys
import traceback


SCRIPT_DIR   = Path(__file__).resolve().parent
RQ4_DIR      = SCRIPT_DIR.parent
CODE_DIR     = RQ4_DIR.parent
PROJECT_ROOT = CODE_DIR.parent
TMP_PATH     = PROJECT_ROOT / "0_Data" / "TMP" / "RQ4"
PROMPTS_PATH = CODE_DIR / "prompt.yaml"

DEFAULT_INPUT_CSV     = RQ4_DIR / "Data" / "sampledApps.csv"
DEFAULT_OUTPUT_FOLDER = RQ4_DIR / "Results"
DEFAULT_PROMPT_ID     = "ObfuscationDetectionV2"
DEFAULT_MODEL         = "gpt-oss:20b"

CONTEXT_WINDOW_SIZE  = 128000
CONTEXT_THRESHOLD    = 0.8 * CONTEXT_WINDOW_SIZE
CONFIDENCE_LEVEL     = 95
ERROR_MARGIN         = 5
OBFUSCATION_THRESHOLD = 0.3
FILTERING            = "both"
RANDOM_SEED          = 777
NUM_ITERATIONS       = 3
MAX_RETRIES          = 3

RESULT_FIELD_NAMES = [
	"sha256",
	"pkgName",
	"addedDate",
	"vtScore",
	"status",
	"numSmaliClasses",
	"numSmaliClassesAnalyzed",
	"pctSmaliClassesObfuscated",
	"llmFinalLabel"
]

class FriendlyArgumentParser(argparse.ArgumentParser):
	def error(self, message):
		self.print_usage(sys.stderr)
		self.exit(2, "\n--- ❌ Argument error: {}\n--- 💡 Use --help for the full CLI reference.\n".format(message))


def buildArgumentParser():
	parser = FriendlyArgumentParser(
		description = "Download AndroZoo APKs one at a time, detect obfuscation, and delete temporary APK files.",
		formatter_class = argparse.RawTextHelpFormatter,
		epilog = (
			"Example:\n"
			"  python experiments.py \\\n"
			"    --input-csv ../Data/sampledApps.csv \\\n"
			"    --model gpt-oss:20b \\\n"
			"    --prompt-id ObfuscationDetectionV2 \\\n"
			"    --output-folder ../Results\n"
		)
	)
	parser.add_argument("--input-csv", default = str(DEFAULT_INPUT_CSV), help = "CSV with sha256,pkgName,addedDate,vtScore columns.")
	parser.add_argument("--output-folder", default = str(DEFAULT_OUTPUT_FOLDER), help = "Folder for resumable JSON and CSV reports.")
	parser.add_argument("--model", default = DEFAULT_MODEL, help = "LLM model. Default: {}".format(DEFAULT_MODEL))
	parser.add_argument("--prompt-id", default = DEFAULT_PROMPT_ID, help = "Prompt ID from prompt.yaml. Default: {}".format(DEFAULT_PROMPT_ID))
	return parser


def validateArgs(args):
	inputCsv     = Path(args.input_csv).expanduser().resolve()
	outputFolder = Path(args.output_folder).expanduser().resolve()

	if not inputCsv.exists():
		raise ValueError("INPUT_CSV does not exist: {}".format(inputCsv))
	if not inputCsv.is_file():
		raise ValueError("INPUT_CSV must be a file: {}".format(inputCsv))
	if not PROMPTS_PATH.exists():
		raise ValueError("prompt.yaml not found: {}".format(PROMPTS_PATH))
	return {
		"inputCsv"     : inputCsv,
		"outputFolder" : outputFolder
	}


def loadAppRecords(inputCsv):
	appsDf = pd.read_csv(inputCsv)
	requiredColumns = ["sha256", "pkgName", "addedDate", "vtScore"]
	missingColumns = [columnName for columnName in requiredColumns if columnName not in appsDf.columns]
	if len(missingColumns) > 0:
		raise ValueError("Missing required CSV columns: {}".format(", ".join(missingColumns)))

	# TEST PURPOSES
	appsDf = appsDf.head(3)

	return appsDf[requiredColumns].fillna("").to_dict("records")


def modelFileName(model):
	return model.replace(":", "_").replace("/", "_")


def validateAndroZooApiKey():
	apiKey = os.getenv("ANDROZOO_API_KEY")
	if apiKey is None or apiKey.strip() == "":
		raise ValueError("ANDROZOO_API_KEY is not set. Add it to .env before downloading APKs.")


def getOutputPaths(outputFolder, promptId, model):
	runOutputFolder = outputFolder / promptId
	runOutputFolder.mkdir(parents = True, exist_ok = True)
	fileModelName = modelFileName(model)
	return {
		"json" : runOutputFolder / "results_{}.json".format(fileModelName),
		"csv"  : runOutputFolder / "results_{}.csv".format(fileModelName)
	}


def loadExistingResults(outputJsonPath):
	if not outputJsonPath.exists():
		return []
	with open(str(outputJsonPath), "r", encoding = "utf-8") as inputFile:
		return json.load(inputFile)


def saveResults(results, outputPaths):
	with open(str(outputPaths["json"]), "w", encoding = "utf-8") as outputFile:
		json.dump(results, outputFile, indent = 4)

	with open(str(outputPaths["csv"]), "w", encoding = "utf-8", newline = "") as outputFile:
		import csv
		writer = csv.DictWriter(outputFile, fieldnames = RESULT_FIELD_NAMES, extrasaction = "ignore")
		writer.writeheader()
		writer.writerows(results)


def downloadApk(sha256, apkPath):
	import requests

	apiKey = os.getenv("ANDROZOO_API_KEY")

	print("\n--- ⭕ Downloading APK from AndroZoo...")
	print("--- 🔑 SHA256: {}".format(sha256))
	response = requests.get(
		"https://androzoo.uni.lu/api/download",
		params  = {"apikey": apiKey, "sha256": sha256},
		headers = {"User-Agent": "RQ4-AndroZoo-ObfuscationDetection/1.0"},
		stream  = True,
		timeout = 120
	)
	response.raise_for_status()

	with open(str(apkPath), "wb") as outputFile:
		for chunk in response.iter_content(chunk_size = 1024 * 1024):
			if chunk:
				outputFile.write(chunk)

	if not apkPath.exists() or apkPath.stat().st_size == 0:
		raise ValueError("AndroZoo download did not create a valid APK: {}".format(apkPath))
	print("--- 💾 Downloaded APK: {}".format(apkPath))


def cleanupAppFiles(apkPath):
	decompiledPath = apkPath.with_suffix("")
	if apkPath.exists():
		apkPath.unlink()
		print("--- 🗑️ Deleted APK: {}".format(apkPath))
	if decompiledPath.exists():
		shutil.rmtree(str(decompiledPath))
		print("--- 🗑️ Deleted decompiled folder: {}".format(decompiledPath))


def initLlm(model, LLMUtils):
	print("\n--- ⭕ LLM Init & Check...")
	print("--- 🤖 Model: {}".format(model))
	if LLMUtils.isOpenAiModel(model):
		llmInterface = LLMUtils.OpenAiInterface(model = model, contextWindow = CONTEXT_WINDOW_SIZE)
	elif model.lower().startswith("gemini"):
		llmInterface = LLMUtils.GeminiInterface(model = model, contextWindow = CONTEXT_WINDOW_SIZE)
	else:
		llmInterface = LLMUtils.OllamaInterface(model = model, contextWindow = CONTEXT_WINDOW_SIZE)
	print("--- 🔸 LLM Response: {}".format(llmInterface.sendRequest("Ping!")))
	return llmInterface


def applyFiltering(app):
	print("\n--- ⭕ Filtering Smali Classes...")
	print("--- 🔹 Filtering Strategy: {}".format(FILTERING))
	if FILTERING == "both":
		app.filterOutSystemLibraries()
		app.filterOutThirdPartyLibraries()
		app.filterOutClassesContainingDollarSign()
	else:
		raise ValueError("Unsupported FILTERING mode: {}".format(FILTERING))


def createResult(appRecord, status, numSmaliClasses = 0, numSmaliClassesAnalyzed = 0, pctSmaliClassesObfuscated = 0.0, llmFinalLabel = None):
	return {
		"sha256"                    : appRecord["sha256"],
		"pkgName"                   : appRecord["pkgName"],
		"addedDate"                 : appRecord["addedDate"],
		"vtScore"                   : appRecord["vtScore"],
		"status"                    : status,
		"numSmaliClasses"           : numSmaliClasses,
		"numSmaliClassesAnalyzed"   : numSmaliClassesAnalyzed,
		"pctSmaliClassesObfuscated" : round(pctSmaliClassesObfuscated, 2),
		"llmFinalLabel"             : llmFinalLabel
	}


def analyzeAppRecord(appRecord, llmInterface, promptTemplate, AppUtils, LLMUtils, AnalysisUtils, ObfuscationDetectionAnalysisUtils):
	sha256 = appRecord["sha256"]
	apkPath = TMP_PATH / "{}.apk".format(sha256)
	app = None

	print("\n--- 🔑 Analyzing SHA256 : {}".format(sha256))
	print("--- 📦 pkgName          : {}".format(appRecord["pkgName"]))
	print("--- 📅 addedDate        : {}".format(appRecord["addedDate"]))
	print("--- 🛡️ VT score         : {}".format(appRecord["vtScore"]))

	try:
		downloadApk(sha256, apkPath)
		app = AppUtils.App(sha256, appRecord["pkgName"], str(TMP_PATH) + "/")
		app.decompileWithApktool()
		if not Path(app.getDecompiledPath()).exists():
			raise ValueError("Apktool did not create the expected decompiled folder.")

		manifestPkgName = app.getPkgNameFromManifest()
		if manifestPkgName is not None and manifestPkgName != app.pkgName:
			print("--- 🔄 pkgName refreshed from manifest: {} -> {}".format(app.pkgName, manifestPkgName))
			app.pkgName = manifestPkgName
			appRecord["pkgName"] = manifestPkgName

		app.collectSmaliClasses()
		applyFiltering(app)
		if app.numSmaliClasses == 0:
			return createResult(appRecord, "NO_SMALI_CLASSES")

		numSmaliClassesAnalyzed = AnalysisUtils.computeRandomSampleSize(app.numSmaliClasses, CONFIDENCE_LEVEL, ERROR_MARGIN)
		print("--- #️⃣ Smali Classes Sampled: {}".format(numSmaliClassesAnalyzed))

		# TEST PURPOSES
		numSmaliClassesAnalyzed = 3

		sampledSmaliClasses = AnalysisUtils.getRandomSample(app.smaliClasses, numSmaliClassesAnalyzed, RANDOM_SEED)
		promptTokenizer = LLMUtils.OpenAiTokenizer()
		effectiveNumSmaliClassesAnalyzed = numSmaliClassesAnalyzed
		numSmaliClassesObfuscated = 0

		for smaliIdx, smaliClass in enumerate(sampledSmaliClasses, start = 1):
			print("--- 🔸 Checking Smali Class [{}/{}]: {}".format(smaliIdx, numSmaliClassesAnalyzed, smaliClass["className"]))
			prompt = ObfuscationDetectionAnalysisUtils.buildObfuscationPrompt(promptTemplate, smaliClass)
			promptNumTokens = promptTokenizer.getNumTokens(prompt)
			if promptNumTokens > CONTEXT_THRESHOLD:
				effectiveNumSmaliClassesAnalyzed -= 1
				print("--- ⏭️ Skipped: prompt has {} tokens > {}".format(promptNumTokens, CONTEXT_THRESHOLD))
				continue

			classAnalysis = ObfuscationDetectionAnalysisUtils.analyzeSmaliClassWithMajorityVote(
				llmInterface  = llmInterface,
				smaliClass    = smaliClass,
				promptTemplate = promptTemplate,
				numIterations = NUM_ITERATIONS,
				maxRetries    = MAX_RETRIES
			)
			if classAnalysis["majorityLabel"]:
				numSmaliClassesObfuscated += 1

		if effectiveNumSmaliClassesAnalyzed == 0:
			return createResult(appRecord, "NO_SMALI_CLASSES_WITHIN_CONTEXT_THRESHOLD", numSmaliClasses = app.numSmaliClasses)

		pctSmaliClassesObfuscated = numSmaliClassesObfuscated / effectiveNumSmaliClassesAnalyzed
		llmFinalLabel = pctSmaliClassesObfuscated >= OBFUSCATION_THRESHOLD
		print("--- 🎯 Obfuscated Smali Classes: {} / {}".format(numSmaliClassesObfuscated, effectiveNumSmaliClassesAnalyzed))
		print("--- 🎯 Final Label: {}".format(llmFinalLabel))
		return createResult(
			appRecord,
			"SUCCESS",
			numSmaliClasses = app.numSmaliClasses,
			numSmaliClassesAnalyzed = effectiveNumSmaliClassesAnalyzed,
			pctSmaliClassesObfuscated = pctSmaliClassesObfuscated,
			llmFinalLabel = llmFinalLabel
		)
	except Exception:
		errorTrace = traceback.format_exc().replace("\n", " | ")
		print("--- ⚠️ Error while analyzing {}: {}".format(sha256, errorTrace))
		return createResult(appRecord, "ERROR - {}".format(errorTrace), numSmaliClasses = 0 if app is None else app.numSmaliClasses)
	finally:
		cleanupAppFiles(apkPath)


def main():
	print("⚡ START: {} ⚡".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
	parser = buildArgumentParser()
	args = parser.parse_args()
	paths = validateArgs(args)
	appRecords = loadAppRecords(paths["inputCsv"])

	if len(appRecords) == 0:
		raise ValueError("No apps found in {}".format(paths["inputCsv"]))

	from dotenv import load_dotenv
	load_dotenv()
	validateAndroZooApiKey()
	TMP_PATH.mkdir(parents = True, exist_ok = True)
	sys.path.append(str(CODE_DIR))
	import AppUtils
	import LLMUtils
	from AnalysisUtils import AnalysisUtils, ObfuscationDetectionAnalysisUtils

	prompts = AnalysisUtils.loadPrompts(str(PROMPTS_PATH))
	promptInfo = AnalysisUtils.getPromptById(prompts, args.prompt_id)
	outputPaths = getOutputPaths(paths["outputFolder"], promptInfo["promptID"], args.model)
	results = loadExistingResults(outputPaths["json"])
	completedSha256Set = {result["sha256"] for result in results}
	pendingAppRecords = [appRecord for appRecord in appRecords if appRecord["sha256"] not in completedSha256Set]

	print("--- 🔄 Existing Results: {}/{}".format(len(results), len(appRecords)))
	print("--- ⏳ Pending Apps    : {}".format(len(pendingAppRecords)))
	if len(pendingAppRecords) == 0:
		saveResults(results, outputPaths)
		return

	llmInterface = initLlm(args.model, LLMUtils)
	for appIdx, appRecord in enumerate(pendingAppRecords, start = 1):
		print("\n--- ▶️ App [{}/{}]".format(appIdx, len(pendingAppRecords)))
		results.append(analyzeAppRecord(
			appRecord,
			llmInterface,
			promptInfo["promptTemplate"],
			AppUtils,
			LLMUtils,
			AnalysisUtils,
			ObfuscationDetectionAnalysisUtils
		))
		saveResults(results, outputPaths)
		print("--- 💾 Partial report saved: {}".format(outputPaths["json"]))

	print("\n--- ✅ Finished {} app(s).".format(len(appRecords)))
	print("--- 💾 JSON Report: {}".format(outputPaths["json"]))
	print("--- 💾 CSV Report : {}".format(outputPaths["csv"]))


if __name__ == "__main__":
	try:
		main()
	except Exception as exc:
		print("\n--- ❌ Fatal error: {}".format(exc), file = sys.stderr)
		sys.exit(1)
