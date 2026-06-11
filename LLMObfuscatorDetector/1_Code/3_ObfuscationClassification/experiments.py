#!/usr/bin/env python3
# Imports
from pathlib 		import Path
from dotenv 		import load_dotenv
import argparse
import datetime
import sys
import traceback

# Custom Imports
scriptDir   = Path(__file__).resolve().parent
codeDir     = scriptDir.parent
projectRoot = codeDir.parent
sys.path.append(str(codeDir))
import AppUtils
import LLMUtils
from AnalysisUtils import AnalysisUtils, LlmRetryLimitExceededError, ObfuscationClassificationAnalysisUtils


##### PARAMETERS #####
# Context Window Size
CONTEXT_WINDOW_SIZE = 128000
CONTEXT_THRESHOLD   = 0.8 * CONTEXT_WINDOW_SIZE

# To computer the minimum number of classes for statistically significant random sample
CONFIDENCE_LEVEL = 95
ERROR_MARGIN     = 5

# Obfuscation Techniques i.e. potential Labels
OBFUSCATION_TECHNIQUES = ["ArithmeticBranch", "CallIndirection", "ClassRename", "ConstStringEncryption", "FieldRename", "Goto", "MethodOverload", "MethodRename", "Reflection", "ResStringEncryption"]

# Filtering [None | "system" | "tp" | "both" | "pkgNameOnly"]
FILTERING = "both"

# Sampling
RANDOM_SEED    = 4316

# LLM Robustness
NUM_ITERATIONS = 1
MAX_RETRIES    = 2

# Logging
SILENT_MODE = False

# TMP folder for decompilation and intermediate files (will be automatically created if not exists)
TMP_PATH = projectRoot / "0_Data" / "TMP"

# Prompts to be used
PROMPTS_PATH = codeDir / "prompt.yaml"
DEFAULT_PROMPT_ID = "ObfuscationClassificationV1"

# Parse command-line arguments and validate them.
class FriendlyArgumentParser(argparse.ArgumentParser):
	def error(self, message):
		self.print_usage(sys.stderr)
		self.exit(2, "\n--- ❌ Argument error: {}\n--- 💡 Use --help for the full CLI reference.\n".format(message))

# Parser for command-line arguments with enhanced error messages and usage instructions.
def buildArgumentParser():
	parser = FriendlyArgumentParser(
		description     = "Run multiclass obfuscation classification on APKs stored in a local folder.",
		formatter_class = argparse.RawTextHelpFormatter,
		epilog          = (
			"Example:\n"
			"  python experiments.py \\\n"
			"    --input-path ../../0_Data/InputApks/ClassRename \\\n"
			"    --model gpt-4o-mini \\\n"
			"    --prompt-id ObfuscationClassificationV1 \\\n"
			"    --output-folder ../../0_Data/Results\n"
		)
	)
	parser.add_argument("--input-path", required=True, help="Folder containing input APK files.")
	parser.add_argument("--model", required=True, help="LLM model to use.")
	parser.add_argument("--prompt-id", default=DEFAULT_PROMPT_ID, help="Prompt ID from prompt.yaml to use. Default: {}".format(DEFAULT_PROMPT_ID))
	parser.add_argument("--output-folder", required=True, help="Base folder where PROMPT_ID/TECHNIQUE/results_<MODEL>.json/csv will be written.")
	return parser

# Valida arguments and return resolved paths.
def validateArgs(args):
	inputPath    = Path(args.input_path).expanduser().resolve()
	outputFolder = Path(args.output_folder).expanduser().resolve()

	if not inputPath.exists():
		raise ValueError("INPUT_PATH does not exist: {}".format(inputPath))
	if not inputPath.is_dir():
		raise ValueError("INPUT_PATH must be a directory: {}".format(inputPath))
	if not any(child.suffix.lower() == ".apk" for child in inputPath.iterdir() if child.is_file()):
		raise ValueError("INPUT_PATH does not contain any .apk files: {}".format(inputPath))
	if not PROMPTS_PATH.exists():
		raise ValueError("prompt.yaml not found: {}".format(PROMPTS_PATH))

	return {
		"inputPath"     : inputPath,
		"outputFolder"  : outputFolder,
	}

# Create TMP folder if not exists.
def ensureTmpFolder():
	if not TMP_PATH.exists():
		TMP_PATH.mkdir(parents=True, exist_ok=True)
		print("--- 🆕 TMP folder created: {}".format(TMP_PATH))

# Extract PkgName from APK file name.
def derivePkgName(apkPath):
	apkStem = apkPath.stem
	if apkStem.endswith("_obfuscated"):
		apkStem = apkStem[:-len("_obfuscated")]

	if "_" in apkStem:
		prefix, suffix = apkStem.rsplit("_", 1)
		if suffix.isdigit():
			return prefix

	return apkStem

# Load APK records from the input folder, extracting sha256, pkgName, and obfuscation techniques.
def loadApkRecords(inputPath):
	obfuscationTechniqueDirName = inputPath.name
	obfuscationTechnique = obfuscationTechniqueDirName
	apkRecords = []

	print("\n--- ⭕ Loading APKs...")
	for apkPath in sorted(inputPath.iterdir()):
		if not apkPath.is_file() or apkPath.suffix.lower() != ".apk":
			continue

		apkRecords.append({
			"sha256"                : AppUtils.App.computeFileSha256(str(apkPath)),
			"pkgName"               : derivePkgName(apkPath),
			"obfuscationTechnique"  : obfuscationTechnique,
			"alreadyDownloadedPath" : str(apkPath)
		})

	print("--- 🔹 Input APKs Path        : {}".format(inputPath))
	print("--- 🔹 Obfuscation Technique  : {}".format(obfuscationTechnique))
	print("--- #️⃣  Number of Apps        : {}".format(len(apkRecords)))
	return apkRecords, obfuscationTechniqueDirName

# Initialize LLM interface and perform a test request.
def initLlm(model):
	print("\n--- ⭕ LLM Init & Check ...")
	print("--- 🔸 Model: {}".format(model))

	# Routing logic: OpenAI GPT models -> OpenAI, gemini* -> Gemini, everything else -> Ollama.
	if LLMUtils.isOpenAiModel(model):
		llmInterface = LLMUtils.OpenAiInterface(model = model, contextWindow = CONTEXT_WINDOW_SIZE)
	elif model.lower().startswith("gemini"):
		llmInterface = LLMUtils.GeminiInterface(model = model, contextWindow = CONTEXT_WINDOW_SIZE)
	else:
		llmInterface = LLMUtils.OllamaInterface(model = model, contextWindow = CONTEXT_WINDOW_SIZE)

	# Send a test request to the LLM to verify that it's working correctly and can respond to queries.
	print("--- 🔸 LLM Response: {}".format(llmInterface.sendRequest("Ping!")))
	return llmInterface


# Apply the selected filtering strategy to the app's Smali classes before sampling
def applyFiltering(app):
	print("\n--- ⭕ Filtering Smali Classes...")
	print("--- 🔹 Filtering Strategy: {}".format(FILTERING))

	if FILTERING is None:
		print("--- 🔹 No filtering applied.")
		return
	
	# Apply filtering based on the selected strategy. The filtering functions will modify the app's smaliClasses list in place, removing classes that match the criteria defined in each filtering function. This step is crucial to ensure that we are analyzing only the relevant Smali classes for obfuscation detection, which can help improve the accuracy of our analysis and reduce noise from irrelevant classes such as system libraries or third-party dependencies.	
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

# Note: After filtering, the number of Smali classes may be significantly reduced, which can impact the analysis results and should be taken into account when interpreting the results.
def computeSampleSize(app):
	print("\n--- ⭕ Computing Random Sample size [confidence={}%, error margin={}%] ...".format(CONFIDENCE_LEVEL, ERROR_MARGIN))
	numSmaliClassesAnalyzed = AnalysisUtils.computeRandomSampleSize(
		app.numSmaliClasses,
		CONFIDENCE_LEVEL,
		ERROR_MARGIN
	)
	print("--- #️⃣  Random Sample Size: {}".format(numSmaliClassesAnalyzed))
	return numSmaliClassesAnalyzed

# Build the OpenAI tokenizer used to estimate prompt size before each request.
def buildPromptTokenizer():
	return LLMUtils.OpenAiTokenizer()

# Check whether the prompt for a Smali class fits within the configured context threshold.
def getPromptTokenCount(promptTemplate, smaliClass, promptTokenizer, expectedLabels):
	prompt = ObfuscationClassificationAnalysisUtils.buildClassificationPrompt(promptTemplate, smaliClass, expectedLabels)
	return promptTokenizer.getNumTokens(prompt)

# Analyze a single APK record: decompile, filter, sample Smali classes, analyze with LLM, and aggregate results.
def analyzeApkRecord(appRecord, llmInterface, promptTemplate, expectedLabels, techniqueDirName):
	
	# Get app information from the record
	sha256  				= appRecord["sha256"]
	pkgName 				= appRecord["pkgName"]
	obfuscationTechnique 	= appRecord["obfuscationTechnique"]
	alreadyDownloadedPath 	= appRecord["alreadyDownloadedPath"]

	# Initialize variables for the app analysis, including the app object and the prompt tokenizer. The app object will be used to manage the decompilation and analysis of the APK, while the prompt tokenizer will be used to estimate the size of the prompts we will send to the LLM for each Smali class, ensuring that we stay within the context limits of the LLM.
	app = None
	promptTokenizer = buildPromptTokenizer()

	print("--- 🔑 Analyzing App SHA256  : {}".format(sha256))
	print("--- 📦 App pkgName           : {}".format(pkgName))
	print("--- 🧪 obfuscationTechnique  : {}".format(obfuscationTechnique))

	# Try to analyze the app, handling any exceptions that may occur during decompilation, filtering, sampling, or LLM analysis. Ensure that all resources are cleaned up in the finally block.
	try:
		app = AppUtils.App(sha256, pkgName, str(TMP_PATH) + "/", downloadedApkPath=alreadyDownloadedPath)
		app.decompileWithApktool()
		manifestPkgName = app.getPkgNameFromManifest()
		if manifestPkgName is not None and manifestPkgName != app.pkgName:
			print("--- 🔄 pkgName refreshed from manifest: {} -> {}".format(app.pkgName, manifestPkgName))
			app.pkgName = manifestPkgName
			pkgName     = manifestPkgName

		app.collectSmaliClasses()
		applyFiltering(app)

		if app.numSmaliClasses == 0:
			print("--- ⚠️ No Smali Classes found.")
			return AnalysisUtils.createResultsObject(
				sha256						= sha256,
				pkgName						= pkgName,
				obfuscationTechnique		= obfuscationTechnique,
				status						= "NO_SMALI_CLASSES",
				numSmaliClasses			  	= app.numSmaliClasses,
				numSmaliClassesAnalyzed		= 0,
				llmFinalLabel				= None
			)


		# Compute the number of Smali classes to analyze based on the total number of classes and the desired confidence level and error margin for the random sampling. This will determine how many Smali classes we will analyze with the LLM to make a final determination about whether the app is obfuscated or not.
		numSmaliClassesAnalyzed = computeSampleSize(app)

		# TEST PURPOSES
		# numSmaliClassesAnalyzed = 3

		# Get a random sample of Smali classes to analyze with the LLM. This sampling is important to ensure that we are analyzing a representative subset of the Smali classes in the app, which can help us make a more accurate determination about whether the app is obfuscated or not, while also keeping the analysis manageable and efficient.
		sampledSmaliClasses                = AnalysisUtils.getRandomSample(app.smaliClasses, numSmaliClassesAnalyzed, RANDOM_SEED)
		effectiveNumSmaliClassesAnalyzed   = numSmaliClassesAnalyzed
		numSkippedForContextThreshold      = 0
		numSkippedForInvalidLlmOutput      = 0
		appLabelCounts                     = {}

		# Analyzing the Smali Classes with LLM
		print("\n--- ⭕ Analyzing Smali Classes with LLM...")
		print("--- 🔹 Num Iterations        : {}".format(NUM_ITERATIONS))
		print("--- 🔹 Max Retries           : {}".format(MAX_RETRIES))
		print("--- 🔹 Expected Labels       : {}\n".format(", ".join(expectedLabels)))

		# For each Smali Class...
		for smaliIdx, smaliClass in enumerate(sampledSmaliClasses):
			if not SILENT_MODE:
				print("--- 🔸 Checking Smali Class [{}/{}]: {}".format(smaliIdx + 1, numSmaliClassesAnalyzed, smaliClass["className"]))

			promptNumTokens = getPromptTokenCount(promptTemplate, smaliClass, promptTokenizer, expectedLabels)
			if promptNumTokens > CONTEXT_THRESHOLD:
				effectiveNumSmaliClassesAnalyzed -= 1
				numSkippedForContextThreshold += 1
				print("--- ⏭️ Skipping Smali Class [{}/{}]: {} | Prompt too large ({} tokens > {}).".format(
					smaliIdx + 1,
					numSmaliClassesAnalyzed,
					smaliClass["className"],
					promptNumTokens,
					CONTEXT_THRESHOLD
				))
				if not SILENT_MODE:
					print("---" * 20)
				continue

			# Send the request to LLM. If this class exhausts its output-format retries,
			# skip only this class and continue with the next sampled class.
			try:
				classAnalysis = ObfuscationClassificationAnalysisUtils.analyzeSmaliClassWithMajorityVote(
					llmInterface		= llmInterface,
					smaliClass			= smaliClass,
					promptTemplate		= promptTemplate,
					expectedLabels		= expectedLabels,
					numIterations		= NUM_ITERATIONS,
					maxRetries			= MAX_RETRIES
				)
			except LlmRetryLimitExceededError as exc:
				effectiveNumSmaliClassesAnalyzed -= 1
				numSkippedForInvalidLlmOutput += 1
				print("--- ⏭️ Skipping Smali Class [{}/{}]: {} | Invalid LLM output after {} retries: {}".format(
					smaliIdx + 1,
					numSmaliClassesAnalyzed,
					smaliClass["className"],
					MAX_RETRIES,
					exc
				))
				if not SILENT_MODE:
					print("---" * 20)
				continue

			# Get the final label
			classLabel = classAnalysis["majorityLabel"]
			appLabelCounts[classLabel] = appLabelCounts.get(classLabel, 0) + 1

			if not SILENT_MODE:
				print("--- 🏷️ Label Counts : {}".format(classAnalysis["labelCounts"]))
				print("--- 🏷️ Majority Label: {}".format(classLabel))
				print("---" * 20)

		if effectiveNumSmaliClassesAnalyzed == 0:
			print("\n--- ⚠️ No sampled Smali Classes could be analyzed.")
			print("--- 🔹 N. Skipped for Context      : {}".format(numSkippedForContextThreshold))
			print("--- 🔹 N. Skipped for LLM Output   : {}".format(numSkippedForInvalidLlmOutput))
			return AnalysisUtils.createResultsObject(
				sha256						= sha256,
				pkgName						= pkgName,
				obfuscationTechnique		= obfuscationTechnique,
				status						= "NO_ANALYZABLE_SMALI_CLASSES",
				numSmaliClasses				= app.numSmaliClasses,
				numSmaliClassesAnalyzed	  	= 0,
				llmFinalLabel=None
			)

		# Determine the final predicted label for the app based on majority voting across analyzed classes, using the label counts. In case of ties, prefer the label of the most recently analyzed class.
		llmFinalLabel = max(OBFUSCATION_TECHNIQUES, key = lambda label: (appLabelCounts.get(label, 0), label == classLabel))
		isCorrect = llmFinalLabel == obfuscationTechnique

		print("\n--- 🎯 Results for App             : {}".format(pkgName))
		print("--- 🔹 Ground Truth Label          : {}".format(obfuscationTechnique))
		print("--- 🔹 Predicted Label             : {}".format(llmFinalLabel))
		print("--- 🔹 Prediction Counts           : {}".format(dict(appLabelCounts)))
		print("--- 🔹 N. Skipped for Context      : {}".format(numSkippedForContextThreshold))
		print("--- 🔹 N. Skipped for LLM Output   : {}".format(numSkippedForInvalidLlmOutput))
		print("--- 🔹 Correct Prediction          : {}".format(isCorrect))

		appResult = AnalysisUtils.createResultsObject(
			sha256                      = sha256,
			pkgName                     = pkgName,
			obfuscationTechnique        = obfuscationTechnique,
			status                      = "SUCCESS",
			numSmaliClasses             = app.numSmaliClasses,
			numSmaliClassesAnalyzed     = effectiveNumSmaliClassesAnalyzed,
			llmFinalLabel               = llmFinalLabel,
			labelFrequency              = dict(appLabelCounts)
		)
	
	except Exception as exc:
		print("--- ⚠️ Error while analyzing {}: {}".format(pkgName, exc))
		errorTrace = traceback.format_exc().replace("\n", " | ")
		appResult = AnalysisUtils.createResultsObject(
			sha256                      = sha256,
			pkgName                     = pkgName,
			obfuscationTechnique        = obfuscationTechnique,
			status                      = "ERROR - {}".format(errorTrace),
			numSmaliClasses             = 0 if app is None else app.numSmaliClasses,
			numSmaliClassesAnalyzed     = 0,
			llmFinalLabel               =None
		)

	# Finally, save the results for this app (whether success or error) and clean up the app's decompiled files to save disk space. Also, print a separator before moving on to the next app.
	finally:
 
		if app is not None:
			app.deleteAPK()
			app.deleteAll()

		print("\n" + "+++" * 20)

	return appResult


# Main
def main():
	# Log the starting time
	print("⚡ START: {} ⚡".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
	initTime = datetime.datetime.now()

	# Parse and validate command-line arguments, load environment variables, and initialize the analysis process, including loading APK records, prompts, and initializing the LLM interface if there are pending APKs to analyze. The main function orchestrates the entire workflow of the analysis, from loading data to saving results and computing statistics.
	parser = buildArgumentParser()
	args   = parser.parse_args()
	paths  = validateArgs(args)
	load_dotenv()
	ensureTmpFolder()

	# Load the APKs
	apkRecords, techniqueDirName = loadApkRecords(paths["inputPath"])
	if len(apkRecords) == 0:
		raise ValueError("No APK files found in {}".format(paths["inputPath"]))

	# LLM Test
	llmInterface = initLlm(args.model)

	# Print expected labels
	print("\n--- ⭕ Expected Labels")
	print("--- 🔹 {}".format(", ".join(OBFUSCATION_TECHNIQUES)))

	# Load Prompts 
	print("\n--- ⭕ Loading Prompts...")
	prompts    		= AnalysisUtils.loadPrompts(str(PROMPTS_PATH))
	promptInfo 		= AnalysisUtils.getPromptById(prompts, args.prompt_id)
	promptTemplate 	= promptInfo["promptTemplate"]
	print("--- 📝 Prompt ID: {}".format(promptInfo["promptID"]))
	print("--- 📝 Prompt Description: {}".format(promptInfo["promptDescription"]))

	# Check for existing results to avoid re-analyzing apps that have already been processed, and prepare the output paths for saving results. This step is crucial for efficiently managing the analysis process, especially when dealing with a large number of apps, as it allows us to skip already analyzed apps and focus only on those that are pending analysis.
	modelFileName 	= args.model.replace(":", "_").replace("/", "_")
	outputFolder 	= paths["outputFolder"] / promptInfo["promptID"] / techniqueDirName
	outputFolder.mkdir(parents = True, exist_ok = True)
	outputPathJson 	= outputFolder / "results_{}.json".format(modelFileName)
	outputPathCsv 	= outputFolder / "results_{}.csv".format(modelFileName)

	# Try to load existing Results
	print("\n--- ⭕ Checking for existing results...")
	obfuscationClassificationResults 	    = AnalysisUtils.loadExistingResults(str(outputPathJson))
	completedSha256Set 			= {result["sha256"] for result in obfuscationClassificationResults}
	pendingApkRecords 			= [record for record in apkRecords if record["sha256"] not in completedSha256Set]

	# Check if there are existing results
	if len(obfuscationClassificationResults) > 0:
		print("--- ☑️  File Found!")
		print("--- 🔄 Current Progress: {}/{}".format(len(obfuscationClassificationResults), len(apkRecords)))
	else:
		print("--- 🆕 No existing results file found! --> Starting fresh analysis...")

	# Analyze every application
	print("\n\n"+"==" * 10 + " ⭐ START LLM ANALYSIS ⭐ " + "==" * 10 + "\n")
	for appRecord in pendingApkRecords:
		appResult = analyzeApkRecord(appRecord, llmInterface, promptTemplate, OBFUSCATION_TECHNIQUES, techniqueDirName)
		obfuscationClassificationResults.append(appResult)
		AnalysisUtils.saveResults(obfuscationClassificationResults, str(outputPathJson))
		print("\n--- 💾 Partial Report saved!")
		print("\n" + "+++" * 20)

	print("\n\n" + "==" * 10 + " ⭐ END  LLM  ANALYSIS ⭐ " + "==" * 10 + "\n")
	AnalysisUtils.saveResults(obfuscationClassificationResults, str(outputPathJson))
	AnalysisUtils.saveResultsAsCsv(obfuscationClassificationResults, str(outputPathCsv))
	print("--- 💾 JSON Report saved : {}".format(outputPathJson))
	print("--- 💾 CSV Report saved  : {}".format(outputPathCsv))

	# Print comprehensive statistics about the results, including the total number of apps analyzed, the distribution of predicted labels, and the accuracy of the predictions compared to the ground truth obfuscation techniques. This step is important for understanding the overall performance of the LLM in classifying obfuscation techniques and identifying any patterns or trends in the results that may warrant further investigation.
	resultsStats = ObfuscationClassificationAnalysisUtils.computeResultsStatistics(obfuscationClassificationResults)
	print("\n--- 📊 Dataset Statistics")
	print("--- 🔹 Total Apps              : {}".format(resultsStats["totalApps"]))
	print("\n--- 🎯 Analyzed Apps")
	print("--- 🔹 Success                 : {} [{:.2%}]".format(resultsStats["numSuccess"], resultsStats["pctSuccess"]))
	print("--- 🔹 Error                   : {} [{:.2%}]".format(resultsStats["numError"], resultsStats["pctError"]))
	print("--- 🔹 Zero Smali Classes      : {} [{:.2%}]".format(resultsStats["numZeroSmaliClasses"], resultsStats["pctZeroSmaliClasses"]))

	# Log end message with time
	endTime 	= datetime.datetime.now()
	totalTime 	= endTime - initTime
	hours 		= totalTime.total_seconds() // 3600
	minutes 	= (totalTime.total_seconds() % 3600) // 60
	print("\n--- 🔚 END: {} 🔚".format(endTime.strftime("%Y-%m-%d %H:%M:%S")))
	print("--- ⏱️  Time: {:02d} hours and {:02d} minutes [{:02d} seconds] ⏱️".format(int(hours), int(minutes), int(totalTime.total_seconds())))

# Entry point of the script
if __name__ == "__main__":
	# Try main
	try:
		main()
	except Exception as exc:
		print("\n--- ❌ Fatal error: {}".format(exc), file = sys.stderr)
		sys.exit(1)
