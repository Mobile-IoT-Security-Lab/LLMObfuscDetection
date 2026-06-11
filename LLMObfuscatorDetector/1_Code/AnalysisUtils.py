from   pydantic import BaseModel, ValidationError, create_model
from   typing   import Literal
import csv
import json
import math
import os
import random
import yaml

### Custom exceptions ###
class AnalysisUtilsError(Exception):
	pass

class PromptNotFoundError(AnalysisUtilsError):
	pass

class InvalidAnalysisParameterError(AnalysisUtilsError):
	pass

class InvalidLlmOutputError(AnalysisUtilsError):
	pass

class LlmRetryLimitExceededError(AnalysisUtilsError):
	pass

class BooleanLabelSchema(BaseModel):
	label: bool


# Build a dynamic schema for classification labels constrained to the expected label set.
def _buildTechniqueLabelSchema(expectedLabels):
	if expectedLabels is None or len(expectedLabels) == 0:
		raise InvalidAnalysisParameterError("expectedLabels must contain at least one label.")

	literalLabels = Literal.__getitem__(tuple(expectedLabels))
	return create_model("TechniqueLabelSchema", label = (literalLabels, ...))

# Utility class for analysis tasks, including prompt management, result handling, LLM interaction, and statistics computation.
class AnalysisUtils:

	# Load prompts from disk.
	@staticmethod
	def loadPrompts(promptsPath):
		with open(promptsPath, "r", encoding = "utf-8") as promptFile:
			return yaml.safe_load(promptFile)

	# Load existing results if they exist.
	@staticmethod
	def loadExistingResults(resultsPath):
		if not os.path.exists(resultsPath):
			return []

		with open(resultsPath, "r", encoding = "utf-8") as resultsFile:
			return json.load(resultsFile)

	# Save results to disk.
	@staticmethod
	def saveResults(results, resultsPath):
		outputDir = os.path.dirname(resultsPath)
		if outputDir != "" and not os.path.exists(outputDir):
			os.makedirs(outputDir)

		with open(resultsPath, "w", encoding = "utf-8") as resultsFile:
			json.dump(results, resultsFile, indent = 4)

	# Save results as CSV.
	@staticmethod
	def saveResultsAsCsv(results, resultsPath):
		outputDir = os.path.dirname(resultsPath)
		if outputDir != "" and not os.path.exists(outputDir):
			os.makedirs(outputDir)

		fieldNames = [
			"sha256",
			"pkgName",
			"obfuscationTechnique",
			"status",
			"numSmaliClasses",
			"numSmaliClassesAnalyzed",
			"llmFinalLabel"
		]
		if any("pctSmaliClassesObfuscated" in result for result in results):
			fieldNames.insert(6, "pctSmaliClassesObfuscated")
		with open(resultsPath, "w", encoding = "utf-8", newline = "") as resultsFile:
			writer = csv.DictWriter(resultsFile, fieldnames = fieldNames, extrasaction = "ignore")
			writer.writeheader()
			for result in results:
				writer.writerow(result)

	# Create a result object for the current app.
	@staticmethod
	def createResultsObject(sha256, pkgName, status, obfuscationTechnique = None, numSmaliClasses = 0, numSmaliClassesAnalyzed = 0, pctSmaliClassesObfuscated = None, llmFinalLabel = False, labelFrequency = None):
		result = {
			"sha256"                    : sha256,
			"pkgName"                   : pkgName,
			"obfuscationTechnique"      : obfuscationTechnique,
			"status"                    : status,
			"numSmaliClasses"           : numSmaliClasses,
			"numSmaliClassesAnalyzed"   : numSmaliClassesAnalyzed,
			"llmFinalLabel"             : llmFinalLabel
		}
		if pctSmaliClassesObfuscated is not None:
			result["pctSmaliClassesObfuscated"] = round(pctSmaliClassesObfuscated, 2)
		if labelFrequency is not None:
			result["labelFrequency"] = labelFrequency
		return result

	# Get a specific prompt using its ID.
	@staticmethod
	def getPromptById(prompts, promptId):
		for prompt in prompts:
			if prompt["promptID"] == promptId:
				return prompt

		raise PromptNotFoundError("Unknown promptID: {}".format(promptId))

	# Compute the minimum sample size for a finite population.
	@staticmethod
	def computeRandomSampleSize(populationSize, confidenceLevel, errorMargin):
		if populationSize <= 0:
			return 0

		zScoreMap = {
			90 : 1.645,
			95 : 1.960,
			99 : 2.576
		}

		if confidenceLevel not in zScoreMap:
			raise InvalidAnalysisParameterError("Unsupported CONFIDENCE_LEVEL: {}".format(confidenceLevel))

		zScore     = zScoreMap[confidenceLevel]
		errorRatio = errorMargin / 100
		pEstimate  = 0.5
		baseSize   = (zScore ** 2) * pEstimate * (1 - pEstimate) / (errorRatio ** 2)
		sampleSize = (populationSize * baseSize) / (populationSize + baseSize - 1)

		return min(populationSize, max(1, math.ceil(sampleSize)))

	# Get a deterministic random sample from the Smali classes.
	@staticmethod
	def getRandomSample(smaliClasses, sampleSize, randomSeed = 42):
		if sampleSize <= 0:
			return []

		randomGenerator = random.Random(randomSeed)
		return randomGenerator.sample(smaliClasses, sampleSize)

	# Build the generic prompt for a specific Smali class.
	@staticmethod
	def buildSmaliPrompt(promptTemplate, smaliClass, **promptVariables):
		if "expectedLabels" in promptVariables and isinstance(promptVariables["expectedLabels"], (list, tuple)):
			promptVariables["expectedLabels"] = ", ".join(promptVariables["expectedLabels"])

		return promptTemplate.format(
			className    = smaliClass["className"],
			classContent = smaliClass["classContent"],
			**promptVariables
		)

# Utility class for obfuscation detection analysis, including prompt management, LLM interaction, result handling, and statistics computation.
class ObfuscationDetectionAnalysisUtils:

	# Build the prompt for a specific Smali class.
	@staticmethod
	def buildObfuscationPrompt(promptTemplate, smaliClass):
		return AnalysisUtils.buildSmaliPrompt(promptTemplate, smaliClass)

	# Parse the LLM reply as a boolean.
	@staticmethod
	def parseLlmBoolean(rawReply):
		normalizedReply = rawReply.strip().lower()

		if normalizedReply.startswith("true"):
			return True
		if normalizedReply.startswith("false"):
			return False
		if "true" in normalizedReply and "false" not in normalizedReply:
			return True
		if "false" in normalizedReply and "true" not in normalizedReply:
			return False

		raise InvalidLlmOutputError("Unable to parse LLM boolean reply: {}".format(rawReply))

	# Try to parse a structured LLM reply using the expected schema.
	@staticmethod
	def parseStructuredBooleanReply(parsedReply):
		try:
			validatedReply = BooleanLabelSchema.model_validate(parsedReply)
		except ValidationError as exc:
			raise InvalidLlmOutputError("Unable to validate structured LLM reply: {}".format(exc))

		return validatedReply.label

	# Query the LLM with retry when the output format is invalid.
	@staticmethod
	def askForBooleanLabel(llmInterface, prompt, maxRetries = 3):
		if maxRetries <= 0:
			raise InvalidAnalysisParameterError("maxRetries must be > 0")

		lastRawReply = None

		for retryIdx in range(maxRetries):
			rawReply = None

			try:
				if hasattr(llmInterface, "supportsStructuredOutput") and llmInterface.supportsStructuredOutput():
					structuredReply = llmInterface.sendRequestWithSchema(prompt, BooleanLabelSchema)
					rawReply = structuredReply["rawReply"]
					label    = ObfuscationDetectionAnalysisUtils.parseStructuredBooleanReply(structuredReply["parsedReply"])
				else:
					rawReply = llmInterface.sendRequest(prompt)
					label    = ObfuscationDetectionAnalysisUtils.parseLlmBoolean(rawReply)

				lastRawReply = rawReply
				return {
					"label"    : label,
					"rawReply" : rawReply,
					"numTries" : retryIdx + 1
				}
			except (InvalidLlmOutputError, json.JSONDecodeError, ValidationError, ValueError, TypeError) as exc:
				lastRawReply = rawReply
				print("--- ⚠️ Invalid LLM output format [{}/{}] : {}".format(retryIdx + 1, maxRetries, rawReply))
				print("--- ⚠️ Parsing error detail: {}".format(exc))

		print("--- ❌ LLM failed to respect the output template after {} attempts.".format(maxRetries))
		raise LlmRetryLimitExceededError("Invalid LLM output after {} attempts: {}".format(maxRetries, lastRawReply))

	# Run the same prompt multiple times and keep the majority label.
	@staticmethod
	def analyzeSmaliClassWithMajorityVote(llmInterface, smaliClass, promptTemplate, numIterations, maxRetries = 3):
		if numIterations <= 0:
			raise InvalidAnalysisParameterError("numIterations must be > 0")

		trueCount  = 0
		falseCount = 0
		iterations = []
		prompt     = ObfuscationDetectionAnalysisUtils.buildObfuscationPrompt(promptTemplate, smaliClass)

		for _ in range(numIterations):
			iterationResult = ObfuscationDetectionAnalysisUtils.askForBooleanLabel(llmInterface, prompt, maxRetries = maxRetries)
			iterations.append(iterationResult)

			if iterationResult["label"]:
				trueCount += 1
			else:
				falseCount += 1

		majorityLabel = trueCount > falseCount
		if trueCount == falseCount:
			majorityLabel = iterations[-1]["label"]

		return {
			"prompt"        : prompt,
			"iterations"    : iterations,
			"trueCount"     : trueCount,
			"falseCount"    : falseCount,
			"majorityLabel" : majorityLabel
		}

	# Compute dataset-level statistics from detection results.
	@staticmethod
	def computeResultsStatistics(results):
		totalApps        = len(results)
		numSuccess       = sum(1 for result in results if result["status"] == "SUCCESS")
		numError         = sum(1 for result in results if str(result["status"]).startswith("ERROR -"))
		numZeroSmali     = sum(1 for result in results if result["status"] == "NO_SMALI_CLASSES")
		successResults   = [result for result in results if result["status"] == "SUCCESS"]
		numObfuscated    = sum(1 for result in successResults if result["llmFinalLabel"] is True)
		numNonObfuscated = sum(1 for result in successResults if result["llmFinalLabel"] is False)

		if totalApps == 0:
			return {
				"totalApps"                : 0,
				"numSuccess"               : 0,
				"pctSuccess"               : 0.0,
				"numError"                 : 0,
				"pctError"                 : 0.0,
				"numZeroSmaliClasses"      : 0,
				"pctZeroSmaliClasses"      : 0.0,
				"numObfuscatedAppsTrue"    : 0,
				"pctObfuscatedAppsTrue"    : 0.0,
				"numObfuscatedAppsFalse"   : 0,
				"pctObfuscatedAppsFalse"   : 0.0
			}

		return {
			"totalApps"                : totalApps,
			"numSuccess"               : numSuccess,
			"pctSuccess"               : numSuccess / totalApps,
			"numError"                 : numError,
			"pctError"                 : numError / totalApps,
			"numZeroSmaliClasses"      : numZeroSmali,
			"pctZeroSmaliClasses"      : numZeroSmali / totalApps,
			"numObfuscatedAppsTrue"    : numObfuscated,
			"pctObfuscatedAppsTrue"    : 0.0 if numSuccess == 0 else numObfuscated / numSuccess,
			"numObfuscatedAppsFalse"   : numNonObfuscated,
			"pctObfuscatedAppsFalse"   : 0.0 if numSuccess == 0 else numNonObfuscated / numSuccess
		}

# Utility class for obfuscation classification analysis, including prompt management, LLM interaction, result handling, and statistics computation.
class ObfuscationClassificationAnalysisUtils:

	# Build the prompt for classification by filling the template with the smali class content, name, and expected label list.
	@staticmethod
	def buildClassificationPrompt(promptTemplate, smaliClass, expectedLabels):
		return AnalysisUtils.buildSmaliPrompt(
			promptTemplate,
			smaliClass,
			expectedLabels = expectedLabels
		)

	# Normalize the raw label by stripping whitespace, punctuation, and quotes.
	@staticmethod
	def normalizeLabel(rawLabel):
		label = rawLabel.strip()
		label = label.strip(" \t\r\n\v\f" + "\"'.,:;!?()[]{}")
		return label

	# Parse LLM reply and extract the label, ensuring it matches one of the expected labels.
	@staticmethod
	def parseTechniqueLabel(rawReply, expectedLabels):
		normalizedReply = ObfuscationClassificationAnalysisUtils.normalizeLabel(rawReply)

		for label in expectedLabels:
			if normalizedReply.lower() == label.lower():
				return label

		raise InvalidLlmOutputError("Unable to parse LLM label reply: {}".format(rawReply))

	# Try to parse a structured LLM reply using a schema constrained to the expected labels.
	@staticmethod
	def parseStructuredTechniqueReply(parsedReply, expectedLabels):
		schemaClass = _buildTechniqueLabelSchema(expectedLabels)

		try:
			validatedReply = schemaClass.model_validate(parsedReply)
		except ValidationError as exc:
			raise InvalidLlmOutputError("Unable to validate structured LLM reply: {}".format(exc))

		return validatedReply.label

	# Ask the LLM for the obfuscation technique label with retries in case of invalid output format.
	@staticmethod
	def askForTechniqueLabel(llmInterface, prompt, expectedLabels, maxRetries = 3):
		if maxRetries <= 0:
			raise InvalidAnalysisParameterError("maxRetries must be > 0")

		lastRawReply = None

		for retryIdx in range(maxRetries):
			rawReply = None
			try:
				if hasattr(llmInterface, "supportsStructuredOutput") and llmInterface.supportsStructuredOutput():
					schemaClass     = _buildTechniqueLabelSchema(expectedLabels)
					structuredReply = llmInterface.sendRequestWithSchema(prompt, schemaClass)
					rawReply        = structuredReply["rawReply"]
					label           = ObfuscationClassificationAnalysisUtils.parseStructuredTechniqueReply(structuredReply["parsedReply"], expectedLabels)
				else:
					rawReply = llmInterface.sendRequest(prompt)
					label    = ObfuscationClassificationAnalysisUtils.parseTechniqueLabel(rawReply, expectedLabels)

				lastRawReply = rawReply
				return {
					"label"    : label,
					"rawReply" : rawReply,
					"numTries" : retryIdx + 1
				}
			except Exception as exc:
				lastRawReply = rawReply
				print("--- ⚠️ Invalid LLM output format [{}/{}] : {}".format(retryIdx + 1, maxRetries, rawReply))
				print("--- ⚠️ Parsing error detail				: {}".format(exc))
				print("--- ⚠️ Expected labels at failure		: {}".format(expectedLabels))

		print("--- ❌ LLM failed to respect the output template after {} attempts.".format(maxRetries))
		raise LlmRetryLimitExceededError("Invalid LLM output after {} attempts: {}".format(maxRetries, lastRawReply))

	# Analyze a smali class with multiple iterations and majority voting to determine the final predicted label.
	@staticmethod
	def analyzeSmaliClassWithMajorityVote(llmInterface, smaliClass, promptTemplate, expectedLabels, numIterations, maxRetries = 3):
		if numIterations <= 0:
			raise InvalidAnalysisParameterError("numIterations must be > 0")

		prompt      = ObfuscationClassificationAnalysisUtils.buildClassificationPrompt(promptTemplate, smaliClass, expectedLabels)
		iterations  = []
		labelCounts = {}

		for _ in range(numIterations):
			iterationResult = ObfuscationClassificationAnalysisUtils.askForTechniqueLabel(
				llmInterface  = llmInterface,
				prompt        = prompt,
				expectedLabels = expectedLabels,
				maxRetries    = maxRetries
			)
			iterations.append(iterationResult)

			label = iterationResult["label"]
			labelCounts[label] = labelCounts.get(label, 0) + 1

		majorityLabel = max(expectedLabels, key = lambda label: (labelCounts.get(label, 0), label == iterations[-1]["label"]))
		return {
			"prompt"        : prompt,
			"iterations"    : iterations,
			"labelCounts"   : labelCounts,
			"majorityLabel" : majorityLabel
		}

	# Compute dataset-level statistics from classification results.
	@staticmethod
	def computeResultsStatistics(results):
		totalApps    = len(results)
		numSuccess   = sum(1 for result in results if result["status"] == "SUCCESS")
		numError     = sum(1 for result in results if str(result["status"]).startswith("ERROR -"))
		numZeroSmali = sum(1 for result in results if result["status"] == "NO_SMALI_CLASSES")

		if totalApps == 0:
			return {
				"totalApps"           : 0,
				"numSuccess"          : 0,
				"pctSuccess"          : 0.0,
				"numError"            : 0,
				"pctError"            : 0.0,
				"numZeroSmaliClasses" : 0,
				"pctZeroSmaliClasses" : 0.0
			}

		return {
			"totalApps"           : totalApps,
			"numSuccess"          : numSuccess,
			"pctSuccess"          : numSuccess / totalApps,
			"numError"            : numError,
			"pctError"            : numError / totalApps,
			"numZeroSmaliClasses" : numZeroSmali,
			"pctZeroSmaliClasses" : numZeroSmali / totalApps
		}
