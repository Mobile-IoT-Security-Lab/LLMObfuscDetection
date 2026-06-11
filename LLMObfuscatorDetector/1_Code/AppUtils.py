from   dotenv                import load_dotenv
import xml.etree.ElementTree as ET
import pandas                as pd
import subprocess
import requests
import shutil
import json
import time
import os
import re
import hashlib

# Class representing an Android App
class App:

	# Fields
	sha256            = None
	apkPath           = None
	alreadyDownloaded = False
	smaliClasses      = None
	numSmaliClasses   = 0

	# Initialize the App object.
	def __init__(self, sha256, pkgName, tmpPath, downloadedApkPath = None):
		self.sha256  = sha256
		self.pkgName = pkgName
		self.apkPath = tmpPath + sha256 + ".apk"
		self.smaliClasses    = []
		self.numSmaliClasses = 0
		
		# If the app is already Downloaded somewhere:
		if downloadedApkPath is not None:
			#print("--- 📤 APK file already downloaded.")
			shutil.copy(downloadedApkPath, self.apkPath)
			self.alreadyDownloaded = True

	# Compute SHA256 for a local file.
	@staticmethod
	def computeFileSha256(filePath):
		sha256Hash = hashlib.sha256()

		with open(filePath, "rb") as inputFile:
			while True:
				chunk = inputFile.read(8192)
				if not chunk:
					break
				sha256Hash.update(chunk)

		return sha256Hash.hexdigest().upper()

	### Apk Related ###
	# Download APK File from AndroZoo.
	def downloadAPK(self):
		MAX_RETRIES = 10
		RETRY_DELAY = 30  # seconds
		
		# Load AndroZoo API KEY
		load_dotenv()
		apiKey = os.getenv("ANDROZOO_API_KEY")
		sha256 = self.sha256

		print("\n--- ⭕ Downloading from AZ...")
		
		# Check if the file already exists
		if os.path.exists(self.apkPath):
			print("--- 📤 APK file with SHA256 already exists.")
			return
		
		# Define request parameters and headers
		params  = {"apikey": apiKey, "sha256": sha256}
		headers = {"User-Agent": "Wget/1.21.1 (linux-gnu)"}
		
		retries = 0
		while retries < MAX_RETRIES:
			
			try:
				# Attempt to download from the first URL
				response = requests.get("http://serval10.uni.lu/api/download", params=params, headers=headers, timeout=1)
			except requests.RequestException:
				# Fall back to the second URL if the first one fails
				response = requests.get("http://androzoo.uni.lu/api/download", params=params, headers=headers, timeout=10)

			# Check for HTTP errors
			if response.status_code in [502, 503]:
				print(f"--- ❌ Error: Received status code {response.status_code}. Retrying in {RETRY_DELAY} seconds...")
				retries += 1
				time.sleep(RETRY_DELAY)
			elif response.status_code == 200:
				# Save the downloaded content to the specified file path
				with open(self.apkPath, "wb") as apkFile:
					apkFile.write(response.content)

				# Store the apkPath
				self.alreadyDownloaded = True
				print(f"--- 💾 APK file downloaded and saved to {self.apkPath}")
				return
			else:
				print(f"--- ❌ Error: Received unexpected status code {response.status_code}.")
				return
		
		print(f"--- ❌ Error: Failed to download APK after {MAX_RETRIES} attempts.")

	# Delete the APK file.
	def deleteAPK(self):
		try:
			print("\n--- 🗑️ Deleting APK File.")
			os.remove(self.apkPath)
			print("--- ✅ Success.")
		except OSError as e:
			print("--- ⚠️ Error : {}\n".format(e))

	# Delete everything related to the analyzed app.
	def deleteAll(self):
		try:
			print("--- 🗑️ Deleting all app-related files")
			shutil.rmtree(self.apkPath[:-4])
			self.smaliClasses    = []
			self.numSmaliClasses = 0
			print("--- ✅ Success.")
		except OSError as e:
			print("--- ⚠️ Error: {}".format(e))


	# Decompile the APK File using ApkTool.
	def decompileWithApktool(self):
		try:
			# Command to decompile APK using Apktool
			print("\n--- ⭕ Decompiling with ApkTool...")

			# Run apktool
			command = ["apktool", "d", "-f", '-o', self.apkPath[:-4], "-q", self.apkPath]
			subprocess.run(command, check=True)
			print("--- ✅ Success.")

		except subprocess.CalledProcessError as e:
			print("⚠️ --- Error : {}".format(e))

	# Get the decompiled APK folder path.
	def getDecompiledPath(self):
		return self.apkPath[:-4]

	# Read the package name from the decompiled AndroidManifest.xml, if available.
	def getPkgNameFromManifest(self):
		manifestPath = os.path.join(self.getDecompiledPath(), "AndroidManifest.xml")
		if not os.path.exists(manifestPath):
			return None

		try:
			manifestTree = ET.parse(manifestPath)
			manifestRoot = manifestTree.getroot()
		except ET.ParseError:
			return None

		pkgName = manifestRoot.attrib.get("package")
		if pkgName is None:
			return None

		pkgName = pkgName.strip()
		return pkgName if pkgName != "" else None

	# Collect all Smali Classes from the decompiled APK.
	def collectSmaliClasses(self):
		# Path from ApkTool
		decompiledPath = self.getDecompiledPath()

		# Error if apktool did not work
		if not os.path.exists(decompiledPath):
			print("--- ⚠️ Decompiled folder not found : {}".format(decompiledPath))
			self.smaliClasses    = []
			self.numSmaliClasses = 0
			return []

		print("\n--- ⭕ Collecting Smali Classes...")

		smaliClasses = []
		for root, _, files in os.walk(decompiledPath):
			for fileName in files:
				if not fileName.endswith(".smali"):
					continue

				smaliPath = os.path.join(root, fileName)
				with open(smaliPath, "r", encoding = "utf-8", errors = "ignore") as smaliFile:
					smaliCode = self.removeSmaliLineDirectives(smaliFile.read())

				className = self.extractSmaliClassName(smaliCode)
				if className is None:
					className = os.path.relpath(smaliPath, decompiledPath).replace(".smali", "")

				className = self.normalizeClassName(className)

				smaliClasses.append({
					"className"    : className,
					"classContent" : smaliCode
				})

		# Save them
		self.smaliClasses    = smaliClasses
		self.numSmaliClasses = len(smaliClasses)

		# Print and return
		print("--- #️⃣ N. Smali Classes: {}".format(self.numSmaliClasses))
		return self.smaliClasses

	# Extract the class name from a Smali file.
	def extractSmaliClassName(self, smaliCode):
		match = re.search(r"^\.class[^\n]*?(L[^;]+;)", smaliCode, re.MULTILINE)
		if match is None:
			return None
		return match.group(1)

	# Remove Smali debug line directives from class content.
	def removeSmaliLineDirectives(self, smaliCode):
		return "\n".join(
			line for line in smaliCode.splitlines()
			if re.match(r"^\s*\.line\s+\d+\s*$", line) is None
		)

	# Normalize Smali class name to dotted Java-like notation.
	def normalizeClassName(self, className):
		className = className.replace("/", ".")
		className = className.replace("\\", ".")

		if className.startswith("L"):
			className = className[1:]

		if className.endswith(";"):
			className = className[:-1]

		return className

	# Get the folder containing the library prefix files.
	def getLibsFilesPath(self):
		return os.path.abspath(os.path.join(os.path.dirname(__file__), "../0_Data/LibsFiles"))

	# Get the project root path.
	def getProjectRootPath(self):
		return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

	# Resolve a path from .env or use a fallback path.
	def resolvePathFromEnv(self, envVarName, fallbackPath):
		load_dotenv()
		pathFromEnv = os.getenv(envVarName)

		if pathFromEnv is None or pathFromEnv.strip() == "":
			return fallbackPath

		if os.path.isabs(pathFromEnv):
			return pathFromEnv

		return os.path.abspath(os.path.join(self.getProjectRootPath(), pathFromEnv))

	# Load class/package prefixes from a text file.
	def loadPrefixesFromFile(self, fileName, envVarName = None):
		defaultFilePath = os.path.join(self.getLibsFilesPath(), fileName)
		filePath        = defaultFilePath

		if envVarName is not None:
			filePath = self.resolvePathFromEnv(envVarName, defaultFilePath)

		with open(filePath, "r", encoding = "utf-8") as prefixesFile:
			return [line.strip() for line in prefixesFile.readlines() if line.strip() != ""]

	# Check whether a class belongs to one of the provided prefixes.
	def classMatchesPrefixes(self, className, prefixes):
		for prefix in prefixes:
			if className == prefix or className.startswith(prefix + "."):
				return True
		return False

	# Apply a generic filter on the stored Smali classes.
	def applySmaliClassesFilter(self, filterName, keepCondition):
		numSmaliClassesBefore = len(self.smaliClasses)
		filteredSmaliClasses  = [smaliClass for smaliClass in self.smaliClasses if keepCondition(smaliClass)]
		numSmaliClassesAfter  = len(filteredSmaliClasses)
		numRemovedClasses     = numSmaliClassesBefore - numSmaliClassesAfter

		self.smaliClasses    = filteredSmaliClasses
		self.numSmaliClasses = numSmaliClassesAfter

		print("--- 🧹 Filter [{:<12}] -> Remaining: {} | Removed: {}".format(filterName, numSmaliClassesAfter, numRemovedClasses))
		return self.smaliClasses

	# Filter out Android system libraries from the stored Smali classes.
	def filterOutSystemLibraries(self):
		systemLibraries = self.loadPrefixesFromFile("SystemLibraries.txt", "SYSTEM_LIBRARIES_PATH")
		return self.applySmaliClassesFilter(
			"system",
			lambda smaliClass: not self.classMatchesPrefixes(smaliClass["className"], systemLibraries)
		)

	# Filter out Smali classes whose class name contains '$'.
	def filterOutClassesContainingDollarSign(self):
		return self.applySmaliClassesFilter(
			"noDollarSign",
			lambda smaliClass: "$" not in smaliClass["className"]
		)

	# Filter out third-party libraries from the stored Smali classes.
	def filterOutThirdPartyLibraries(self):
		thirdPartyLibraries = self.loadPrefixesFromFile("AndroLibZoo.txt", "THIRD_PARTY_LIBRARIES_PATH")
		return self.applySmaliClassesFilter(
			"tp",
			lambda smaliClass: not self.classMatchesPrefixes(smaliClass["className"], thirdPartyLibraries)
		)

	# Keep only classes that match the app package name prefix.
	def filterByPkgName(self):
		return self.applySmaliClassesFilter(
			"pkgNameOnly",
			lambda smaliClass: self.classMatchesPrefixes(smaliClass["className"], [self.pkgName])
		)
