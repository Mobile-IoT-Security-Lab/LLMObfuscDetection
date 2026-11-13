"""Exercise the classification driver without APK tools, credentials, or model APIs."""

from contextlib import redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


CODE_DIR = Path(__file__).resolve().parents[1] / "1_Code"
sys.path.insert(0, str(CODE_DIR))

from AnalysisUtils import AnalysisUtils, OBFUSCATION_TECHNIQUES  # noqa: E402


TRIPLE = ["ClassRename", "FieldRename", "Goto"]
OTHER_TRIPLE = ["ClassRename", "FieldRename", "Reflection"]
PROMPT_TEMPLATE = "Class: {className}\n{classContent}\nAllowed: {expectedLabels}"


class FakeApp:
    instances = []

    def __init__(self, sha256, pkg_name, tmp_path, downloadedApkPath):
        self.pkgName = pkg_name
        self.smaliClasses = [
            {"className": "example.First", "classContent": ".class public Lexample/First;"},
            {"className": "example.Second", "classContent": ".class public Lexample/Second;"},
        ]
        self.numSmaliClasses = 2
        self.apk_deleted = False
        self.decompiled_deleted = False
        self.instances.append(self)

    def decompileWithApktool(self):
        pass

    def getPkgNameFromManifest(self):
        return self.pkgName

    def collectSmaliClasses(self):
        pass

    def deleteAPK(self):
        self.apk_deleted = True

    def deleteAll(self):
        self.decompiled_deleted = True


class FakeTokenizer:
    def getNumTokens(self, prompt):
        return 20


class PerClassBackend:
    def __init__(self, first_replies, second_replies):
        self.replies = {
            "example.First": iter(first_replies),
            "example.Second": iter(second_replies),
        }
        self.num_calls = 0

    def supportsStructuredOutput(self):
        return False

    def sendRequest(self, prompt):
        self.num_calls += 1
        for class_name, replies in self.replies.items():
            if "Class: " + class_name + "\n" in prompt:
                return next(replies)
        raise AssertionError("Unexpected class in prompt")


def load_driver_without_external_dependencies():
    app_module = types.ModuleType("AppUtils")
    app_module.App = FakeApp
    llm_module = types.ModuleType("LLMUtils")
    llm_module.OpenAiTokenizer = FakeTokenizer
    dotenv_module = types.ModuleType("dotenv")
    dotenv_module.load_dotenv = lambda: None
    spec = importlib.util.spec_from_file_location(
        "classification_driver_under_test", CODE_DIR / "3_ObfuscationClassification" / "experiments.py",
    )
    driver = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {
        "AppUtils": app_module, "LLMUtils": llm_module, "dotenv": dotenv_module,
    }):
        spec.loader.exec_module(driver)
    return driver


class ClassificationDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = load_driver_without_external_dependencies()

    def setUp(self):
        FakeApp.instances = []

    def analyze(self, backend, num_labels):
        record = {
            "sha256": "c" * 64, "pkgName": "example.app",
            "obfuscationTechnique": "ClassRename", "alreadyDownloadedPath": "unused-test.apk",
        }
        with patch.object(self.driver, "FILTERING", None), \
                patch.object(self.driver, "SILENT_MODE", True), \
                patch.object(self.driver, "NUM_ITERATIONS", 5), \
                patch.object(self.driver, "MAX_RETRIES", 2), \
                redirect_stdout(io.StringIO()):
            result = self.driver.analyzeApkRecord(
                record, backend, PROMPT_TEMPLATE, OBFUSCATION_TECHNIQUES,
                techniqueDirName="ClassRename", numLabels=num_labels,
            )
        self.assertEqual(result["status"], "SUCCESS", result)
        self.assertTrue(FakeApp.instances[-1].apk_deleted)
        self.assertTrue(FakeApp.instances[-1].decompiled_deleted)
        return result

    def test_multi_apk_aggregates_final_class_votes_not_thirty_inference_votes(self):
        first = [", ".join(TRIPLE)] * 3 + [", ".join(OTHER_TRIPLE)] * 2
        second = [", ".join(OTHER_TRIPLE)] * 4 + [", ".join(TRIPLE)]
        backend = PerClassBackend(first, second)
        result = self.analyze(backend, num_labels=3)
        self.assertEqual(backend.num_calls, 10)
        self.assertEqual(result["numSmaliClassesAnalyzed"], 2)
        self.assertEqual(result["labelFrequency"], {
            "ClassRename": 2, "FieldRename": 2, "Goto": 1, "Reflection": 1,
        })
        self.assertEqual(sum(result["labelFrequency"].values()), 6)
        self.assertEqual(result["llmFinalLabels"], TRIPLE)
        self.assertEqual(result["rankedLabels"], TRIPLE + ["Reflection"])
        self.assertEqual(result["numLabelsPerClass"], 3)
        self.assertNotIn("llmFinalLabel", result)
        # A directory name does not assert the applied triple for an APK.
        self.assertIsNone(result["obfuscationTechnique"])

    def test_invalid_multi_class_is_skipped_without_discarding_valid_class(self):
        backend = PerClassBackend(["ClassRename"] * 2, [", ".join(TRIPLE)] * 5)
        result = self.analyze(backend, num_labels=3)
        self.assertEqual(backend.num_calls, 7)
        self.assertEqual(result["numSmaliClassesAnalyzed"], 1)
        self.assertEqual(result["labelFrequency"], dict.fromkeys(TRIPLE, 1))
        self.assertEqual(result["llmFinalLabels"], TRIPLE)

    def test_single_apk_keeps_scalar_output_and_alphabetic_tie_break(self):
        backend = PerClassBackend(["Reflection"] * 5, ["ClassRename"] * 5)
        result = self.analyze(backend, num_labels=1)
        self.assertEqual(backend.num_calls, 10)
        self.assertEqual(result["labelFrequency"], {"Reflection": 1, "ClassRename": 1})
        self.assertEqual(result["llmFinalLabel"], "ClassRename")
        self.assertNotIn("llmFinalLabels", result)
        self.assertEqual(result["numLabelsPerClass"], 1)
        self.assertEqual(result["obfuscationTechnique"], "ClassRename")

    def valid_multi_result(self):
        return AnalysisUtils.createResultsObject(
            sha256="d" * 64, pkgName="example.cached", status="SUCCESS",
            numSmaliClasses=2, numSmaliClassesAnalyzed=2,
            llmFinalLabels=TRIPLE, numLabelsPerClass=3, rankedLabels=TRIPLE,
            labelFrequency=dict.fromkeys(TRIPLE, 2),
        )

    def test_resume_rejects_legacy_wrong_mode_failed_and_malformed_predictions(self):
        valid = self.valid_multi_result()
        self.assertTrue(self.driver.isReusableClassificationResult(valid, 3))
        legacy = deepcopy(valid)
        legacy.pop("numLabelsPerClass")
        failed = dict(valid, status="ERROR - invalid output")
        single_shape = deepcopy(valid)
        single_shape.pop("llmFinalLabels")
        single_shape["llmFinalLabel"] = "ClassRename"
        duplicate = dict(valid, llmFinalLabels=["ClassRename", "ClassRename", "Goto"])
        unknown = dict(valid, llmFinalLabels=["ClassRename", "FieldRename", "ResStringEncryption"])
        empty_counts = dict(valid, labelFrequency={})
        for result in [legacy, failed, single_shape, duplicate, unknown, empty_counts]:
            with self.subTest(result=result):
                self.assertFalse(self.driver.isReusableClassificationResult(result, 3))
        self.assertFalse(self.driver.isReusableClassificationResult(valid, 1))

    def test_resume_backs_up_original_bytes_before_excluding_legacy_records(self):
        valid = self.valid_multi_result()
        legacy = {"sha256": "e" * 64, "status": "SUCCESS", "llmFinalLabel": "ClassRename"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.json"
            original = json.dumps([legacy, valid], indent=2).encode("utf-8")
            path.write_bytes(original)
            with redirect_stdout(io.StringIO()):
                reusable = self.driver.loadReusableClassificationResults(path, 3)
            self.assertEqual(reusable, [valid])
            backups = list(Path(directory).glob("results.json.backup-*"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_bytes(), original)
            self.assertEqual(path.read_bytes(), original)

    def test_resume_preserves_valid_multi_cache_without_creating_backup(self):
        valid = self.valid_multi_result()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.json"
            AnalysisUtils.saveResults([valid], path)
            self.assertEqual(self.driver.loadReusableClassificationResults(path, 3), [valid])
            self.assertEqual(list(Path(directory).glob("results.json.backup-*")), [])


if __name__ == "__main__":
    unittest.main()
