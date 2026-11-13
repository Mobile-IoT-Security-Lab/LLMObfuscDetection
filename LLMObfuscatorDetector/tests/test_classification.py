"""Classification regressions; all inference responses are local test doubles.

Run from the repository root with:
    python -m unittest discover -s LLMObfuscatorDetector/tests -v
"""

import ast
from contextlib import redirect_stdout
import csv
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest


CODE_DIR = Path(__file__).resolve().parents[1] / "1_Code"
sys.path.insert(0, str(CODE_DIR))

from AnalysisUtils import (  # noqa: E402
    AnalysisUtils,
    InvalidLlmOutputError,
    LlmRetryLimitExceededError,
    OBFUSCATION_TECHNIQUES,
    ObfuscationClassificationAnalysisUtils as Classification,
    getClassificationLabelCount,
    rankTechniqueLabels,
)


LABELS = tuple(OBFUSCATION_TECHNIQUES)
TRIPLE = ["ClassRename", "FieldRename", "Goto"]
SMALI_CLASS = {"className": "example.Test", "classContent": ".class public Lexample/Test;"}
PROMPT_TEMPLATE = "{className}\n{classContent}\nLabels: {expectedLabels}"


class TextBackend:
    """A finite response sequence; never imports or contacts a model provider."""

    def __init__(self, replies):
        self.replies = iter(replies)
        self.prompts = []

    def supportsStructuredOutput(self):
        return False

    def sendRequest(self, prompt):
        self.prompts.append(prompt)
        return next(self.replies)


class StructuredBackend:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.schemas = []

    def supportsStructuredOutput(self):
        return True

    def sendRequestWithSchema(self, prompt, schema):
        self.schemas.append(schema)
        parsed = next(self.replies)
        return {"parsedReply": parsed, "rawReply": json.dumps(parsed)}

    def sendRequest(self, prompt):
        raise AssertionError("Structured classification must not silently use text fallback")


class PromptConfigurationTests(unittest.TestCase):
    def test_yaml_retains_all_five_distinct_prompts_and_driver_default(self):
        prompts = AnalysisUtils.loadPrompts(CODE_DIR / "prompt.yaml")
        ids = [prompt["promptID"] for prompt in prompts]
        self.assertEqual(len(ids), 5)
        self.assertEqual(len(set(ids)), 5)
        self.assertEqual(set(ids), {
            "ObfuscationDetectionV1", "ObfuscationDetectionV2", "ObfuscationDetectionV3",
            "ObfuscationClassificationV1", "ObfuscationMultiClassificationV1",
        })
        # Read the CLI's declared default without importing inference dependencies.
        driver = ast.parse((CODE_DIR / "3_ObfuscationClassification" / "experiments.py").read_text())
        default_node = next(
            node.value for node in driver.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "DEFAULT_PROMPT_ID"
                    for target in node.targets)
        )
        default_id = ast.literal_eval(default_node)
        default_prompt = AnalysisUtils.getPromptById(prompts, default_id)
        self.assertEqual(default_id, "ObfuscationClassificationV1")
        self.assertEqual(default_prompt["promptID"], default_id)

    def test_canonical_taxonomy_and_both_classification_prompts_agree(self):
        self.assertEqual(set(LABELS), {
            "ArithmeticBranch", "CallIndirection", "ClassRename", "ConstStringEncryption",
            "FieldRename", "Goto", "MethodOverload", "MethodRename", "Reorder", "Reflection",
        })
        self.assertEqual(len(LABELS), 10)
        self.assertNotIn("ResStringEncryption", LABELS)
        prompts = AnalysisUtils.loadPrompts(CODE_DIR / "prompt.yaml")
        for prompt_id, count in [("ObfuscationClassificationV1", 1),
                                 ("ObfuscationMultiClassificationV1", 3)]:
            with self.subTest(prompt=prompt_id):
                self.assertEqual(getClassificationLabelCount(prompt_id), count)
                template = AnalysisUtils.getPromptById(prompts, prompt_id)["promptTemplate"]
                for label in LABELS:
                    self.assertRegex(template, r"-\s*" + label + r"\s*:")
                self.assertNotIn("ResStringEncryption", template)


class ClassificationParsingTests(unittest.TestCase):
    def test_multi_csv_normalizes_case_and_preserves_three_distinct_labels(self):
        self.assertEqual(
            Classification.parseTechniqueLabels(" classrename, FIELDRENAME, Goto ", LABELS),
            TRIPLE,
        )

    def test_multi_csv_rejects_wrong_counts_duplicates_and_unknown_labels(self):
        invalid = [
            "ClassRename",
            "ClassRename, FieldRename",
            "ClassRename, FieldRename, Goto, Reflection",
            "ClassRename, classrename, Goto",
            "ClassRename, FieldRename, ResStringEncryption",
            "ClassRename, FieldRename, unknown",
            "",
        ]
        for reply in invalid:
            with self.subTest(reply=reply), self.assertRaises(InvalidLlmOutputError):
                Classification.parseTechniqueLabels(reply, LABELS, numLabels=3)

    def test_multi_structured_accepts_three_labels(self):
        self.assertEqual(
            Classification.parseStructuredTechniqueReply({"labels": TRIPLE}, LABELS, numLabels=3),
            TRIPLE,
        )

    def test_multi_structured_rejects_single_shape_wrong_counts_and_duplicates(self):
        invalid = [
            {"label": "ClassRename"},
            {"labels": ["ClassRename", "FieldRename"]},
            {"labels": TRIPLE + ["Reflection"]},
            {"labels": ["ClassRename", "ClassRename", "Goto"]},
            {"labels": ["ClassRename", "classrename", "Goto"]},
            {"labels": ["ClassRename", "FieldRename", "ResStringEncryption"]},
            {"labels": "ClassRename, FieldRename, Goto"},
        ]
        for reply in invalid:
            with self.subTest(reply=reply), self.assertRaises(InvalidLlmOutputError):
                Classification.parseStructuredTechniqueReply(reply, LABELS, numLabels=3)

    def test_single_label_text_and_structured_interfaces_remain_compatible(self):
        self.assertEqual(Classification.parseTechniqueLabel(' "reflection". ', LABELS), "Reflection")
        self.assertEqual(
            Classification.parseStructuredTechniqueReply({"label": "Reorder"}, LABELS),
            "Reorder",
        )
        with self.assertRaises(InvalidLlmOutputError):
            Classification.parseTechniqueLabel("ClassRename, FieldRename, Goto", LABELS)


class ClassificationInferenceTests(unittest.TestCase):
    def test_multi_invalid_single_reply_retries_instead_of_accepting_one_label(self):
        backend = TextBackend(["ClassRename", ", ".join(TRIPLE)])
        with redirect_stdout(io.StringIO()):
            result = Classification.askForTechniqueLabel(
                backend, "prompt", LABELS, maxRetries=2, numLabels=3,
            )
        self.assertEqual(result["labels"], TRIPLE)
        self.assertEqual(result["numTries"], 2)
        self.assertEqual(len(backend.prompts), 2)

    def test_multi_retry_exhaustion_does_not_return_a_single_label(self):
        backend = TextBackend(["ClassRename", "FieldRename"])
        with redirect_stdout(io.StringIO()), self.assertRaises(LlmRetryLimitExceededError):
            Classification.askForTechniqueLabel(backend, "prompt", LABELS, maxRetries=2, numLabels=3)
        self.assertEqual(len(backend.prompts), 2)

    def test_structured_multi_retries_invalid_shape_and_uses_multi_schema(self):
        backend = StructuredBackend([{"label": "ClassRename"}, {"labels": TRIPLE}])
        with redirect_stdout(io.StringIO()):
            result = Classification.askForTechniqueLabel(
                backend, "prompt", LABELS, maxRetries=2, numLabels=3,
            )
        self.assertEqual(result["labels"], TRIPLE)
        self.assertEqual(result["numTries"], 2)
        self.assertEqual(len(backend.schemas), 2)
        self.assertIn("labels", backend.schemas[-1].model_json_schema()["properties"])

    def test_structured_invalid_output_does_not_fall_back_to_raw_text(self):
        class MisleadingStructuredBackend(StructuredBackend):
            def sendRequestWithSchema(self, prompt, schema):
                self.schemas.append(schema)
                return {"parsedReply": {"label": "ClassRename"}, "rawReply": ", ".join(TRIPLE)}

        backend = MisleadingStructuredBackend([])
        with redirect_stdout(io.StringIO()), self.assertRaises(LlmRetryLimitExceededError):
            Classification.askForTechniqueLabel(backend, "prompt", LABELS, maxRetries=2, numLabels=3)
        self.assertEqual(len(backend.schemas), 2)

    def test_multi_majority_counts_all_labels_and_breaks_ties_alphabetically(self):
        backend = TextBackend([
            "ClassRename, FieldRename, Goto",
            "ClassRename, FieldRename, Reflection",
            "ClassRename, Goto, Reflection",
            "ClassRename, FieldRename, Goto",
            "ClassRename, FieldRename, Reflection",
        ])
        result = Classification.analyzeSmaliClassWithMajorityVote(
            backend, SMALI_CLASS, PROMPT_TEMPLATE, LABELS, numIterations=5, numLabels=3,
        )
        self.assertEqual(result["majorityLabels"], TRIPLE)
        self.assertEqual(result["labelCounts"], {
            "ClassRename": 5, "FieldRename": 4, "Goto": 3, "Reflection": 3,
        })
        self.assertEqual(len(result["iterations"]), 5)
        self.assertEqual(len(backend.prompts), 5)
        self.assertTrue(all(len(iteration["labels"]) == 3 for iteration in result["iterations"]))
        self.assertIn(SMALI_CLASS["classContent"], result["prompt"])

    def test_structured_multi_majority_keeps_three_labels(self):
        backend = StructuredBackend([
            {"labels": TRIPLE},
            {"labels": ["ClassRename", "Reflection", "Goto"]},
            {"labels": TRIPLE},
        ])
        result = Classification.analyzeSmaliClassWithMajorityVote(
            backend, SMALI_CLASS, PROMPT_TEMPLATE, LABELS, numIterations=3, numLabels=3,
        )
        self.assertEqual(result["majorityLabels"], ["ClassRename", "Goto", "FieldRename"])
        self.assertEqual(sum(result["labelCounts"].values()), 9)

    def test_single_label_default_still_returns_legacy_keys(self):
        backend = TextBackend(["Reflection", "ClassRename", "Reflection"])
        result = Classification.analyzeSmaliClassWithMajorityVote(
            backend, SMALI_CLASS, PROMPT_TEMPLATE, LABELS, numIterations=3,
        )
        self.assertEqual(result["majorityLabel"], "Reflection")
        self.assertEqual([iteration["label"] for iteration in result["iterations"]],
                         ["Reflection", "ClassRename", "Reflection"])
        self.assertEqual(result["labelCounts"], {"Reflection": 2, "ClassRename": 1})


class AggregationAndPersistenceTests(unittest.TestCase):
    def test_binary_detection_preserves_boolean_score_and_legacy_csv_fields(self):
        classification_fields = {"llmFinalLabels", "numLabelsPerClass", "rankedLabels", "labelFrequency"}
        for prediction, score in [(True, 0.875), (False, 0.0)]:
            with self.subTest(prediction=prediction):
                result = AnalysisUtils.createResultsObject(
                    sha256="f" * 64, pkgName="example.binary", status="SUCCESS",
                    numSmaliClasses=8, numSmaliClassesAnalyzed=8,
                    llmFinalLabel=prediction, pctSmaliClassesObfuscated=score,
                )
                self.assertIs(result["llmFinalLabel"], prediction)
                self.assertEqual(result["pctSmaliClassesObfuscated"], round(score, 2))
                self.assertFalse(classification_fields.intersection(result))
                with tempfile.TemporaryDirectory() as directory:
                    json_path = Path(directory) / "binary.json"
                    csv_path = Path(directory) / "binary.csv"
                    AnalysisUtils.saveResults([result], json_path)
                    loaded = AnalysisUtils.loadExistingResults(json_path)[0]
                    self.assertIs(loaded["llmFinalLabel"], prediction)
                    self.assertEqual(loaded, result)
                    AnalysisUtils.saveResultsAsCsv([result], csv_path)
                    with csv_path.open(newline="", encoding="utf-8") as stream:
                        row = next(csv.DictReader(stream))
                self.assertEqual(row["llmFinalLabel"], str(prediction))
                self.assertEqual(float(row["pctSmaliClassesObfuscated"]), round(score, 2))
                self.assertFalse(classification_fields.intersection(row))

    def test_rank_ignores_unobserved_labels_and_is_independent_of_insertion_order(self):
        counts = {"Reflection": 2, "Goto": 0, "FieldRename": 3, "ClassRename": 3}
        expected = ["ClassRename", "FieldRename", "Reflection"]
        self.assertEqual(rankTechniqueLabels(counts), expected)
        self.assertEqual(rankTechniqueLabels(dict(reversed(list(counts.items())))), expected)
        self.assertEqual(rankTechniqueLabels({"Goto": 0}), [])

    def test_multi_result_survives_json_and_csv_roundtrip(self):
        counts = {"ClassRename": 3, "FieldRename": 2, "Goto": 3, "Reflection": 1}
        ranked = ["ClassRename", "Goto", "FieldRename", "Reflection"]
        result = AnalysisUtils.createResultsObject(
            sha256="a" * 64, pkgName="example.app", status="SUCCESS",
            obfuscationTechnique="combined", numSmaliClasses=8, numSmaliClassesAnalyzed=3,
            llmFinalLabel=ranked[0], labelFrequency=counts,
            llmFinalLabels=ranked[:3], numLabelsPerClass=3, rankedLabels=ranked,
        )
        self.assertEqual(result["llmFinalLabels"], ranked[:3])
        self.assertEqual(result["rankedLabels"], ranked)
        self.assertEqual(result["numLabelsPerClass"], 3)
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "nested" / "results.json"
            csv_path = Path(directory) / "nested" / "results.csv"
            AnalysisUtils.saveResults([result], json_path)
            self.assertEqual(AnalysisUtils.loadExistingResults(json_path), [result])
            AnalysisUtils.saveResultsAsCsv([result], csv_path)
            with csv_path.open(newline="", encoding="utf-8") as stream:
                row = next(csv.DictReader(stream))
        self.assertEqual(json.loads(row["llmFinalLabels"]), ranked[:3])
        self.assertEqual(json.loads(row["rankedLabels"]), ranked)
        self.assertEqual(json.loads(row["labelFrequency"]), counts)
        self.assertEqual(int(row["numLabelsPerClass"]), 3)

    def test_single_result_keeps_scalar_label_in_json_and_csv(self):
        result = AnalysisUtils.createResultsObject(
            sha256="b" * 64, pkgName="example.single", status="SUCCESS",
            llmFinalLabel="Reorder", labelFrequency={"Reorder": 2},
        )
        self.assertEqual(result["llmFinalLabel"], "Reorder")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "single.csv"
            AnalysisUtils.saveResultsAsCsv([result], path)
            with path.open(newline="", encoding="utf-8") as stream:
                row = next(csv.DictReader(stream))
        self.assertEqual(row["llmFinalLabel"], "Reorder")


if __name__ == "__main__":
    unittest.main()
