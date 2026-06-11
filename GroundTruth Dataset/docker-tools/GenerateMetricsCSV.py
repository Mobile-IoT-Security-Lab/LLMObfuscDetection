import csv
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
INPUT_CSV = BASE_DIR / "results/results.csv"
OUTPUT_CSV = BASE_DIR / "results/metrics.csv"

TOOLS = {
    "SEBASTiAN": "SEBASTiAN_result",
    "APKHunt": "APKHunt_result",
    "Trueseeing": "Trueseeing_result",
}

OBFUSCATION_METHODS = [
    "ArithmeticBranch",
    "CallIndirection",
    "ClassRename",
    "ConstStringEncryption",
    "FieldRename",
    "Goto",
    "MethodOverload",
    "MethodRename",
    "Reflection",
    "ResStringEncryption",
]


def is_true(value: str) -> bool:
    return value.strip().lower() == "true"


def ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def format_metric(value: float) -> str:
    return f"{value:.6f}"


def main() -> None:
    with INPUT_CSV.open(newline="", encoding="utf-8") as csvfile:
        rows = list(csv.DictReader(csvfile))

    output_rows = []

    for tool_name, result_column in TOOLS.items():
        tp = tn = fp = fn = 0

        for row in rows:
            actual_positive = row["Obfuscation_method"] != "None"
            predicted_positive = is_true(row.get(result_column, ""))

            if actual_positive and predicted_positive:
                tp += 1
            elif actual_positive and not predicted_positive:
                fn += 1
            elif not actual_positive and predicted_positive:
                fp += 1
            else:
                tn += 1

        precision = ratio(tp, tp + fp)
        recall = ratio(tp, tp + fn)
        f1 = ratio(2 * precision * recall, precision + recall)
        accuracy = ratio(tp + tn, tp + tn + fp + fn)
        fpr = ratio(fp, fp + tn)

        output_row = {
            "Tool": tool_name,
            "overallPrecision": format_metric(precision),
            "overallRecall": format_metric(recall),
            "overallF1": format_metric(f1),
            "overallAccuracy": format_metric(accuracy),
            "overallFPR": format_metric(fpr),
            "TP": tp,
            "TN": tn,
            "FP": fp,
            "FN": fn,
        }

        for method in OBFUSCATION_METHODS:
            method_rows = [row for row in rows if row["Obfuscation_method"] == method]
            method_tp = sum(1 for row in method_rows if is_true(row.get(result_column, "")))
            method_fn = len(method_rows) - method_tp
            method_recall = ratio(method_tp, len(method_rows))

            output_row[f"TP_{method}"] = method_tp
            output_row[f"FN_{method}"] = method_fn
            output_row[f"FP_{method}"] = fp
            output_row[f"TN_{method}"] = tn
            output_row[f"Recall_{method}"] = format_metric(method_recall)
            output_row[f"FPR_{method}"] = format_metric(fpr)

        output_rows.append(output_row)

    fieldnames = [
        "Tool",
        "overallPrecision",
        "overallRecall",
        "overallF1",
        "overallAccuracy",
        "overallFPR",
        "TP",
        "TN",
        "FP",
        "FN",
    ]

    for method in OBFUSCATION_METHODS:
        fieldnames.extend([f"TP_{method}", f"FN_{method}", f"FP_{method}", f"TN_{method}", f"Recall_{method}", f"FPR_{method}"])

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output_rows)


if __name__ == "__main__":
    main()
