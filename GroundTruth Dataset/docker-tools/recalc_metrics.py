import csv
from pathlib import Path

def ratio(num, den):
    if den == 0:
        return 0.0
    return num / den

def format_metric(val):
    return f"{val:.6f}"

def calc_metrics(tp, tn, fp, fn):
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = ratio(2 * precision * recall, precision + recall)
    accuracy = ratio(tp + tn, tp + tn + fp + fn)
    fpr = ratio(fp, fp + tn)
    return precision, recall, f1, accuracy, fpr

BASE_DIR = Path(__file__).resolve().parent
METRICS_CSV = BASE_DIR / "results" / "metrics.csv"

def main():
    with METRICS_CSV.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = list(reader.fieldnames)

    # find methods by looking for TP_<method> where method != "total"
    methods = []
    for f in fieldnames:
        if f.startswith("TP_") and f != "TP_total":
            methods.append(f[3:])

    # Make sure new fields are in fieldnames
    for m in methods:
        for metric in ["Precision", "Recall", "F1", "Accuracy", "FPR"]:
            col = f"{metric}_{m}"
            if col not in fieldnames:
                fieldnames.append(col)

    for row in rows:
        # overall
        def safe_int(val):
            try:
                if not val: return 0
                return int(val)
            except ValueError:
                return 0

        tp = safe_int(row.get("TP_total", 0))
        tn = safe_int(row.get("TN_total", 0))
        fp = safe_int(row.get("FP_total", 0))
        fn = safe_int(row.get("FN_total", 0))
        
        p, r, f1, a, fpr = calc_metrics(tp, tn, fp, fn)
        row["overallPrecision"] = format_metric(p)
        row["overallRecall"] = format_metric(r)
        row["overallF1"] = format_metric(f1)
        row["overallAccuracy"] = format_metric(a)
        row["overallFPR"] = format_metric(fpr)

        # per method
        for m in methods:
            tp_m = safe_int(row.get(f"TP_{m}", 0))
            tn_m = safe_int(row.get(f"TN_{m}", 0))
            fp_m = safe_int(row.get(f"FP_{m}", 0))
            fn_m = safe_int(row.get(f"FN_{m}", 0))
            
            p, r, f1, a, fpr = calc_metrics(tp_m, tn_m, fp_m, fn_m)
            row[f"Precision_{m}"] = format_metric(p)
            row[f"Recall_{m}"] = format_metric(r)
            row[f"F1_{m}"] = format_metric(f1)
            row[f"Accuracy_{m}"] = format_metric(a)
            row[f"FPR_{m}"] = format_metric(fpr)

    # order fieldnames correctly for readability? Just append the new ones.
    with METRICS_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    
    print("Metrics recalculated successfully.")

if __name__ == "__main__":
    main()
