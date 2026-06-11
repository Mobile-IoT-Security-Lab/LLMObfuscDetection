import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path
import os

BASE_DIR = Path("/Users/lucaferrari/Desktop/work/LLMObfuscDataSet/docker-tools/results")
INPUT_CSV = BASE_DIR / "metrics.csv"
OUTPUT_DIR = BASE_DIR / "graphs"

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

df = pd.read_csv(INPUT_CSV)
tools = df["Tool"].tolist()

# Define the methods
methods = [
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
    "R8",
    "NoObfusc",
]

# 1. Generate Overall Total Graph
overall_metrics = [
    "overallPrecision",
    "overallRecall",
    "overallF1",
    "overallAccuracy",
    "overallFPR",
]

x = np.arange(len(overall_metrics))
width = 0.25

fig, ax = plt.subplots(figsize=(10, 6))

for i, tool in enumerate(tools):
    values = []
    for metric in overall_metrics:
        val = df.loc[df["Tool"] == tool, metric].values[0]
        # In case there are missing/NaN values
        values.append(float(val) if not pd.isna(val) else 0.0)

    # Calculate offset for grouped bars
    offset = (i - len(tools) / 2 + 0.5) * width
    ax.bar(x + offset, values, width, label=tool)

ax.set_ylabel("Scores")
ax.set_title("Overall Performance Metrics by Tool")
ax.set_xticks(x)
ax.set_xticklabels(overall_metrics)
ax.legend()
ax.set_ylim(0, 1.1)

plt.tight_layout()
total_path = OUTPUT_DIR / "overall_metrics.png"
plt.savefig(total_path)
plt.close()
print(f"Generated {total_path}")

# 2. Generate per-method graphs
for method in methods:
    # Check if the method exists in the dataframe
    if f"Precision_{method}" in df.columns:
        metrics = ["Precision", "Recall", "F1", "Accuracy", "FPR"]
        x_m = np.arange(len(metrics))
        fig, ax = plt.subplots(figsize=(10, 6))

        for i, tool in enumerate(tools):
            values = []
            for metric in metrics:
                col_name = f"{metric}_{method}"
                if col_name in df.columns:
                    val = df.loc[df["Tool"] == tool, col_name].values[0]
                    values.append(float(val) if not pd.isna(val) else 0.0)
                else:
                    values.append(0.0)

            offset = (i - len(tools) / 2 + 0.5) * width
            ax.bar(x_m + offset, values, width, label=tool)

        ax.set_ylabel("Scores")
        ax.set_title(f"Performance Metrics for {method}")
        ax.set_xticks(x_m)
        ax.set_xticklabels(metrics)
        ax.legend()
        ax.set_ylim(0, 1.1)

        plt.tight_layout()
        method_path = OUTPUT_DIR / f"metrics_{method}.png"
        plt.savefig(method_path)
        plt.close()
        print(f"Generated {method_path}")

print("All graphs generated successfully.")
