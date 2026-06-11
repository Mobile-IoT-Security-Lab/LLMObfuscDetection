import hashlib
import csv
import os
from ToolParser import SEBASTiANParse, APKHuntParse, TrueeseeingParse, extract_package
import sys


def calc_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def add_to_csv(
    file_path: str,
    csv_path: str,
    pkg_name: str,
    obfuscation_technique: str,
    sebastian_result: str,
    apkhunt_result: str,
    trueesing_result: str,
):
    sha256 = calc_sha256(file_path)

    row = {
        "sha256": sha256,
        "pkg_name": pkg_name,
        "obfuscation_technique": obfuscation_technique,
        "SEBASTiAN_result": sebastian_result,
        "APKHunt_result": apkhunt_result,
        "Trueesing_result": trueesing_result,
    }

    fieldnames = list(row.keys())
    file_exists = os.path.isfile(csv_path)

    # FIX: assicura che il file termini con \n prima di appendere
    if file_exists:
        with open(csv_path, "rb+") as f:
            f.seek(0, 2)  # vai alla fine
            if f.tell() > 0:
                f.seek(-1, 2)
                last_char = f.read(1)
                if last_char != b"\n":
                    f.write(b"\n")

    with open(csv_path, mode="a", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


add_to_csv(
    file_path="/apks/" + sys.argv[1] + ".apk",
    csv_path="/results/results.csv",
    pkg_name=extract_package("/results/APKHunt/" + sys.argv[1] + ".txt"),
    obfuscation_technique="",
    sebastian_result=SEBASTiANParse("/results/SEBASTiAN/" + sys.argv[1] + ".json"),
    apkhunt_result=APKHuntParse("/results/APKHunt/" + sys.argv[1] + ".txt"),
    trueesing_result=TrueeseeingParse("/results/Trueseeing/" + sys.argv[1] + ".json"),
)
