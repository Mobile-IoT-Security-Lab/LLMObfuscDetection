import re
import json

def extract_package(filepath):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # Pattern 1: package="com.example.app"
    match = re.search(r'package="([^"]+)"', content)
    if match:
        return match.group(1)

    # Pattern 2: fallback per file parsati (senza virgolette)
    basic_info_idx = content.find("The Basic Information")
    if basic_info_idx != -1:
        snippet = content[basic_info_idx:basic_info_idx + 500]
        match2 = re.search(r'package([a-zA-Z][a-zA-Z0-9._]+)', snippet)
        if match2:
            return match2.group(1)

    return None

def TrueeseeingParse(report_path: str) -> str:
    """
    Parses a Trueseeing JSON report and checks whether 'detect-obfuscator'
    with summary 'Lack Of Obfuscation' is present.

    Args:
        report_path: Path to the Trueseeing .json report file.

    Returns:
        'false' if the signature is found,
        'true' otherwise.
    """
    with open(report_path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)

    def search(obj) -> bool:
        if isinstance(obj, dict):
            if (
                obj.get("sig") == "detect-obfuscator"
                and obj.get("summary") == "Lack Of Obfuscation"
            ):
                return True
            return any(search(v) for v in obj.values())
        if isinstance(obj, list):
            return any(search(item) for item in obj)
        return False

    return "false" if search(data) else "true"


def APKHuntParse(report_path: str) -> str:
    """
    Parses an APKHunt report and checks whether the obfuscation QuickNote is present.

    Args:
        report_path: Path to the APKHunt .txt report file.

    Returns:
        'false' if the QuickNote is found (no obfuscation detected),
        'true' otherwise.
    """
    with open(report_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    pattern = re.compile(
        r"\[!\]\s+QuickNote:.*?"
        r"It is recommended that some basic obfuscation should be implemented "
        r"to the release byte-code",
        re.DOTALL,
    )

    return "false" if pattern.search(content) else "true"


import json


def SEBASTiANParse(report_path: str) -> str:
    """
    Parses a SEBASTiAN JSON report and checks whether 'ObfuscationMissing' is present.

    Args:
        report_path: Path to the SEBASTiAN .json report file.

    Returns:
        'false' if the id 'ObfuscationMissing' is found,
        'true' otherwise.
    """
    with open(report_path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)

    def search(obj) -> bool:
        if isinstance(obj, dict):
            if obj.get("id") == "ObfuscationMissing":
                return True
            return any(search(v) for v in obj.values())
        if isinstance(obj, list):
            return any(search(item) for item in obj)
        return False

    return "false" if search(data) else "true"
