import os
import json
import subprocess
from datetime import datetime, UTC
from rules import DLP_RULES

SCAN_DIR = "sample_files"
ALERT_FILE = "alerts/dlp_alerts.json"

ALLOWLIST = [
    "test_numbers.txt"
]

def classify_file(matches):
    highest_rank = 0
    classification = "none"

    severity_rank = {
        "low": 1,
        "medium": 2,
        "high": 3
    }

    for match in matches:
        severity = str(match.get("severity", "")).strip().lower()

        if severity in severity_rank and severity_rank[severity] > highest_rank:
            highest_rank = severity_rank[severity]
            classification = severity

    return classification

def apply_classification_tag(file_path, classification):
    result = subprocess.run(
        [
            "setfattr",
            "-n",
            "user.classification",
            "-v",
            classification,
            file_path
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"Failed to classify {file_path}: {result.stderr.strip()}")

def scan_file(file_path):
    alerts = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        content = file.read()

    for rule_name, rule in DLP_RULES.items():
        matches = rule["pattern"].findall(content)

        if matches:
            severity = str(rule["severity"]).strip().lower()

            alerts.append({
                "file_path": file_path,
                "match_type": rule_name,
                "match_count": len(matches),
                "severity": severity
            })

    return alerts

def main():
    all_alerts = []

    for filename in os.listdir(SCAN_DIR):
        if filename in ALLOWLIST:
            continue

        file_path = os.path.join(SCAN_DIR, filename)

        if os.path.isfile(file_path):
            file_alerts = scan_file(file_path)
            classification = classify_file(file_alerts)

            if classification != "none":
                apply_classification_tag(file_path, classification)

            for alert in file_alerts:
                alert["classification"] = classification
                alert["timestamp"] = datetime.now(UTC).isoformat()

            all_alerts.extend(file_alerts)

    os.makedirs("alerts", exist_ok=True)

    with open(ALERT_FILE, "w") as output:
        json.dump(all_alerts, output, indent=4)

    print(f"Scan complete. {len(all_alerts)} alerts written to {ALERT_FILE}")

if __name__ == "__main__":
    main()
