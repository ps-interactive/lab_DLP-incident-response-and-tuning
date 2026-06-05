import os
import json
import subprocess
from datetime import datetime
from rules import DLP_RULES

SCAN_DIR = "sample_files"
ALERT_FILE = "alerts/dlp_alerts.json"

ALLOWLIST = [
    "test_numbers.txt"
]

def classify_file(matches):
    total_matches = sum(match["match_count"] for match in matches)

    if total_matches >= 5:
        return "high"
    elif total_matches >= 2:
        return "medium"
    elif total_matches == 1:
        return "low"
    return "none"

def apply_classification_tag(file_path, classification):
    try:
        subprocess.run(
            [
                "setfattr",
                "-n",
                "user.classification",
                "-v",
                classification,
                file_path
            ],
            check=True
        )
        print(f"Applied classification '{classification}' to {file_path}")

    except subprocess.CalledProcessError as error:
        print(f"Failed to tag {file_path}: {error}")

def scan_file(file_path):
    alerts = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        content = file.read()

    for rule_name, rule in DLP_RULES.items():
        matches = rule["pattern"].findall(content)

        if matches:
            alerts.append({
                "file_path": file_path,
                "match_type": rule_name,
                "match_count": len(matches)
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
                alert["timestamp"] = datetime.utcnow().isoformat() + "Z"

            all_alerts.extend(file_alerts)

    os.makedirs("alerts", exist_ok=True)

    with open(ALERT_FILE, "w") as output:
        json.dump(all_alerts, output, indent=4)

    print(f"Scan complete. {len(all_alerts)} alerts written to {ALERT_FILE}")

if __name__ == "__main__":
    main()
