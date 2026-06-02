import os
import json
from datetime import datetime
from rules import DLP_RULES

SCAN_DIR = "sample_files"
ALERT_FILE = "alerts/dlp_alerts.json"

ALLOWLIST = [
    "test_numbers.txt"
]

def classify_file(matches):
    high_count = sum(1 for m in matches if m["severity"] == "high")
    medium_count = sum(1 for m in matches if m["severity"] == "medium")

    if high_count >= 1:
        return "high"
    elif medium_count >= 2:
        return "medium"
    elif medium_count == 1:
        return "low"
    return "none"

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
                "match_count": len(matches),
                "severity": rule["severity"]
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
