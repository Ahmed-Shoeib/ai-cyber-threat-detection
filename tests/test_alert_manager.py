"""Tests for alert generation — confirms every alert has the required fields."""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from src.alert_manager import build_alert, generate_all_alerts
from src.log_parser import load_and_prepare_logs

REQUIRED_ALERT_FIELDS = [
    "alert_id", "timestamp", "source_ip", "destination_ip", "threat_name",
    "description", "detection_reason", "severity", "mitre_tactic",
    "mitre_technique_id", "mitre_technique_name", "recommended_response",
    "detection_method",
]


def test_build_alert_from_brute_force_detection():
    detection = {
        "detection_type": "brute_force",
        "source_ip": "1.2.3.4",
        "destination_ip": "10.0.0.5",
        "username": "admin",
        "event_count": 10,
        "window_start": "2025-01-01T09:00:00",
        "detection_reason": "test reason",
    }
    alert = build_alert(detection)
    for field in REQUIRED_ALERT_FIELDS:
        assert field in alert, f"Missing field: {field}"
    assert alert["mitre_technique_id"] == "T1110"


def test_generate_all_alerts_on_real_data():
    logs = load_and_prepare_logs(Path("data/raw/synthetic_logs.csv"))
    alerts = generate_all_alerts(logs)
    assert len(alerts) == 6  # 1 brute-force + 1 port-scan + 4 sql-injection
    alert_ids = [a["alert_id"] for a in alerts]
    assert len(alert_ids) == len(set(alert_ids))  # all unique


if __name__ == "__main__":
    test_build_alert_from_brute_force_detection()
    test_generate_all_alerts_on_real_data()
    print("All alert_manager tests passed.")