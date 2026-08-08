"""
Smoke test for the dashboard's data layer. We don't test Streamlit's UI
directly (better suited to manual verification) but we do confirm the
underlying alerts file is well-formed enough for the dashboard to consume
without crashing.
"""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

import pandas as pd

ALERTS_PATH = Path("data/processed/alerts.json")

REQUIRED_DASHBOARD_COLUMNS = [
    "alert_id", "timestamp", "source_ip", "threat_name", "severity",
    "risk_score", "confidence_or_anomaly_score", "mitre_technique_id", "detection_method",
]


def test_alerts_file_exists_and_has_required_columns():
    assert ALERTS_PATH.exists(), "Run `python -m src.alert_manager` before testing the dashboard"
    df = pd.read_json(ALERTS_PATH)
    for col in REQUIRED_DASHBOARD_COLUMNS:
        assert col in df.columns, f"Missing column dashboard depends on: {col}"


def test_severity_values_are_valid():
    df = pd.read_json(ALERTS_PATH)
    valid_severities = {"Low", "Medium", "High", "Critical"}
    assert set(df["severity"].unique()).issubset(valid_severities)


if __name__ == "__main__":
    test_alerts_file_exists_and_has_required_columns()
    test_severity_values_are_valid()
    print("All dashboard data tests passed.")