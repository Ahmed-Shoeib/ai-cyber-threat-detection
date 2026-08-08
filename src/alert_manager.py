"""
Converts raw rule detections into standardized, analyst-ready alerts, and
exports them to JSON/CSV for the dashboard to consume.

An alert is the packaged, human-readable output of a detection: it adds
severity, MITRE context, and a recommended response on top of the raw
evidence our detection rules already found.
"""

import json
import uuid
from pathlib import Path

import pandas as pd

from src.detection_rules import detect_brute_force, detect_port_scan, detect_sql_injection
from src.mitre_mapping import get_mitre_info
from src.risk_scoring import calculate_risk_score, score_to_severity
from src.feature_engineering import build_features
from src.anomaly_detector import train_model, score_features


THREAT_NAMES = {
    "brute_force": "Brute Force Login Attempt",
    "port_scan": "Port Scanning Activity",
    "sql_injection": "Suspicious SQL Injection Pattern",
}


def _build_description(detection: dict) -> str:
    """Creates a short, human-readable summary for the alert."""
    dtype = detection["detection_type"]
    if dtype == "brute_force":
        return (
            f"{detection['event_count']} failed login attempts from "
            f"{detection['source_ip']} against username '{detection['username']}'."
        )
    if dtype == "port_scan":
        return (
            f"{detection['source_ip']} touched {detection['distinct_ports_touched']} "
            f"distinct ports on {detection['destination_ip']} in a short window."
        )
    if dtype == "sql_injection":
        return (
            f"Request from {detection['source_ip']} to '{detection['url_or_path']}' "
            f"matched known SQL injection patterns."
        )
    return "Suspicious activity detected."


def build_alert(detection: dict, all_detections: list[dict]) -> dict:
    """Converts one raw detection dictionary into a standardized alert."""
    dtype = detection["detection_type"]
    mitre = get_mitre_info(dtype)

    timestamp = detection.get("timestamp") or detection.get("window_start")

    risk_score = calculate_risk_score(detection, all_detections)
    severity = score_to_severity(risk_score)

    return {
        "alert_id": str(uuid.uuid4())[:8],
        "timestamp": str(timestamp),
        "source_ip": detection.get("source_ip", ""),
        "destination_ip": detection.get("destination_ip", ""),
        "threat_name": THREAT_NAMES.get(dtype, "Unknown Threat"),
        "detection_type": dtype,
        "description": _build_description(detection),
        "detection_reason": detection.get("detection_reason", ""),
        "risk_score": risk_score,
        "severity": severity,
        "confidence_or_anomaly_score": None,
        "mitre_tactic": mitre["tactic"],
        "mitre_technique_id": mitre["technique_id"],
        "mitre_technique_name": mitre["technique_name"],
        "recommended_response": mitre["recommended_response"],
        "detection_method": "rule-based",
    }


def _build_anomaly_lookup(df: pd.DataFrame) -> dict:
    """
    Builds a source_ip -> anomaly_score_0_100 lookup so we can attach ML
    context to rule-based alerts without letting ML override them.
    """
    features = build_features(df)
    model = train_model(features)
    scored = score_features(model, features)

    return dict(zip(scored["source_ip"], scored["anomaly_score_0_100"]))


def generate_all_alerts(df: pd.DataFrame) -> list[dict]:
    """Runs all three detection rules, attaches ML anomaly context, and
    converts every result into a standardized alert.
    """
    all_detections = []
    all_detections += detect_brute_force(df)
    all_detections += detect_port_scan(df)
    all_detections += detect_sql_injection(df)

    anomaly_lookup = _build_anomaly_lookup(df)

    alerts = []

    for detection in all_detections:
        alert = build_alert(detection, all_detections)

        source_ip = detection.get("source_ip")
        anomaly_score = anomaly_lookup.get(source_ip)

        if anomaly_score is not None:
            alert["confidence_or_anomaly_score"] = anomaly_score

            if anomaly_score >= 70:
                alert["detection_method"] = "rule-based + ML-confirmed"

        alerts.append(alert)

    return alerts


def save_alerts(alerts: list[dict], output_path: Path) -> None:
    """Saves alerts to JSON (dashboard-friendly) and a matching CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2, default=str)

    csv_path = output_path.with_suffix(".csv")
    pd.DataFrame(alerts).to_csv(csv_path, index=False)

    print(f"Saved {len(alerts)} alerts -> {output_path} and {csv_path}")


if __name__ == "__main__":
    from src.log_parser import load_and_prepare_logs

    logs = load_and_prepare_logs(Path("data/raw/synthetic_logs.csv"))
    alerts = generate_all_alerts(logs)

    print(f"Generated {len(alerts)} total alerts:\n")

    for a in alerts:
        print(
            f"[{a['severity']} | score {a['risk_score']}] "
            f"{a['threat_name']} - {a['source_ip']} "
            f"({a['mitre_technique_id']}: {a['mitre_technique_name']})"
        )

    save_alerts(alerts, Path("data/processed/alerts.json"))