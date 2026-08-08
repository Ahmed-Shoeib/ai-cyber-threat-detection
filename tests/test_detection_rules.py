"""Tests for the brute-force detection rule using small, controlled data."""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

import pandas as pd
from src.detection_rules import detect_brute_force


def make_login_row(timestamp, source_ip, username, status):
    return {
        "timestamp": pd.Timestamp(timestamp),
        "source_ip": source_ip,
        "destination_ip": "10.0.0.5",
        "source_port": 5000,
        "destination_port": 443,
        "protocol": "TCP",
        "event_type": "login",
        "username": username,
        "login_status": status,
        "http_method": "POST",
        "url_or_path": "/login",
        "response_status_code": 401 if status == "failed" else 200,
        "bytes_transferred": 200,
    }


def test_detects_brute_force_burst():
    """6 failed attempts in 30 seconds should trigger one detection."""
    rows = [
        make_login_row(f"2025-01-01T09:00:{i:02d}", "1.2.3.4", "admin", "failed")
        for i in range(0, 30, 5)  # 6 attempts, 5 seconds apart = 25s span
    ]
    df = pd.DataFrame(rows)
    detections = detect_brute_force(df)
    assert len(detections) == 1
    assert detections[0]["source_ip"] == "1.2.3.4"
    assert detections[0]["event_count"] >= 5


def test_no_detection_for_normal_activity():
    """A couple of failed logins spread far apart should NOT trigger."""
    rows = [
        make_login_row("2025-01-01T09:00:00", "1.2.3.4", "bob", "failed"),
        make_login_row("2025-01-01T09:10:00", "1.2.3.4", "bob", "failed"),
    ]
    df = pd.DataFrame(rows)
    detections = detect_brute_force(df)
    assert len(detections) == 0


if __name__ == "__main__":
    test_detects_brute_force_burst()
    test_no_detection_for_normal_activity()
    print("All detection_rules tests passed.")