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



from src.detection_rules import detect_port_scan


def make_connection_row(timestamp, source_ip, destination_port):
    return {
        "timestamp": pd.Timestamp(timestamp),
        "source_ip": source_ip,
        "destination_ip": "10.0.0.5",
        "source_port": 5000,
        "destination_port": destination_port,
        "protocol": "TCP",
        "event_type": "connection",
        "username": "",
        "login_status": "",
        "http_method": "",
        "url_or_path": "",
        "response_status_code": 0,
        "bytes_transferred": 50,
    }


def test_detects_port_scan_burst():
    """12 distinct ports touched in under a minute should trigger one detection."""
    ports = [20 + i for i in range(12)]
    rows = [
        make_connection_row(f"2025-01-01T10:00:{i:02d}", "5.6.7.8", port)
        for i, port in enumerate(ports)
    ]
    df = pd.DataFrame(rows)
    detections = detect_port_scan(df)
    assert len(detections) == 1
    assert detections[0]["distinct_ports_touched"] >= 10


def test_no_detection_for_repeated_same_port():
    """Many connections to the SAME port should NOT count as a scan."""
    rows = [
        make_connection_row(f"2025-01-01T10:00:{i:02d}", "5.6.7.8", 443)
        for i in range(15)
    ]
    df = pd.DataFrame(rows)
    detections = detect_port_scan(df)
    assert len(detections) == 0


if __name__ == "__main__":
    test_detects_brute_force_burst()
    test_no_detection_for_normal_activity()
    test_detects_port_scan_burst()
    test_no_detection_for_repeated_same_port()
    print("All detection_rules tests passed.")

from src.detection_rules import detect_sql_injection


def make_web_request_row(timestamp, source_ip, url_path):
    return {
        "timestamp": pd.Timestamp(timestamp),
        "source_ip": source_ip,
        "destination_ip": "10.0.0.5",
        "source_port": 5000,
        "destination_port": 443,
        "protocol": "TCP",
        "event_type": "http_request",
        "username": "",
        "login_status": "",
        "http_method": "GET",
        "url_or_path": url_path,
        "response_status_code": 200,
        "bytes_transferred": 500,
    }


def test_detects_sql_injection_pattern():
    """A request containing a known SQLi pattern should be flagged."""
    rows = [
        make_web_request_row("2025-01-01T11:00:00", "9.9.9.9", "/search?q=UNION SELECT * FROM users"),
    ]
    df = pd.DataFrame(rows)
    detections = detect_sql_injection(df)
    assert len(detections) == 1
    assert "union select" in detections[0]["matched_patterns"]


def test_no_detection_for_normal_request():
    """A normal, harmless request should not be flagged."""
    rows = [
        make_web_request_row("2025-01-01T11:00:00", "9.9.9.9", "/products?id=5"),
    ]
    df = pd.DataFrame(rows)
    detections = detect_sql_injection(df)
    assert len(detections) == 0


if __name__ == "__main__":
    test_detects_brute_force_burst()
    test_no_detection_for_normal_activity()
    test_detects_port_scan_burst()
    test_no_detection_for_repeated_same_port()
    test_detects_sql_injection_pattern()
    test_no_detection_for_normal_request()
    print("All detection_rules tests passed.")