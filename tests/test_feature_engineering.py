"""Tests for feature engineering — confirms features reflect known behavior
patterns and that true_label never leaks into the feature table."""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

import pandas as pd
from src.feature_engineering import build_features, FEATURE_COLUMNS


def make_row(timestamp, source_ip, event_type, login_status="", username="",
             destination_port=443, url_or_path=""):
    return {
        "timestamp": pd.Timestamp(timestamp),
        "source_ip": source_ip,
        "destination_ip": "10.0.0.5",
        "source_port": 5000,
        "destination_port": destination_port,
        "protocol": "TCP",
        "event_type": event_type,
        "username": username,
        "login_status": login_status,
        "http_method": "GET" if event_type == "http_request" else "",
        "url_or_path": url_or_path,
        "response_status_code": 200,
        "bytes_transferred": 100,
    }


def test_brute_force_ip_has_high_failed_ratio():
    rows = [
        make_row(f"2025-01-01T09:00:{i:02d}", "1.1.1.1", "login", "failed", "admin")
        for i in range(6)
    ]
    df = pd.DataFrame(rows)
    features = build_features(df)
    ip_row = features[features["source_ip"] == "1.1.1.1"].iloc[0]
    assert ip_row["failed_login_ratio"] == 1.0
    assert ip_row["failed_login_count"] == 6


def test_port_scan_ip_has_many_distinct_ports():
    rows = [
        make_row(f"2025-01-01T09:00:{i:02d}", "2.2.2.2", "connection", destination_port=20 + i)
        for i in range(10)
    ]
    df = pd.DataFrame(rows)
    features = build_features(df)
    ip_row = features[features["source_ip"] == "2.2.2.2"].iloc[0]
    assert ip_row["distinct_destination_ports"] == 10


def test_no_true_label_column_present():
    """Feature table must never contain true_label - would be data leakage."""
    rows = [make_row("2025-01-01T09:00:00", "3.3.3.3", "login", "success", "bob")]
    df = pd.DataFrame(rows)
    df["true_label"] = "normal"  # simulate the real dataset having this column
    features = build_features(df)
    assert "true_label" not in features.columns
    assert list(features.columns[1:]) == FEATURE_COLUMNS  # only intended features


if __name__ == "__main__":
    test_brute_force_ip_has_high_failed_ratio()
    test_port_scan_ip_has_many_distinct_ports()
    test_no_true_label_column_present()
    print("All feature_engineering tests passed.")