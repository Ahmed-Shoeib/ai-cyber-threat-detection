"""Tests for the Isolation Forest anomaly detector."""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

import pandas as pd
from src.anomaly_detector import train_model, score_features
from src.feature_engineering import FEATURE_COLUMNS


def make_feature_row(source_ip, **overrides):
    row = {
        "source_ip": source_ip,
        "total_events": 3,
        "failed_login_count": 0,
        "failed_login_ratio": 0.0,
        "distinct_destination_ports": 1,
        "distinct_usernames_targeted": 1,
        "sqli_pattern_matches": 0,
        "avg_time_between_events_seconds": 30.0,
    }
    row.update(overrides)
    return row


def test_obvious_outlier_gets_high_anomaly_score():
    """A row with extreme values compared to the rest should score as more anomalous."""
    normal_rows = [make_feature_row(f"1.1.1.{i}") for i in range(20)]
    outlier_row = make_feature_row(
        "9.9.9.9",
        total_events=200,
        failed_login_count=150,
        failed_login_ratio=1.0,
        distinct_destination_ports=50,
        avg_time_between_events_seconds=0.5,
    )
    df = pd.DataFrame(normal_rows + [outlier_row])

    model = train_model(df)
    scored = score_features(model, df)

    outlier_score = scored[scored["source_ip"] == "9.9.9.9"]["anomaly_score_0_100"].iloc[0]
    normal_avg_score = scored[scored["source_ip"] != "9.9.9.9"]["anomaly_score_0_100"].mean()

    assert outlier_score > normal_avg_score


def test_scoring_does_not_modify_feature_columns():
    """Scoring should add new columns but never change the original feature values."""
    rows = [make_feature_row(f"1.1.1.{i}") for i in range(10)]
    df = pd.DataFrame(rows)

    model = train_model(df)
    scored = score_features(model, df)

    for col in FEATURE_COLUMNS:
        assert (scored[col] == df[col]).all()


if __name__ == "__main__":
    test_obvious_outlier_gets_high_anomaly_score()
    test_scoring_does_not_modify_feature_columns()
    print("All anomaly_detector tests passed.")