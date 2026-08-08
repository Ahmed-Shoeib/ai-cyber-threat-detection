"""Tests for risk scoring — confirms the formula behaves predictably
across low, medium, high, and critical cases."""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from src.risk_scoring import calculate_risk_score, score_to_severity


def test_minimal_brute_force_is_medium():
    """Exactly at threshold (5 attempts), no multi-rule bonus -> Medium."""
    detection = {"detection_type": "brute_force", "source_ip": "1.1.1.1", "event_count": 5}
    score = calculate_risk_score(detection, [detection])
    assert score_to_severity(score) == "Medium"


def test_large_brute_force_is_high_or_critical():
    """Large burst well above threshold -> High or Critical."""
    detection = {"detection_type": "brute_force", "source_ip": "2.2.2.2", "event_count": 25}
    score = calculate_risk_score(detection, [detection])
    assert score_to_severity(score) in ("High", "Critical")


def test_multi_rule_bonus_increases_score():
    """Same detection, but source IP also triggered a second rule type -> higher score."""
    base_detection = {"detection_type": "port_scan", "source_ip": "3.3.3.3", "distinct_ports_touched": 10}
    other_detection = {"detection_type": "brute_force", "source_ip": "3.3.3.3", "event_count": 5}

    score_alone = calculate_risk_score(base_detection, [base_detection])
    score_with_multi_rule = calculate_risk_score(base_detection, [base_detection, other_detection])

    assert score_with_multi_rule > score_alone


def test_severity_bucket_boundaries():
    assert score_to_severity(0) == "Low"
    assert score_to_severity(39) == "Low"
    assert score_to_severity(40) == "Medium"
    assert score_to_severity(64) == "Medium"
    assert score_to_severity(65) == "High"
    assert score_to_severity(84) == "High"
    assert score_to_severity(85) == "Critical"
    assert score_to_severity(100) == "Critical"


if __name__ == "__main__":
    test_minimal_brute_force_is_medium()
    test_large_brute_force_is_high_or_critical()
    test_multi_rule_bonus_increases_score()
    test_severity_bucket_boundaries()
    print("All risk_scoring tests passed.")