"""
Computes an explainable 0-100 risk score for each alert and maps it to a
severity label. Every component of the score is tied to a concrete,
describable factor - no unexplainable "magic" weights.
"""

BASE_POINTS = {
    "brute_force": 40,
    "port_scan": 25,
    "sql_injection": 45,
}

# Matches the thresholds used in detection_rules.py
BRUTE_FORCE_THRESHOLD = 5
PORT_SCAN_THRESHOLD = 10

MULTI_RULE_BONUS = 15


def _volume_bonus(detection: dict) -> int:
    """
    Extra points for how far the detection exceeded its trigger threshold.
    Capped so one extreme outlier doesn't dominate the whole score.
    """
    dtype = detection["detection_type"]

    if dtype == "brute_force":
        excess = max(0, detection.get("event_count", 0) - BRUTE_FORCE_THRESHOLD)
        return min(excess * 2, 30)

    if dtype == "port_scan":
        excess = max(0, detection.get("distinct_ports_touched", 0) - PORT_SCAN_THRESHOLD)
        return min(excess * 2, 30)

    if dtype == "sql_injection":
        matched = len(detection.get("matched_patterns", []))
        extra_patterns = max(0, matched - 1)
        return min(extra_patterns * 10, 20)

    return 0


def _multi_rule_bonus(detection: dict, all_detections: list[dict]) -> int:
    """
    Adds bonus points if this detection's source_ip also triggered a
    DIFFERENT threat type anywhere in the dataset - a strong signal of a
    deliberate, persistent attacker rather than an isolated false positive.
    """
    source_ip = detection.get("source_ip")
    this_type = detection.get("detection_type")

    other_types_from_same_ip = {
        d["detection_type"]
        for d in all_detections
        if d.get("source_ip") == source_ip and d.get("detection_type") != this_type
    }

    return MULTI_RULE_BONUS if other_types_from_same_ip else 0


def calculate_risk_score(detection: dict, all_detections: list[dict]) -> int:
    """
    Full risk score for one detection: base + volume bonus + multi-rule
    bonus, capped at 100.
    """
    base = BASE_POINTS.get(detection["detection_type"], 10)
    volume = _volume_bonus(detection)
    multi_rule = _multi_rule_bonus(detection, all_detections)

    total = base + volume + multi_rule
    return min(total, 100)


def score_to_severity(score: int) -> str:
    """Maps a 0-100 risk score to a severity label."""
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"