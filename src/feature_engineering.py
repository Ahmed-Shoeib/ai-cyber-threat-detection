"""
Builds a per-source-IP feature table from cleaned logs. These numeric
features are what the Isolation Forest model (Phase 11) will actually
learn from — the model never sees raw log rows or the true_label column.
"""

import pandas as pd


FEATURE_COLUMNS = [
    "total_events",
    "failed_login_count",
    "failed_login_ratio",
    "distinct_destination_ports",
    "distinct_usernames_targeted",
    "sqli_pattern_matches",
    "avg_time_between_events_seconds",
]

SQLI_PATTERNS = [
    "union select",
    "' or 1=1",
    "or 1=1--",
    "sleep(",
    "information_schema",
    "' or '1'='1",
    "--",
    "drop table",
]


def _count_sqli_matches(paths: pd.Series) -> int:
    """Counts how many requests from this IP matched a known SQLi pattern."""
    count = 0
    for path in paths:
        path_lower = str(path).lower()
        if any(pattern in path_lower for pattern in SQLI_PATTERNS):
            count += 1
    return count


def _avg_time_gap_seconds(timestamps: pd.Series) -> float:
    """
    Average number of seconds between this IP's consecutive events.
    A single event has no gap to measure, so we return 0.0 for that case.
    """
    if len(timestamps) < 2:
        return 0.0
    sorted_ts = timestamps.sort_values()
    gaps = sorted_ts.diff().dropna().dt.total_seconds()
    return float(gaps.mean())


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregates cleaned logs into one row of numeric features per source_ip.
    Deliberately does NOT use true_label - the model must learn only from
    behavior, the same information available in a real, unlabeled deployment.
    """
    rows = []

    for source_ip, group in df.groupby("source_ip"):
        login_events = group[group["event_type"] == "login"]
        failed_logins = login_events[login_events["login_status"] == "failed"]

        total_events = len(group)
        failed_login_count = len(failed_logins)
        failed_login_ratio = (
            failed_login_count / len(login_events) if len(login_events) > 0 else 0.0
        )
        distinct_ports = group["destination_port"].nunique()
        distinct_usernames = login_events["username"].nunique()

        web_requests = group[group["event_type"] == "http_request"]
        sqli_matches = _count_sqli_matches(web_requests["url_or_path"])

        avg_gap = _avg_time_gap_seconds(group["timestamp"])

        rows.append(
            {
                "source_ip": source_ip,
                "total_events": total_events,
                "failed_login_count": failed_login_count,
                "failed_login_ratio": round(failed_login_ratio, 3),
                "distinct_destination_ports": distinct_ports,
                "distinct_usernames_targeted": distinct_usernames,
                "sqli_pattern_matches": sqli_matches,
                "avg_time_between_events_seconds": round(avg_gap, 2),
            }
        )

    return pd.DataFrame(rows)


if __name__ == "__main__":
    from pathlib import Path
    from src.log_parser import load_and_prepare_logs

    logs = load_and_prepare_logs(Path("data/raw/synthetic_logs.csv"))
    features = build_features(logs)

    print(f"Built features for {len(features)} distinct source IPs\n")
    print(features.to_string(index=False))

    output_path = Path("data/processed/features.csv")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    features.to_csv(output_path, index=False)
    print(f"\nSaved -> {output_path}")