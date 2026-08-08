"""
Rule-based detection logic. Each function takes the cleaned log DataFrame
and returns a list of detections — dictionaries describing exactly what
suspicious pattern was found and why. Detections are not full alerts yet
(no severity/MITRE mapping) — that enrichment happens in alert_manager.py.
"""

from datetime import timedelta

import pandas as pd

# --- Brute-force detection settings ---
BRUTE_FORCE_FAILED_ATTEMPT_THRESHOLD = 5
BRUTE_FORCE_TIME_WINDOW_SECONDS = 60


def detect_brute_force(df: pd.DataFrame) -> list[dict]:
    """
    Flags (source_ip, username) pairs with 5+ failed logins within any
    60-second window.

    Approach:
    1. Keep only failed login events.
    2. Group by source_ip + username, since brute-forcing targets one
       account at a time in our threat model.
    3. Within each group, sort by time and use a sliding window: for each
       failed attempt, count how many other failed attempts from the same
       group happened within the last 60 seconds. If that count reaches
       the threshold, it's a detection.
    """
    failed_logins = df[
        (df["event_type"] == "login") & (df["login_status"] == "failed")
    ].copy()

    detections = []
    window = timedelta(seconds=BRUTE_FORCE_TIME_WINDOW_SECONDS)

    grouped = failed_logins.groupby(["source_ip", "username"])

    for (source_ip, username), group in grouped:
        group = group.sort_values("timestamp").reset_index(drop=True)
        timestamps = group["timestamp"].tolist()

        already_flagged = False  # avoid duplicate detections for the same burst

        for i in range(len(timestamps)):
            window_start = timestamps[i]
            window_end = window_start + window

            attempts_in_window = [
                t for t in timestamps if window_start <= t <= window_end
            ]

            if len(attempts_in_window) >= BRUTE_FORCE_FAILED_ATTEMPT_THRESHOLD:
                if not already_flagged:
                    detections.append(
                        {
                            "detection_type": "brute_force",
                            "source_ip": source_ip,
                            "username": username,
                            "destination_ip": group["destination_ip"].iloc[0],
                            "event_count": len(attempts_in_window),
                            "window_start": window_start,
                            "window_end": window_end,
                            "detection_reason": (
                                f"{len(attempts_in_window)} failed login attempts "
                                f"from {source_ip} against username '{username}' "
                                f"within {BRUTE_FORCE_TIME_WINDOW_SECONDS} seconds"
                            ),
                        }
                    )
                    already_flagged = True
            else:
                already_flagged = False

    return detections


if __name__ == "__main__":
    from pathlib import Path
    from src.log_parser import load_and_prepare_logs

    logs = load_and_prepare_logs(Path("data/raw/synthetic_logs.csv"))
    results = detect_brute_force(logs)

    print(f"Found {len(results)} brute-force detection(s):\n")
    for d in results:
        print(d)