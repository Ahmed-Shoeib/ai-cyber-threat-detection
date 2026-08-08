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




# --- Port-scan detection settings ---
PORT_SCAN_DISTINCT_PORT_THRESHOLD = 10
PORT_SCAN_TIME_WINDOW_SECONDS = 60


def detect_port_scan(df: pd.DataFrame) -> list[dict]:
    """
    Flags source_ips that connect to 10+ DISTINCT destination ports within
    any 60-second window, against the same destination IP.

    Approach:
    1. Keep only connection-type events (any event with a destination_port).
    2. Group by source_ip + destination_ip, since a scan targets one host.
    3. Sort by time, and for each event, look at the sliding window of
       events within the next 60 seconds and count DISTINCT ports touched
       (not total events — repeated hits on the same port don't count).
    4. If distinct port count reaches the threshold, it's a detection.
    """
    connections = df[df["destination_port"] > 0].copy()

    detections = []
    window = timedelta(seconds=PORT_SCAN_TIME_WINDOW_SECONDS)

    grouped = connections.groupby(["source_ip", "destination_ip"])

    for (source_ip, destination_ip), group in grouped:
        group = group.sort_values("timestamp").reset_index(drop=True)

        already_flagged = False

        for i in range(len(group)):
            window_start = group["timestamp"].iloc[i]
            window_end = window_start + window

            in_window = group[
                (group["timestamp"] >= window_start)
                & (group["timestamp"] <= window_end)
            ]
            distinct_ports = in_window["destination_port"].nunique()

            if distinct_ports >= PORT_SCAN_DISTINCT_PORT_THRESHOLD:
                if not already_flagged:
                    detections.append(
                        {
                            "detection_type": "port_scan",
                            "source_ip": source_ip,
                            "destination_ip": destination_ip,
                            "username": "",
                            "distinct_ports_touched": distinct_ports,
                            "ports_sample": sorted(
                                in_window["destination_port"].unique().tolist()
                            )[:15],
                            "window_start": window_start,
                            "window_end": window_end,
                            "detection_reason": (
                                f"{source_ip} connected to {distinct_ports} distinct "
                                f"ports on {destination_ip} within "
                                f"{PORT_SCAN_TIME_WINDOW_SECONDS} seconds"
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

    bf_results = detect_brute_force(logs)
    print(f"Found {len(bf_results)} brute-force detection(s):\n")
    for d in bf_results:
        print(d)

    print()

    ps_results = detect_port_scan(logs)
    print(f"Found {len(ps_results)} port-scan detection(s):\n")
    for d in ps_results:
        print(d)