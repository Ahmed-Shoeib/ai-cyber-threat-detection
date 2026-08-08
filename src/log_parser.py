"""
Loads, validates, and cleans the raw security log CSV before any detection
logic runs. This mirrors the "log ingestion" stage of a real SIEM: nothing
gets analyzed until we trust its structure and types.
"""

from pathlib import Path

import pandas as pd

REQUIRED_COLUMNS = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "event_type",
    "username",
    "login_status",
    "http_method",
    "url_or_path",
    "response_status_code",
    "bytes_transferred",
]


class LogValidationError(Exception):
    """Raised when the log file is missing required structure."""


def load_logs(csv_path: Path) -> pd.DataFrame:
    """Reads the raw CSV into a DataFrame."""
    if not csv_path.exists():
        raise FileNotFoundError(f"Log file not found: {csv_path}")
    return pd.read_csv(csv_path)


def validate_columns(df: pd.DataFrame) -> None:
    """
    Confirms every required column exists. We check this BEFORE doing
    anything else, because a missing column would cause confusing errors
    much later (e.g., inside a detection rule) instead of a clear one here.
    """
    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing:
        raise LogValidationError(f"Missing required columns: {missing}")


def clean_logs(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans and standardizes the raw DataFrame:
    - Converts timestamp strings into real datetime objects
    - Fills missing text fields with empty string (blank username on a
      port-scan row is expected behavior, not corrupted data)
    - Fills missing numeric fields with 0
    - Drops rows where timestamp itself failed to parse, since we cannot
      do any time-window analysis on a row with no valid time
    """
    df = df.copy()

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce").astype("datetime64[ns]")

    before_count = len(df)
    df = df.dropna(subset=["timestamp"])
    dropped = before_count - len(df)
    if dropped > 0:
        print(f"Warning: dropped {dropped} row(s) with unparseable timestamps")

    text_columns = [
        "source_ip",
        "destination_ip",
        "protocol",
        "event_type",
        "username",
        "login_status",
        "http_method",
        "url_or_path",
    ]
    for col in text_columns:
        df[col] = df[col].fillna("")

    numeric_columns = [
        "source_port",
        "destination_port",
        "response_status_code",
        "bytes_transferred",
    ]
    for col in numeric_columns:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)

    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


def load_and_prepare_logs(csv_path: Path) -> pd.DataFrame:
    """Main entry point: load, validate, and clean in one call."""
    df = load_logs(csv_path)
    validate_columns(df)
    df = clean_logs(df)
    return df


if __name__ == "__main__":
    raw_path = Path("data/raw/synthetic_logs.csv")
    logs = load_and_prepare_logs(raw_path)

    print(f"Loaded and cleaned {len(logs)} log rows")
    print(f"Columns: {list(logs.columns)}")
    print(f"Timestamp dtype: {logs['timestamp'].dtype}")
    print("\nFirst 3 rows:")
    print(logs.head(3))