"""Basic tests for log_parser.py — confirms loading and cleaning behave correctly."""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from src.log_parser import load_and_prepare_logs, validate_columns, LogValidationError
import pandas as pd


def test_load_and_prepare_real_file():
    """The real synthetic dataset should load with a proper datetime column."""
    df = load_and_prepare_logs(Path("data/raw/synthetic_logs.csv"))
    assert len(df) > 0
    assert str(df["timestamp"].dtype) == "datetime64[ns]"
    assert df["timestamp"].is_monotonic_increasing


def test_validate_columns_missing_column_raises():
    """A DataFrame missing a required column should raise our custom error."""
    bad_df = pd.DataFrame({"timestamp": ["2025-01-01"]})
    try:
        validate_columns(bad_df)
        assert False, "Expected LogValidationError but none was raised"
    except LogValidationError:
        pass


if __name__ == "__main__":
    test_load_and_prepare_real_file()
    test_validate_columns_missing_column_raises()
    print("All log_parser tests passed.")