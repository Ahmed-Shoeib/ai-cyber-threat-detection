"""
Runs the full detection pipeline end-to-end, from raw log generation
through alert export. Run this before starting the Streamlit dashboard.

Usage (from project root, with venv activated):
    python main.py
"""

from pathlib import Path

from src.data_generator import main as generate_synthetic_logs
from src.log_parser import load_and_prepare_logs
from src.alert_manager import generate_all_alerts, save_alerts

RAW_LOGS_PATH = Path("data/raw/synthetic_logs.csv")
ALERTS_OUTPUT_PATH = Path("data/processed/alerts.json")


def run_pipeline() -> None:
    print("Step 1/4: Generating synthetic logs...")
    generate_synthetic_logs()

    print("\nStep 2/4: Loading and validating logs...")
    logs = load_and_prepare_logs(RAW_LOGS_PATH)
    print(f"  Loaded {len(logs)} clean log rows")

    print("\nStep 3/4: Running detection rules, ML scoring, and risk scoring...")
    alerts = generate_all_alerts(logs)
    print(f"  Generated {len(alerts)} alerts")

    print("\nStep 4/4: Saving alerts...")
    save_alerts(alerts, ALERTS_OUTPUT_PATH)

    print("\nPipeline complete. Run the dashboard with:")
    print("    streamlit run dashboard\\app.py")


if __name__ == "__main__":
    run_pipeline()