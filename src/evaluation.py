"""
Evaluates rule-based and ML-based detection separately against the
true_label column. true_label is used HERE ONLY - never during training
or rule design - since real production logs would never have it.
"""

from pathlib import Path

import pandas as pd


def _ip_is_true_attacker(df: pd.DataFrame, source_ip: str) -> bool:
    """
    An IP counts as a true attacker if ANY of its log rows carry a
    true_label other than 'normal'.
    """
    ip_rows = df[df["source_ip"] == source_ip]
    return (ip_rows["true_label"] != "normal").any()


def compute_confusion_counts(flagged_ips: set, all_ips: set, df: pd.DataFrame) -> dict:
    """
    Computes TP, FP, FN, TN at the source_ip level by comparing a set of
    flagged IPs against the ground-truth true_label column.
    """
    tp = fp = fn = tn = 0

    for ip in all_ips:
        actually_attacker = _ip_is_true_attacker(df, ip)
        was_flagged = ip in flagged_ips

        if was_flagged and actually_attacker:
            tp += 1
        elif was_flagged and not actually_attacker:
            fp += 1
        elif not was_flagged and actually_attacker:
            fn += 1
        else:
            tn += 1

    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn}


def compute_metrics(counts: dict) -> dict:
    """Computes precision, recall, and F1 from confusion counts, guarding
    against division by zero when a component has no positive predictions."""
    tp, fp, fn = counts["TP"], counts["FP"], counts["FN"]

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    return {
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1, 3),
    }


def evaluate_rule_based(df: pd.DataFrame, alerts: list[dict]) -> dict:
    """Evaluates: did ANY rule fire for this IP, vs. was it a true attacker?"""
    all_ips = set(df["source_ip"].unique())
    flagged_ips = {a["source_ip"] for a in alerts}

    counts = compute_confusion_counts(flagged_ips, all_ips, df)
    metrics = compute_metrics(counts)
    return {**counts, **metrics}


def evaluate_ml_based(df: pd.DataFrame, scored_features: pd.DataFrame) -> dict:
    """Evaluates: did Isolation Forest flag this IP as anomalous, vs. was it a true attacker?"""
    all_ips = set(df["source_ip"].unique())
    flagged_ips = set(scored_features[scored_features["is_anomaly"]]["source_ip"])

    counts = compute_confusion_counts(flagged_ips, all_ips, df)
    metrics = compute_metrics(counts)
    return {**counts, **metrics}


if __name__ == "__main__":
    from src.log_parser import load_and_prepare_logs
    from src.alert_manager import generate_all_alerts
    from src.feature_engineering import build_features
    from src.anomaly_detector import train_model, score_features

    logs = load_and_prepare_logs(Path("data/raw/synthetic_logs.csv"))

    # Rule-based evaluation
    alerts = generate_all_alerts(logs)
    rule_results = evaluate_rule_based(logs, alerts)

    # ML-based evaluation
    features = build_features(logs)
    model = train_model(features)
    scored = score_features(model, features)
    ml_results = evaluate_ml_based(logs, scored)

    print("=== Rule-Based Detection Evaluation (per source IP) ===")
    for k, v in rule_results.items():
        print(f"  {k}: {v}")

    print("\n=== ML (Isolation Forest) Detection Evaluation (per source IP) ===")
    for k, v in ml_results.items():
        print(f"  {k}: {v}")

    print(
        "\nNote: evaluated on a small synthetic dataset with very few true "
        "attacker IPs - these numbers demonstrate the METHOD works, not "
        "production-grade performance. See docs for full discussion."
    )