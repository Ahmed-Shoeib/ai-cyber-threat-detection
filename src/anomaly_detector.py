"""
Trains an Isolation Forest on our per-IP feature table to catch unusual
behavior that our three specific rules might miss. The model's output is
treated as a supporting signal, never as automatic proof of an attack -
that judgment call always belongs to a rule (with an explainable reason)
or a human analyst.
"""

import pickle
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest

from src.feature_engineering import FEATURE_COLUMNS

MODEL_PATH = Path("models/isolation_forest.pkl")

# contamination = our rough estimate of what fraction of source IPs are
# likely anomalous. We keep this conservative since most traffic in any
# network - including ours - should be normal.
CONTAMINATION = 0.15
RANDOM_STATE = 42  # reproducible results, same spirit as data_generator.py's seed


def train_model(features_df: pd.DataFrame) -> IsolationForest:
    """
    Trains an Isolation Forest using ONLY the numeric behavioral features -
    never source_ip (an identifier) and never true_label (would be leakage).
    """
    X = features_df[FEATURE_COLUMNS]

    model = IsolationForest(
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
        n_estimators=100,
    )
    model.fit(X)
    return model


def score_features(model: IsolationForest, features_df: pd.DataFrame) -> pd.DataFrame:
    """
    Adds two columns to the feature table:
    - raw_anomaly_score: scikit-learn's decision_function output (lower = more anomalous)
    - anomaly_score_0_100: rescaled so higher = MORE anomalous, easier for
      analysts to read alongside our 0-100 risk scores from Phase 9
    - is_anomaly: True if the model's binary prediction flags this IP as an outlier
    """
    X = features_df[FEATURE_COLUMNS]
    result = features_df.copy()

    raw_scores = model.decision_function(X)  # higher = more normal in sklearn's convention
    predictions = model.predict(X)  # -1 = anomaly, 1 = normal

    result["raw_anomaly_score"] = raw_scores
    result["is_anomaly"] = predictions == -1

    # Rescale so a HIGHER number means MORE anomalous (0-100), matching the
    # intuitive direction of our risk_score from Phase 9. We invert the raw
    # score and min-max scale it across this dataset's own range.
    min_score, max_score = raw_scores.min(), raw_scores.max()
    if max_score == min_score:
        result["anomaly_score_0_100"] = 0.0
    else:
        inverted = max_score - raw_scores  # flip direction: more anomalous = higher
        scaled = (inverted - inverted.min()) / (inverted.max() - inverted.min()) * 100
        result["anomaly_score_0_100"] = scaled.round(1)

    return result


def save_model(model: IsolationForest, path: Path = MODEL_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        pickle.dump(model, f)
    print(f"Saved model -> {path}")


def load_model(path: Path = MODEL_PATH) -> IsolationForest:
    with open(path, "rb") as f:
        return pickle.load(f)


if __name__ == "__main__":
    from src.log_parser import load_and_prepare_logs
    from src.feature_engineering import build_features

    logs = load_and_prepare_logs(Path("data/raw/synthetic_logs.csv"))
    features = build_features(logs)

    model = train_model(features)
    scored = score_features(model, features)

    print("Anomaly detection results (sorted by anomaly score, most unusual first):\n")
    display_cols = ["source_ip", "anomaly_score_0_100", "is_anomaly"] + FEATURE_COLUMNS
    print(scored.sort_values("anomaly_score_0_100", ascending=False)[display_cols].to_string(index=False))

    save_model(model)

    output_path = Path("data/processed/anomaly_scores.csv")
    scored.to_csv(output_path, index=False)
    print(f"\nSaved -> {output_path}")