"""Tests for evaluation metrics — uses small hand-built confusion counts
to confirm precision/recall/F1 formulas are correct."""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from src.evaluation import compute_metrics


def test_perfect_detector():
    counts = {"TP": 5, "FP": 0, "FN": 0, "TN": 20}
    metrics = compute_metrics(counts)
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1_score"] == 1.0


def test_detector_with_false_positives_lowers_precision():
    counts = {"TP": 5, "FP": 5, "FN": 0, "TN": 20}
    metrics = compute_metrics(counts)
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 1.0


def test_detector_with_false_negatives_lowers_recall():
    counts = {"TP": 5, "FP": 0, "FN": 5, "TN": 20}
    metrics = compute_metrics(counts)
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 0.5


def test_detector_with_no_positive_predictions_does_not_crash():
    """A detector that flags nothing should return 0.0 metrics, not error."""
    counts = {"TP": 0, "FP": 0, "FN": 3, "TN": 20}
    metrics = compute_metrics(counts)
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1_score"] == 0.0


if __name__ == "__main__":
    test_perfect_detector()
    test_detector_with_false_positives_lowers_precision()
    test_detector_with_false_negatives_lowers_recall()
    test_detector_with_no_positive_predictions_does_not_crash()
    print("All evaluation tests passed.")