# Project Explanation

## What problem does this solve?

Manually reviewing security logs for suspicious activity doesn't scale.
This project automates detection of three well-understood attack patterns
using explainable rules, then adds an anomaly detection layer to catch
statistically unusual behavior the rules might miss.

## Why rules first, ML second?

Rules are explainable: every alert can point to the exact evidence and
threshold that triggered it. This is essential in security, where an
analyst needs to trust and act on an alert's reasoning, not just its
existence. ML anomaly detection is powerful for catching the unexpected,
but it cannot explain *why* something is unusual the way a rule can — so
it is used here to add supporting context, never to independently create
or override rule-based alerts.

## What makes this different from a standard ML classification project?

A standard ML project would take a labeled dataset and optimize a model's
accuracy. This project instead treats explainable, threshold-based
security rules as the primary detection mechanism, with ML providing a
secondary, supporting signal — mirroring how detection engineering
actually works in practice, where rules (or SIEM correlation searches)
remain the backbone of most detection programs.

## Pipeline walkthrough

1. **data_generator.py** creates a labeled synthetic log dataset
2. **log_parser.py** validates and cleans it
3. **detection_rules.py** applies three explainable rules
4. **feature_engineering.py** aggregates per-IP behavioral features
5. **anomaly_detector.py** trains/scores an Isolation Forest model
6. **risk_scoring.py** computes an explainable 0-100 risk score
7. **mitre_mapping.py** attaches MITRE ATT&CK context
8. **alert_manager.py** combines everything into standardized alerts
9. **evaluation.py** measures precision/recall/F1 for both components
10. **dashboard/app.py** presents alerts for triage and investigation