# AI-Powered Cybersecurity Threat Detection & Mini SOC Dashboard

A beginner-friendly cybersecurity project that detects brute-force login
attempts, port scanning, and SQL injection probing in security logs using
explainable detection rules, enriched with an Isolation Forest anomaly
detection model, and presented through a Streamlit mini SOC dashboard.

## Project Overview

This project is a small-scale simulation of what a SOC analyst does day to
day: review security logs, detect suspicious patterns, assess severity,
map findings to known attacker techniques, and decide on a response. It is
built to demonstrate real cybersecurity reasoning first, with machine
learning as a supporting — not primary — detection mechanism.

**Cyber/AI balance:** ~65% cybersecurity logic (log design, detection
rules, severity scoring, MITRE ATT&CK mapping, SOC dashboard workflow),
~35% AI/ML (feature engineering, Isolation Forest anomaly detection,
evaluation).

## Problem Statement

Security teams face far more log data than they can manually review.
Automated detection — using both explicit rules and statistical anomaly
detection — helps surface the events most worth an analyst's attention.
This project builds a small, understandable version of that detection +
triage pipeline for three common attack patterns.

## Cybersecurity Concepts Demonstrated

- Security log structure and analysis
- Rule-based threshold detection (brute force, port scanning)
- Pattern-based detection (SQL injection probing)
- Security alert standardization
- Risk scoring and severity classification
- MITRE ATT&CK tactic/technique mapping
- SOC analyst triage workflow

See `docs/CYBERSECURITY_CONCEPTS.md` for full explanations.

## AI/ML Role

An Isolation Forest anomaly detection model (unsupervised learning) is
trained on per-source-IP behavioral features to catch statistically
unusual activity. Its output enriches rule-based alerts with an anomaly
score — it never replaces or overrides rule-based detection. See
`docs/AI_ML_EXPLANATION.md` for full details.

## Architecture

```text
Raw logs (CSV)
   -> Parsing & validation (Pandas)
   -> Rule-based detection (brute force / port scan / SQL injection)
   -> Feature engineering (per-source-IP aggregation)
   -> Isolation Forest anomaly scoring
   -> Risk scoring (0-100, mapped to Low/Medium/High/Critical)
   -> MITRE ATT&CK mapping
   -> Standardized alert export (JSON/CSV)
   -> Streamlit SOC dashboard
```

## Folder Structure

```text
ai-cyber-threat-detection/
├── data/
│   ├── raw/            # synthetic log CSV
│   └── processed/       # alerts, features, anomaly scores (generated, gitignored)
├── src/                 # all detection/scoring/ML logic
├── dashboard/app.py      # Streamlit SOC dashboard
├── models/               # saved Isolation Forest model (generated, gitignored)
├── tests/                # unit tests per module
├── docs/                 # supplementary documentation
├── main.py               # runs the full pipeline end-to-end
└── requirements.txt
```

## Installation

```powershell
git clone https://github.com/YOUR_USERNAME/ai-cyber-threat-detection.git
cd ai-cyber-threat-detection
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## How to Run

```powershell
python main.py
streamlit run dashboard\app.py
```

## Sample Alert

```json
{
  "alert_id": "a1b2c3d4",
  "threat_name": "Brute Force Login Attempt",
  "severity": "Critical",
  "risk_score": 85,
  "mitre_technique_id": "T1110",
  "mitre_technique_name": "Brute Force",
  "recommended_response": "Temporarily block or rate-limit the source IP..."
}
```

## Screenshots

*(Add dashboard screenshots here before submitting/presenting — see
docs/DEMO_GUIDE.md for which views to capture.)*

## Evaluation

Rule-based and ML-based detection are evaluated separately using
precision, recall, and F1-score at the source-IP level. See
`docs/AI_ML_EXPLANATION.md` for full results and discussion.

## Limitations

- Synthetic dataset only — small scale, clean/obvious attack patterns
  compared to real-world traffic
- Not a real-time system — processes static log files, not a live stream
- Not a full SIEM — no multi-source ingestion, case management, or
  multi-analyst support
- Detection thresholds are reasonable estimates, not tuned against real
  production traffic

## Ethical Statement

This project uses only synthetic, self-generated data. No scanning,
attacking, or testing was performed against any system without explicit
authorization. This project is for educational and portfolio purposes
only, and its detection logic should not be relied upon in a production
security environment without significant further validation.

## Future Improvements

- Support for a public, real-world security log dataset as an optional
  extension
- ML-only detection surfaced as a distinct alert category (currently ML
  only enriches rule-based alerts)
- Password-spraying detection (many usernames, one source IP)
- Case management / alert status tracking (open, investigating, resolved)