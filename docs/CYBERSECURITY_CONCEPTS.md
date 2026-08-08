# Cybersecurity Concepts

## Core vocabulary

- **Event**: one raw occurrence (one log row)
- **Log**: the stored collection of events
- **Detection**: a rule or model identifying a suspicious pattern
- **Alert**: the standardized, packaged output of a detection
- **Incident**: an alert confirmed by a human analyst as a real security event
- **False positive**: an alert that turns out to represent normal activity
- **True positive**: an alert confirmed as genuinely malicious/unauthorized

## Detection rules

### Brute force (T1110 - Credential Access)
5+ failed logins from the same source IP against the same username within
60 seconds. Threshold chosen to be well above normal human retry behavior
while catching automated attempts. False positives can arise from shared
NAT IPs or buggy client retry logic.

### Port scanning (T1046 - Discovery)
10+ distinct destination ports touched by the same source IP within 60
seconds. Uses distinct port *count*, not total connections, to distinguish
reconnaissance from normal busy traffic to one service. False positives
can arise from legitimate internal vulnerability scanners.

### SQL injection patterns (T1190 - Initial Access)
Web request paths matched against known SQLi substrings (`union select`,
`' or 1=1`, `sleep(`, `information_schema`, etc.). The weakest of our
three rules in terms of false-positive rate, since it relies on text
pattern matching rather than behavioral counting.

## Risk scoring

Base points per threat type + a volume/intensity bonus (capped) + a
+15 point bonus if the same source IP triggered more than one threat
type. Mapped to Low (0-39) / Medium (40-64) / High (65-84) / Critical
(85-100). Full formula and reasoning in `src/risk_scoring.py`.

## MITRE ATT&CK

A public knowledge base of real-world attacker Tactics (goals) and
Techniques (methods), giving analysts a shared vocabulary across tools
and organizations. This project maps each of its three threat types to
one specific technique (see README architecture section).

## SOC and SIEM

A **SOC** is the team and process responsible for monitoring, detecting,
and responding to security threats. A **SIEM** is the enterprise platform
that ingests and correlates logs at scale for that team. This project's
dashboard simulates the SOC analyst's core triage loop at small scale but
is explicitly not a SIEM — see README limitations section.