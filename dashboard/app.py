"""
Mini SOC Dashboard — Streamlit app that loads generated alerts and lets
you triage, filter, and investigate them, simulating the core loop of a
real SOC analyst's workflow at a small, learning-project scale.

This is NOT a full SIEM: no real-time ingestion, no multi-source log
correlation, no case management. See docs/PROJECT_EXPLANATION.md for the
full list of what a real SIEM does that this project intentionally omits.
"""

from pathlib import Path

import pandas as pd
import streamlit as st

ALERTS_PATH = Path("data/processed/alerts.json")
RAW_LOGS_PATH = Path("data/raw/synthetic_logs.csv")

st.set_page_config(page_title="Mini SOC Dashboard", layout="wide")


@st.cache_data
def load_alerts() -> pd.DataFrame:
    """Loads generated alerts. Cached so Streamlit doesn't re-read the
    file on every single user interaction (filter change, etc.)."""
    if not ALERTS_PATH.exists():
        return pd.DataFrame()
    df = pd.read_json(ALERTS_PATH)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


@st.cache_data
def load_raw_event_count() -> int:
    """Total processed events, for the top-line metric."""
    if not RAW_LOGS_PATH.exists():
        return 0
    return len(pd.read_csv(RAW_LOGS_PATH))


st.title("🛡️ Mini SOC Dashboard")
st.caption(
    "A small-scale simulation of a SOC analyst's triage workflow — "
    "not a production SIEM. Rule-based detections, enriched with ML anomaly context."
)

alerts_df = load_alerts()

if alerts_df.empty:
    st.warning(
        "No alerts found. Run `python -m src.alert_manager` first to "
        "generate `data/processed/alerts.json`."
    )
    st.stop()

# --- Section 1: Top-line metrics ---
total_events = load_raw_event_count()
total_alerts = len(alerts_df)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Events Processed", total_events)
col2.metric("Total Alerts", total_alerts)
col3.metric("Distinct Source IPs Alerted", alerts_df["source_ip"].nunique())
col4.metric(
    "Critical/High Alerts",
    len(alerts_df[alerts_df["severity"].isin(["Critical", "High"])]),
)

st.divider()

# --- Section 2: Filters (in the sidebar) ---
st.sidebar.header("Filters")

threat_options = sorted(alerts_df["threat_name"].unique())
selected_threats = st.sidebar.multiselect(
    "Threat Type", options=threat_options, default=threat_options
)

severity_options = ["Critical", "High", "Medium", "Low"]
selected_severities = st.sidebar.multiselect(
    "Severity", options=severity_options, default=severity_options
)

filtered_df = alerts_df[
    alerts_df["threat_name"].isin(selected_threats)
    & alerts_df["severity"].isin(selected_severities)
]

st.sidebar.caption(f"Showing {len(filtered_df)} of {total_alerts} alerts")

# --- Section 3: Alerts by severity and by attack type (charts) ---
chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.subheader("Alerts by Severity")
    severity_counts = filtered_df["severity"].value_counts().reindex(severity_options).fillna(0)
    st.bar_chart(severity_counts)

with chart_col2:
    st.subheader("Alerts by Attack Type")
    threat_counts = filtered_df["threat_name"].value_counts()
    st.bar_chart(threat_counts)

# --- Section 4: Top suspicious source IPs ---
st.subheader("Top Suspicious Source IPs")
top_ips = (
    filtered_df.groupby("source_ip")
    .agg(alert_count=("alert_id", "count"), max_risk_score=("risk_score", "max"))
    .sort_values("max_risk_score", ascending=False)
    .head(10)
)
st.dataframe(top_ips, use_container_width=True)

# --- Section 5: Timeline of suspicious activity ---
st.subheader("Timeline of Suspicious Activity")
timeline = filtered_df.set_index("timestamp").resample("1min").size()
st.line_chart(timeline, use_container_width=True)

st.divider()

# --- Section 6: Detailed alert table ---
st.subheader("Alert Details")
display_columns = [
    "alert_id", "timestamp", "source_ip", "threat_name", "severity",
    "risk_score", "confidence_or_anomaly_score", "mitre_technique_id", "detection_method",
]
st.dataframe(
    filtered_df[display_columns].sort_values("timestamp", ascending=False),
    use_container_width=True,
)

# --- Section 7: Alert investigation ---
st.subheader("Investigate an Alert")
selected_alert_id = st.selectbox(
    "Select an Alert ID to investigate", options=filtered_df["alert_id"].tolist()
)

if selected_alert_id:
    alert = filtered_df[filtered_df["alert_id"] == selected_alert_id].iloc[0]

    inv_col1, inv_col2 = st.columns(2)

    with inv_col1:
        st.markdown(f"**Threat:** {alert['threat_name']}")
        st.markdown(f"**Severity:** {alert['severity']} (risk score: {alert['risk_score']})")
        st.markdown(f"**Source IP:** {alert['source_ip']}")
        st.markdown(f"**Destination IP:** {alert['destination_ip']}")
        st.markdown(f"**Timestamp:** {alert['timestamp']}")
        st.markdown(f"**Detection Method:** {alert['detection_method']}")
        if pd.notna(alert["confidence_or_anomaly_score"]):
            st.markdown(f"**ML Anomaly Score:** {alert['confidence_or_anomaly_score']}/100")

    with inv_col2:
        st.markdown(f"**MITRE Technique:** {alert['mitre_technique_id']} — {alert['mitre_technique_name']}")
        st.markdown(f"**MITRE Tactic:** {alert['mitre_tactic']}")
        st.markdown("**Description:**")
        st.info(alert["description"])
        st.markdown("**Detection Reason:**")
        st.info(alert["detection_reason"])

    st.markdown("**Recommended Response:**")
    st.success(alert["recommended_response"])