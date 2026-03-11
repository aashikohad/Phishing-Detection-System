import streamlit as st
import requests
import pandas as pd

API_URL = "http://127.0.0.1:5000"

st.set_page_config(
    page_title="Phishing Threat Monitor",
    layout="wide"
)

st.title(" Adaptive Phishing Detection SOC Dashboard")
st.caption("User identity is generated using device fingerprinting.")

# -----------------------------
# USER INPUT PANEL
# -----------------------------

st.sidebar.header("User Activity Simulation")

user_name = st.sidebar.text_input("User Name", "user1")

login_hour = st.sidebar.slider("Login Hour", 0, 23)

device_id = st.sidebar.text_input(
    "Device ID",
    "android-SM_G991B-8f3a92d1"
)

# Generate unique fingerprint
fingerprint = user_name + device_id
user_id = abs(hash(fingerprint)) % 10000

st.sidebar.info(f"Generated User ID: {user_id}")

payload = st.sidebar.text_area(
    "Email Content",
    height=200
)

# -----------------------------
# THREAT EVALUATION
# -----------------------------

if st.sidebar.button(" Evaluate Threat"):

    data = {
        "user_id": int(user_id),
        "login_hour": int(login_hour),
        "device_id": device_id,
        "payload": payload
    }

    try:

        r = requests.post(f"{API_URL}/api/v1/evaluate", json=data)

        result = r.json()

        col1, col2, col3 = st.columns(3)

        col1.metric("Risk Score", result["risk_score"])
        col2.metric("Risk Level", result["risk_level"])
        col3.metric("Login Hour", login_hour)

        if result["risk_level"] == "HIGH":
            st.error("🚨 HIGH RISK PHISHING ATTACK DETECTED")

        elif result["risk_level"] == "MEDIUM":
            st.warning("⚠ Suspicious Activity Detected")

        else:
            st.success("✅ Activity appears safe")

        st.subheader("🔍 Detection Signals")

        st.json(result["signals"])

    except:
        st.error("Backend API is not reachable.")

# -----------------------------
# INCIDENT MONITORING
# -----------------------------

st.subheader(" Security Event Logs")

try:

    r = requests.get(f"{API_URL}/api/v1/incidents")

    df = pd.DataFrame(r.json())

    if len(df) > 0:

        # Metrics
        col1, col2, col3 = st.columns(3)

        col1.metric("Total Events", len(df))

        high_count = len(df[df["risk_level"] == "HIGH"])
        col2.metric("High Risk Attacks", high_count)

        medium_count = len(df[df["risk_level"] == "MEDIUM"])
        col3.metric("Medium Risk Events", medium_count)

        # Sort by time
        if "timestamp" in df.columns:
            df = df.sort_values(by="timestamp", ascending=False)

        # -----------------------------
        # Severity coloring
        # -----------------------------

        def highlight_risk(val):

            if val == "HIGH":
                return "background-color: red; color:white"

            elif val == "MEDIUM":
                return "background-color: orange"

            elif val == "LOW":
                return "background-color: lightgreen"

            return ""

        styled_df = df.style.applymap(
            highlight_risk,
            subset=["risk_level"]
        )

        st.dataframe(styled_df)

        # -----------------------------
        # Threat analytics
        # -----------------------------

        st.subheader("Threat Analytics")

        col1, col2 = st.columns(2)

        # Risk score chart
        col1.bar_chart(df["risk_score"])

        # Threat distribution
        risk_counts = df["risk_level"].value_counts()

        col2.write("Threat Distribution")
        col2.bar_chart(risk_counts)

        # -----------------------------
        # Attack timeline
        # -----------------------------

        if "timestamp" in df.columns:

            st.subheader(" Attack Timeline")

            timeline = df.copy()

            timeline["timestamp"] = pd.to_datetime(timeline["timestamp"])

            timeline = timeline.sort_values("timestamp")

            timeline = timeline.set_index("timestamp")

            st.line_chart(timeline["risk_score"])

        # -----------------------------
        # Top attacked users
        # -----------------------------

        st.subheader("Most Targeted Users")

        user_counts = df["user_id"].value_counts().head(5)

        st.bar_chart(user_counts)

    else:

        st.info("No security events recorded yet.")

except:

    st.warning("Could not fetch security events. Check if API server is running.")