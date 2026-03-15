import streamlit as st
import requests
import pandas as pd
# --- NEW IMPORTS ---
import io
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
# -------------------

API_URL = "http://127.0.0.1:5000"

st.set_page_config(
    page_title="Phishing Threat Monitor",
    layout="wide"
)

st.title("🛡 Adaptive Phishing Detection SOC Dashboard")
st.caption("Real-time monitoring of phishing detection events.")

# -----------------------------
# REFRESH BUTTON
# -----------------------------

if st.button("🔄 Refresh Dashboard"):
    st.rerun()

st.divider()

# -----------------------------
# FETCH INCIDENT DATA
# -----------------------------

try:
    response = requests.get(f"{API_URL}/api/v1/incidents")
    df = pd.DataFrame(response.json())

    # -----------------------------
    # HANDLE EMPTY DATA
    # -----------------------------

    if df.empty:
        st.info("No security events recorded yet.")
        st.stop()

    # -----------------------------
    # DATA CLEANING
    # -----------------------------

    if "risk_score" in df.columns:
        df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce")

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    df = df.dropna(subset=["risk_score"])

    # -----------------------------
    # METRICS
    # -----------------------------

    st.subheader("Threat Overview")
    col1, col2, col3, col4 = st.columns(4)

    total_events = len(df)
    high_count = len(df[df["risk_level"] == "HIGH"])
    medium_count = len(df[df["risk_level"] == "MEDIUM"])
    low_count = len(df[df["risk_level"] == "LOW"])

    col1.metric("Total Events", total_events)
    col2.metric("High Risk", high_count)
    col3.metric("Medium Risk", medium_count)
    col4.metric("Low Risk", low_count)

    st.divider()

    # -----------------------------
    # SECURITY EVENT LOG TABLE
    # -----------------------------

    st.subheader("Security Event Logs")

    if "timestamp" in df.columns:
        df = df.sort_values(by="timestamp", ascending=False)

    def highlight_risk(val):
        if val == "HIGH":
            return "background-color:red;color:white"
        elif val == "MEDIUM":
            return "background-color:orange"
        elif val == "LOW":
            return "background-color:lightgreen"
        return ""

    # Note: applymap is deprecated in newer pandas; use .map for element-wise
    styled_df = df.style.applymap(highlight_risk, subset=["risk_level"])
    st.dataframe(styled_df, use_container_width=True)

    st.divider()

    # -----------------------------
    # THREAT ANALYTICS
    # -----------------------------

    st.subheader("Threat Analytics")
    col1, col2 = st.columns(2)

    if not df["risk_score"].empty:
        col1.write("Risk Score Distribution")
        col1.bar_chart(df["risk_score"])

    if "risk_level" in df.columns:
        risk_counts = df["risk_level"].value_counts()
        if not risk_counts.empty:
            col2.write("Threat Level Distribution")
            col2.bar_chart(risk_counts)

    st.divider()

    # -----------------------------
    # ATTACK TIMELINE
    # -----------------------------

    if "timestamp" in df.columns:
        st.subheader("Attack Timeline")
        timeline = df.dropna(subset=["timestamp", "risk_score"])
        if not timeline.empty:
            timeline = timeline.sort_values("timestamp")
            timeline = timeline.set_index("timestamp")
            st.line_chart(timeline["risk_score"])

    st.divider()

    # -----------------------------
    # MOST TARGETED USERS
    # -----------------------------

    st.subheader("Most Targeted Users")
    if "user_id" in df.columns:
        user_counts = df["user_id"].value_counts().head(5)
        if not user_counts.empty:
            st.bar_chart(user_counts)

    # ---------------------------------------------------------
    # NEW: SECURITY REPORT GENERATION (Inside the try block)
    # ---------------------------------------------------------
    
    st.divider()
    st.subheader("Security Report")

    def generate_pdf_report(df):
        buffer = io.BytesIO()
        styles = getSampleStyleSheet()
        elements = []

        elements.append(Paragraph("Adaptive Phishing Detection SOC Report", styles['Title']))
        elements.append(Spacer(1, 20))

        t_events = len(df)
        h_attacks = len(df[df["risk_level"] == "HIGH"])
        m_attacks = len(df[df["risk_level"] == "MEDIUM"])
        l_attacks = len(df[df["risk_level"] == "LOW"])

        elements.append(Paragraph(f"Total Events: {t_events}", styles['Normal']))
        elements.append(Paragraph(f"High Risk Attacks: {h_attacks}", styles['Normal']))
        elements.append(Paragraph(f"Medium Risk Attacks: {m_attacks}", styles['Normal']))
        elements.append(Paragraph(f"Low Risk Events: {l_attacks}", styles['Normal']))
        elements.append(Spacer(1, 20))

        # Top users
        if "user_id" in df.columns:
            top_users = df["user_id"].value_counts().head(5)
            user_data = [["User ID", "Attack Count"]]
            for user, count in top_users.items():
                user_data.append([str(user), str(count)])
            elements.append(Paragraph("Most Targeted Users", styles['Heading2']))
            elements.append(Table(user_data))
            elements.append(Spacer(1, 20))

        # Top IPs
        if "source_ip" in df.columns:
            top_ips = df["source_ip"].value_counts().head(5)
            ip_data = [["Source IP", "Attack Count"]]
            for ip, count in top_ips.items():
                ip_data.append([str(ip), str(count)])
            elements.append(Paragraph("Top Attacking Source IPs", styles['Heading2']))
            elements.append(Table(ip_data))
            elements.append(Spacer(1, 20))

        # Devices
        if "device_id" in df.columns:
            top_devices = df["device_id"].value_counts().head(5)
            device_data = [["Device", "Events"]]
            for dev, count in top_devices.items():
                device_data.append([str(dev), str(count)])
            elements.append(Paragraph("Most Used Devices", styles['Heading2']))
            elements.append(Table(device_data))

        doc = SimpleDocTemplate(buffer)
        doc.build(elements)
        buffer.seek(0)
        return buffer

    if st.button("Generate PDF Security Report"):
        pdf = generate_pdf_report(df)
        st.download_button(
            label="Download PDF Report",
            data=pdf,
            file_name="soc_security_report.pdf",
            mime="application/pdf"
        )

except Exception as e:
    st.error(f"Unable to fetch security events. Error: {e}")
    st.info("Please ensure the backend API is running.")