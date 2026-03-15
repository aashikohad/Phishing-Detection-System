import streamlit as st
import requests

API_URL = "http://127.0.0.1:5000"

st.set_page_config(
    page_title="Email Threat Evaluation",
    layout="wide"
)

st.title("📧 Email Threat Evaluation Console")
st.caption("Submit email metadata and content to evaluate phishing risk.")

st.divider()

# -----------------------------
# API STATUS CHECK
# -----------------------------

try:
    health = requests.get(API_URL, timeout=2)
    if health.status_code == 200:
        st.success("Backend API Connected")
    else:
        st.warning("Backend API responded but returned unexpected status.")
except:
    st.error("Backend API is not running. Please start Flask server with: python app.py")
    st.stop()

# -----------------------------
# EMAIL METADATA
# -----------------------------

st.subheader("Email Metadata")

col1, col2 = st.columns(2)

with col1:
    user_id = st.number_input("User ID", value=1001)

    device_id = st.text_input(
        "Device Name",
        "android-SM_G991B"
    )

    source_ip = st.text_input(
        "Source IP",
        "185.23.55.10"
    )

with col2:
    destination_ip = st.text_input(
        "Destination IP",
        "192.168.1.12"
    )

    login_hour = st.slider(
        "Login Hour",
        0,
        23,
        12
    )

st.divider()

# -----------------------------
# EMAIL CONTENT
# -----------------------------

st.subheader("Email Content")

payload = st.text_area(
    "Paste Email Content",
    height=250,
    placeholder="Paste suspicious email content here..."
)

st.divider()

# -----------------------------
# EVALUATE EMAIL
# -----------------------------

if st.button("🚨 Evaluate Email Threat"):

    if payload.strip() == "":
        st.warning("Please paste email content before evaluation.")
        st.stop()

    data = {
        "user_id": int(user_id),
        "device_id": device_id,
        "login_hour": int(login_hour),
        "payload": payload,
        "source_ip": source_ip,
        "destination_ip": destination_ip
    }

    try:

        response = requests.post(
            f"{API_URL}/api/v1/evaluate",
            json=data,
            timeout=5
        )

        if response.status_code != 200:
            st.error(f"API returned error: {response.status_code}")
            st.stop()

        result = response.json()

        st.subheader("Evaluation Result")

        col1, col2 = st.columns(2)

        col1.metric("Risk Score", result["risk_score"])
        col2.metric("Risk Level", result["risk_level"])

        # -----------------------------
        # RISK ALERT
        # -----------------------------

        if result["risk_level"] == "HIGH":
            st.error("🚨 HIGH RISK PHISHING EMAIL DETECTED")

        elif result["risk_level"] == "MEDIUM":
            st.warning("⚠ Suspicious Email Detected")

        else:
            st.success("✅ Email appears safe")

        st.subheader("Detection Signals")

        st.json(result["signals"])

    except Exception as e:

        st.error("Failed to connect to backend API.")
        st.code(str(e))