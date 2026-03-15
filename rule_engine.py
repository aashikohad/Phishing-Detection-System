from payload_analyzer import analyze_payload
from device_checker import check_device


def time_risk(hour):

    if 0 <= hour <= 5:
        return 0.7
    elif hour >= 22:
        return 0.5
    else:
        return 0.2


def evaluate(user_id, login_hour, device_id, payload):

    # Analyze email content
    content_score, content_signals = analyze_payload(payload)

    # Check device reputation
    device_score, new_device = check_device(user_id, device_id)

    # Check login time
    time_score = time_risk(login_hour)

    # -----------------------------
    # Risk Scoring Formula
    # -----------------------------
    risk = (
        0.6 * content_score +
        0.25 * time_score +
        0.15 * device_score
    )

    # -----------------------------
    # Risk Classification
    # -----------------------------
    if risk >= 0.7:
        level = "HIGH"

    elif risk >= 0.35:
        level = "MEDIUM"

    else:
        level = "LOW"

    # -----------------------------
    # Override Rules (Cybersecurity)
    # -----------------------------

    # Strong phishing signals
    if content_score >= 0.9:
        level = "HIGH"

    # Phishing + night login
    if content_score >= 0.6 and login_hour <= 5:
        level = "HIGH"

    return {
        "risk_score": round(risk, 3),
        "risk_level": level,
        "signals": {
            "content_score": content_score,
            "device_score": device_score,
            "time_score": time_score,
            "new_device": new_device
        }
    }