from payload_analyzer import analyze_payload
from device_checker import check_device


def time_risk(hour):

    if hour >= 0 and hour <= 5:
        return 0.8
    elif hour >= 22:
        return 0.6
    else:
        return 0.2


def evaluate(user_id, login_hour, device_id, payload):

    content_score, content_signals = analyze_payload(payload)

    device_score, new_device = check_device(user_id, device_id)

    time_score = time_risk(login_hour)

    risk = (
        0.7 * content_score +
        0.2 * time_score +
        0.1 * device_score
    )

    # Default classification
    if risk > 0.7:
        level = "HIGH"
    elif risk > 0.25:
        level = "MEDIUM"
    else:
        level = "LOW"

    # -----------------------------
    # Cybersecurity Rule Upgrades
    # -----------------------------

    # Rule 1: Strong phishing override
    if content_score > 0.8:
        level = "HIGH"

    # Rule 2: Phishing + night login
    if content_score > 0.6 and login_hour <= 5:
        level = "HIGH"

    # Rule 3: Very high risk score
    if risk > 0.6:
        level = "HIGH"

    return {
        "risk_score": round(risk, 3),
        "risk_level": level,
        "signals": {
            "content_score": content_score,
            "time_score": time_score,
            "new_device": new_device
        }
    }