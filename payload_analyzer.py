import re

phishing_keywords = [
    "verify account",
    "reset password",
    "urgent action",
    "account suspended",
    "click here",
    "login immediately",
    "verify your account",
    "security alert",
    "confirm account"
]

suspicious_domains = [
    ".xyz",
    ".top",
    ".click",
    ".ru"
]


def analyze_payload(text):

    score = 0

    signals = {
        "keyword_detected": False,
        "suspicious_url": False
    }

    lower = text.lower()

    # phishing keyword detection
    for k in phishing_keywords:
        if k in lower:
            score += 0.5
            signals["keyword_detected"] = True

    # external link detection
    if "http://" in lower or "https://" in lower:
        score += 0.3
        signals["suspicious_url"] = True

    # suspicious domain detection
    for d in suspicious_domains:
        if d in lower:
            score += 0.4
            signals["suspicious_url"] = True

    return min(score, 1.0), signals