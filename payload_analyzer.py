import re

# -----------------------------
# PHISHING KEYWORDS
# -----------------------------
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

# -----------------------------
# SUSPICIOUS TLDS
# -----------------------------
suspicious_domains = [
    ".xyz",
    ".top",
    ".click",
    ".ru",
    ".gq",
    ".tk"
]

# -----------------------------
# BRAND IMPERSONATION TARGETS
# -----------------------------
target_brands = [
    "paypal",
    "amazon",
    "microsoft",
    "google",
    "apple",
    "bank",
    "netflix"
]


def extract_urls(text):
    """Extract URLs from text"""
    url_pattern = r"https?://[^\s]+"
    return re.findall(url_pattern, text)


def analyze_payload(text):

    score = 0
    signals = {
        "keyword_detected": False,
        "url_detected": False,
        "suspicious_domain": False,
        "brand_impersonation": False
    }

    lower = text.lower()

    # -----------------------------
    # KEYWORD DETECTION
    # -----------------------------
    if any(k in lower for k in phishing_keywords):
        score += 0.4
        signals["keyword_detected"] = True

    # -----------------------------
    # URL DETECTION
    # -----------------------------
    urls = extract_urls(text)

    if urls:
        score += 0.2
        signals["url_detected"] = True

    # -----------------------------
    # DOMAIN CHECK
    # -----------------------------
    for url in urls:

        for d in suspicious_domains:
            if d in url:
                score += 0.4
                signals["suspicious_domain"] = True

        # brand impersonation detection
        for brand in target_brands:
            if brand in url and not url.startswith(f"https://{brand}."):
                score += 0.3
                signals["brand_impersonation"] = True

    return min(score, 1.0), signals