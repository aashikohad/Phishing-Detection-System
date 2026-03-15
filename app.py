from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

from rule_engine import evaluate
from database import init_db, insert_event, get_events, flag_malicious_ip

app = Flask(__name__)
CORS(app)


# -----------------------------
# API HEALTH CHECK
# -----------------------------
@app.route("/")
def home():
    return jsonify({
        "status": "running",
        "service": "Adaptive Phishing Detection API"
    })


# -----------------------------
# EMAIL EVALUATION
# -----------------------------
@app.route("/api/v1/evaluate", methods=["POST"])
def evaluate_api():

    try:

        data = request.get_json()

        if not data:
            return jsonify({"error": "Invalid JSON request"}), 400

        user_id = data.get("user_id", 0)
        login_hour = data.get("login_hour", 12)
        device_id = data.get("device_id", "unknown-device")
        payload = data.get("payload", "")
        source_ip = data.get("source_ip", "0.0.0.0")
        destination_ip = data.get("destination_ip", "0.0.0.0")

        # -----------------------------
        # RUN RISK EVALUATION
        # -----------------------------
        result = evaluate(user_id, login_hour, device_id, payload)

        timestamp = datetime.utcnow().isoformat()

        # -----------------------------
        # STORE EVENT
        # -----------------------------
        insert_event(
            user_id,
            device_id,
            source_ip,
            destination_ip,
            login_hour,
            payload,
            result["risk_score"],
            result["risk_level"],
            timestamp
        )

        # -----------------------------
        # FLAG MALICIOUS SOURCE IP
        # -----------------------------
        if result["risk_level"] == "HIGH":
            flag_malicious_ip(source_ip, timestamp)

        return jsonify(result)

    except Exception as e:

        return jsonify({
            "error": "Evaluation failed",
            "details": str(e)
        }), 500


# -----------------------------
# INCIDENT LOGS
# -----------------------------
@app.route("/api/v1/incidents")
def incidents():

    try:

        events = get_events()

        return jsonify(events)

    except Exception as e:

        return jsonify({
            "error": "Failed to fetch events",
            "details": str(e)
        }), 500


# -----------------------------
# START SERVER
# -----------------------------
if __name__ == "__main__":

    init_db()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )