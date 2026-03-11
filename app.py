from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

from rule_engine import evaluate
from database import init_db, insert_event, get_events

app = Flask(__name__)
CORS(app)


@app.route("/")
def home():
    return "Adaptive Phishing Detection API Running"


@app.route("/api/v1/evaluate", methods=["POST"])
def evaluate_api():

    data = request.get_json()

    user_id = data.get("user_id")
    login_hour = data.get("login_hour")
    device_id = data.get("device_id")
    payload = data.get("payload")

    result = evaluate(user_id, login_hour, device_id, payload)

    insert_event(
        user_id,
        device_id,
        login_hour,
        payload,
        result["risk_score"],
        result["risk_level"],
        datetime.utcnow().isoformat()
    )

    return jsonify(result)


@app.route("/api/v1/incidents")
def incidents():

    events = get_events()

    return jsonify(events)


if __name__ == "__main__":

    init_db()

    app.run(host="0.0.0.0", port=5000, debug=True)