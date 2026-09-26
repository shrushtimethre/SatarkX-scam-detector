from flask import Flask, render_template, request, jsonify, send_file
import re
import json
import os
from io import BytesIO
from datetime import datetime
from uuid import uuid4

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


app = Flask(__name__)
HISTORY_FILE = os.path.join(app.root_path, "scan_history.json")


# --------------------------------------------------
# MINI ML MODEL
# --------------------------------------------------

training_messages = [
    "hello how are you",
    "your meeting is scheduled tomorrow",
    "thank you for your message",
    "your order has been delivered",
    "happy birthday have a great day",
    "please find the document attached",
    "your payment was successful",

    "urgent your account will be blocked click this link",
    "verify your bank account immediately",
    "you have won a lottery claim your prize now",
    "send your otp immediately to verify your account",
    "your kyc has expired click the link",
    "congratulations you won a cash reward",
    "your account will be suspended verify now",
    "click here to receive free money",
    "share your password and otp immediately",
    "urgent payment required your account will be closed"
]

training_labels = [
    0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1
]

vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words="english"
)

X = vectorizer.fit_transform(training_messages)

model = LogisticRegression(max_iter=1000)
model.fit(X, training_labels)


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []

    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def save_history(history):
    with open(HISTORY_FILE, "w", encoding="utf-8") as file:
        json.dump(history, file, indent=2)


def add_history_record(record):
    history = load_history()
    history.insert(0, record)
    save_history(history[:20])


def build_dashboard_stats(history):
    total = len(history)
    high = sum(1 for item in history if item.get("risk_color") == "high")
    suspicious = sum(1 for item in history if item.get("risk_color") == "medium")
    safe = sum(1 for item in history if item.get("risk_color") == "safe")
    return {
        "total": total,
        "high": high,
        "suspicious": suspicious,
        "safe": safe
    }


# --------------------------------------------------
# URL SECURITY ANALYSIS
# --------------------------------------------------

def analyze_url(url):

    reasons = []
    score = 0

    suspicious_words = [
        "verify",
        "login",
        "secure",
        "account",
        "update",
        "confirm",
        "claim",
        "reward",
        "free",
        "wallet",
        "bank"
    ]

    shortened_domains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "shorturl.at",
        "is.gd"
    ]

    if not url.lower().startswith("https://"):
        score += 15
        reasons.append("⚠ Link does not use HTTPS")

    if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
        score += 30
        reasons.append("⚠ URL uses an IP address")

    if "@" in url:
        score += 25
        reasons.append("⚠ Suspicious '@' character detected")

    domain_part = re.sub(r"https?://", "", url).split("/")[0]
    if domain_part.count(".") >= 3:
        score += 15
        reasons.append("⚠ Unusually complex domain structure")

    if len(url) > 100:
        score += 10
        reasons.append("⚠ Unusually long URL")

    lower_url = url.lower()
    found_words = []
    for word in suspicious_words:
        if word in lower_url:
            found_words.append(word)

    if found_words:
        score += min(20, len(found_words) * 5)
        reasons.append("⚠ Suspicious URL keywords: " + ", ".join(found_words[:4]))

    for domain in shortened_domains:
        if domain in lower_url:
            score += 20
            reasons.append("⚠ URL shortening service detected")
            break

    return min(score, 100), reasons


# --------------------------------------------------
# MESSAGE ANALYSIS
# --------------------------------------------------

def analyze_message(message):

    reasons = []
    score = 0

    lower_message = message.lower()

    transformed = vectorizer.transform([message])
    probability = model.predict_proba(transformed)[0][1]
    ml_score = int(probability * 60)
    score += ml_score

    urgency_words = [
        "urgent",
        "immediately",
        "now",
        "today",
        "hurry",
        "asap",
        "last warning"
    ]

    found_urgency = [word for word in urgency_words if word in lower_message]
    if found_urgency:
        score += 15
        reasons.append("⚠ Urgent or pressure-based language detected")

    sensitive_words = [
        "otp",
        "password",
        "pin",
        "cvv",
        "bank details",
        "card details"
    ]

    found_sensitive = [word for word in sensitive_words if word in lower_message]
    if found_sensitive:
        score += 20
        reasons.append("⚠ Request for sensitive information detected")

    money_words = [
        "payment",
        "pay",
        "money",
        "cash",
        "reward",
        "prize",
        "lottery",
        "refund"
    ]

    if any(word in lower_message for word in money_words):
        score += 10
        reasons.append("⚠ Financial/reward-related language detected")

    if re.search(r"https?://\S+", message):
        score += 10
        reasons.append("⚠ External link detected")

    impersonation_words = [
        "bank",
        "government",
        "police",
        "income tax",
        "kyc",
        "customer care",
        "support team"
    ]

    if any(word in lower_message for word in impersonation_words):
        score += 10
        reasons.append("⚠ Possible organization impersonation detected")

    return min(score, 100), reasons


# --------------------------------------------------
# MAIN ANALYSIS
# --------------------------------------------------

def analyze_input(user_input):

    text_score, reasons = analyze_message(user_input)
    urls = re.findall(r'https?://[^\s]+', user_input)
    url_score = 0

    for url in urls:
        current_score, url_reasons = analyze_url(url)
        url_score = max(url_score, current_score)
        reasons.extend(url_reasons)

    final_score = min(100, int(text_score * 0.65 + url_score * 0.35))

    if url_score >= 50:
        final_score = max(final_score, 60)

    if final_score >= 70:
        risk_level = "HIGH RISK"
        risk_color = "high"
    elif final_score >= 40:
        risk_level = "SUSPICIOUS"
        risk_color = "medium"
    else:
        risk_level = "LOW RISK"
        risk_color = "safe"

    unique_reasons = []
    for reason in reasons:
        if reason not in unique_reasons:
            unique_reasons.append(reason)

    if not unique_reasons:
        unique_reasons.append("✓ No major scam indicators detected")

    return {
        "score": final_score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "reasons": unique_reasons[:6]
    }


# --------------------------------------------------
# ROUTES
# --------------------------------------------------

@app.route("/")
def home():
    history = load_history()
    stats = build_dashboard_stats(history)
    return render_template("index.html", history=history[:5], stats=stats)


@app.route("/history")
def get_history():
    return jsonify({"history": load_history()})


@app.route("/download/<scan_id>")
def download_scan(scan_id):
    history = load_history()
    scan = next((item for item in history if item.get("id") == scan_id), None)

    if not scan:
        return jsonify({"error": "Scan not found."}), 404

    payload = json.dumps(scan, indent=2).encode("utf-8")
    file_stream = BytesIO(payload)
    return send_file(
        file_stream,
        mimetype="application/json",
        as_attachment=True,
        download_name=f"scan_{scan_id}.json"
    )


@app.route("/analyze", methods=["POST"])

def analyze():
    data = request.get_json()

    if not data or not data.get("text"):
        return jsonify({"error": "Please enter a message or URL."}), 400

    user_input = data["text"].strip()
    result = analyze_input(user_input)

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    scan_record = {
        "id": str(uuid4()),
        "text": user_input[:220],
        "score": result["score"],
        "risk_level": result["risk_level"],
        "risk_color": result["risk_color"],
        "reasons": result["reasons"],
        "timestamp": timestamp
    }
    add_history_record(scan_record)

    return jsonify({**result, "scan_id": scan_record["id"]})


# --------------------------------------------------
# RUN SERVER
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)