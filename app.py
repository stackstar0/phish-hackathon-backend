from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # allow requests from any frontend

# Simple rule-based phishing check
def rule_check(url: str) -> bool:
    suspicious_words = ["login", "free", "click", "verify", "account", "bank"]
    u = (url or "").lower().strip()
    if not u:
        return False
    if "@" in u or len(u) > 120 or u.count("/") > 4:
        return True
    for w in suspicious_words:
        if w in u:
            return True
    return False

@app.route("/")
def home():
    return jsonify({"status": "ok", "message": "Backend running"})

@app.route("/check-url", methods=["POST"])
def check_url():
    data = request.get_json() or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"status": "error", "message": "No URL provided"}), 400

    phishing = rule_check(url)

    return jsonify({
        "status": "success",
        "url": url,
        "phishing": phishing
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
