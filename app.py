# backend/app.py
import os
import hashlib
import time
import json
from flask import Flask, request, jsonify
from flask_cors import CORS

# Optional OpenAI import (guarded)
try:
    import openai
except Exception:
    openai = None

# load key (empty string if not set)
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
if OPENAI_API_KEY and openai:
    openai.api_key = OPENAI_API_KEY

app = Flask(__name__)
CORS(app)

# ----------------------------
# Simple Blockchain helpers
# ----------------------------
BLOCKCHAIN = []

def create_block(data):
    """Create a new block and append to BLOCKCHAIN. Returns dict block."""
    index = len(BLOCKCHAIN) + 1
    timestamp = time.time()
    prev_hash = BLOCKCHAIN[-1]["hash"] if BLOCKCHAIN else "0"
    payload = {
        "index": index,
        "timestamp": timestamp,
        "data": data,
        "previous_hash": prev_hash
    }
    # For deterministic hashing, dump sorted keys
    block_string = json.dumps(payload, sort_keys=True)
    block_hash = hashlib.sha256(block_string.encode()).hexdigest()
    block = {
        "index": index,
        "timestamp": timestamp,
        "data": data,
        "previous_hash": prev_hash,
        "hash": block_hash
    }
    BLOCKCHAIN.append(block)
    return block

def get_blockchain():
    """Return a copy of the blockchain."""
    return BLOCKCHAIN.copy()

# ----------------------------
# Rule-based fallback detector
# ----------------------------
def rule_check(url: str) -> bool:
    """Return True if URL looks suspicious (phishing) by simple heuristics."""
    suspicious_words = [
        "login", "free", "click", "verify", "account", "bank",
        "secure", "update", "signin", "confirm", "phish", "acct", "password"
    ]
    u = (url or "").lower().strip()
    if not u:
        return False
    # very long URLs are suspicious
    if len(u) > 120:
        return True
    # presence of username@host or suspicious characters
    if "@" in u:
        return True
    # many path segments may be suspicious
    if u.count("/") > 4:
        return True
    for w in suspicious_words:
        if w in u:
            return True
    return False

# ----------------------------
# OpenAI-based detector (optional)
# ----------------------------
def openai_check(url: str) -> tuple[bool, str]:
    """
    Returns (is_phishing:bool, raw_text:str)
    - Uses OpenAI if key and module are available, otherwise raises/returns None.
    """
    if not OPENAI_API_KEY or not openai:
        raise RuntimeError("OpenAI not configured")
    try:
        # small, cheap prompt — keep tokens low for hackathon/demo
        resp = openai.Completion.create(
            model="text-davinci-003",
            prompt=f"Classify this URL as either 'phishing' or 'safe'. Reply with one word only.\n\nURL: {url}\n\nAnswer:",
            max_tokens=5,
            temperature=0
        )
        text = resp.choices[0].text.strip().lower()
        is_phish = "phish" in text
        return is_phish, text
    except Exception as e:
        # bubble up or allow caller to fallback
        raise

# ----------------------------
# Routes
# ----------------------------
@app.route("/")
def home():
    return jsonify({"status": "ok", "message": "Phishing Detector API running"})

@app.route("/check-url", methods=["POST"])
def check_url():
    body = request.get_json() or {}
    url = body.get("url", "").strip()
    if not url:
        return jsonify({"status": "error", "message": "No URL provided"}), 400

    used_openai = False
    phishing = False
    openai_text = None

    # Try OpenAI first if configured
    if OPENAI_API_KEY and openai:
        try:
            used_openai = True
            phishing, openai_text = openai_check(url)
        except Exception as e:
            # on any OpenAI failure, fallback to rule-based
            print("OpenAI error (falling back to rule):", e)
            used_openai = False
            phishing = rule_check(url)
    else:
        phishing = rule_check(url)

    # Log into blockchain (we log every check for transparency)
    block = create_block({"url": url, "phishing": phishing, "used_openai": used_openai})

    response = {
        "status": "success",
        "url": url,
        "phishing": phishing,
        "used_openai": used_openai,
        "openai_text": openai_text,
        "block_index": block["index"],
        "block_hash": block["hash"]
    }
    return jsonify(response)

@app.route("/blockchain", methods=["GET"])
def blockchain_route():
    chain = get_blockchain()
    return jsonify({"length": len(chain), "chain": chain})

# ----------------------------
# Run (for local dev)
# ----------------------------
if __name__ == "__main__":
    # debug True for local dev only
    app.run(host="0.0.0.0", port=5000, debug=True)
