import os
import json
import time
import requests
from flask import Flask, request, jsonify
from danger_ffjwt import (
    guest_to_jwt,
    access_to_jwt,
    eat_to_jwt,
    decode_jwt,
    inspect_access_token
)

app = Flask(__name__)

# Developer credit
DEV_CREDIT = "@mahfuj_offcial_143"

# ---------- Version fetching with simple TTL cache ----------
_versions_cache = {
    "ob_version": "OB52",
    "client_version": "1.123.2",
    "last_fetch": 0
}

def get_versions():
    """Fetch latest OB & client versions from GitHub, cache for 1 hour."""
    global _versions_cache
    now = time.time()
    # Agar cache 1 ghante se purana hai to refresh karo
    if now - _versions_cache["last_fetch"] > 3600:
        try:
            resp = requests.get(
                "https://raw.githubusercontent.com/vkboyx77/JWT_VK/refs/heads/main/versions.json",
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                _versions_cache["ob_version"] = data.get("ob_version", "OB52")
                _versions_cache["client_version"] = data.get("client_version", "1.123.2")
                _versions_cache["last_fetch"] = now
        except Exception:
            # Fetch fail – purana hi rakho ya default
            pass
    return _versions_cache["ob_version"], _versions_cache["client_version"]

# ---------- Helper to add dev credit in response headers ----------
def add_dev_headers(response):
    response.headers["X-Developer"] = DEV_CREDIT
    return response

# ---------- Routes ----------
@app.route('/token', methods=['GET'])
def token_converter():
    ob_ver, client_ver = get_versions()
    args = request.args

    try:
        # 1. UID + Password
        if 'uid' in args and 'password' in args:
            uid = args.get('uid').strip()
            pwd = args.get('password').strip()
            if not uid or not pwd:
                return add_dev_headers(jsonify({"success": False, "error": "UID and password required"}))
            result = guest_to_jwt(uid, pwd, ob_version=ob_ver, client_version=client_ver)

        # 2. EAT token
        elif 'eat' in args:
            eat = args.get('eat').strip()
            if not eat:
                return add_dev_headers(jsonify({"success": False, "error": "EAT token required"}))
            result = eat_to_jwt(eat, ob_version=ob_ver, client_version=client_ver)

        # 3. Access token
        elif 'access' in args:
            access = args.get('access').strip()
            if not access:
                return add_dev_headers(jsonify({"success": False, "error": "Access token required"}))
            result = access_to_jwt(access, ob_version=ob_ver, client_version=client_ver)

        else:
            return add_dev_headers(jsonify({
                "success": False,
                "error": "Missing parameters. Use ?uid&password OR ?eat OR ?access"
            }))

        # Agar result dictionary hai to seedha bhejo
        return add_dev_headers(jsonify(result))

    except Exception as e:
        return add_dev_headers(jsonify({"success": False, "error": str(e)}))

@app.route('/decode', methods=['GET'])
def decode_token():
    args = request.args
    token = args.get('token', '').strip()
    if not token:
        return add_dev_headers(jsonify({"success": False, "error": "Missing token parameter"}))

    try:
        decoded = decode_jwt(token)
        if decoded:
            return add_dev_headers(jsonify({"success": True, "decoded": decoded}))
        else:
            return add_dev_headers(jsonify({"success": False, "error": "Invalid JWT or decode failed"}))
    except Exception as e:
        return add_dev_headers(jsonify({"success": False, "error": str(e)}))

# Optional: inspect endpoint (as extra)
@app.route('/inspect', methods=['GET'])
def inspect_token():
    args = request.args
    token = args.get('access', '').strip()
    if not token:
        return add_dev_headers(jsonify({"success": False, "error": "Missing access token"}))
    try:
        result = inspect_access_token(token)
        if result:
            return add_dev_headers(jsonify({"success": True, "info": result}))
        else:
            return add_dev_headers(jsonify({"success": False, "error": "Invalid token"}))
    except Exception as e:
        return add_dev_headers(jsonify({"success": False, "error": str(e)}))

# ---------- Local test ----------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6600, debug=False)