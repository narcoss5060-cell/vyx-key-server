import os
import json
import time
import hmac
import hashlib
import secrets
import base64
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify

app = Flask(__name__)

ADMIN_SECRET = os.environ.get("VYX_ADMIN_SECRET", "vyx_admin_2024")
JWT_SECRET = os.environ.get("VYX_JWT_SECRET", secrets.token_hex(32))
DB_PATH = os.environ.get("VYX_DB_PATH", "vyx_keys.db")
TOKEN_EXPIRY_DAYS = int(os.environ.get("VYX_TOKEN_EXPIRY_DAYS", "30"))


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_value TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            is_used INTEGER NOT NULL DEFAULT 0,
            used_by_hwid TEXT,
            used_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_keys_value ON keys(key_value);
    """)
    conn.commit()
    conn.close()


def jwt_create(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    def b64url(data):
        return base64.urlsafe_b64encode(json.dumps(data, separators=(',', ':')).encode()).rstrip(b'=').decode()
    def b64url_bytes(data):
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
    h = b64url(header)
    p = b64url(payload)
    sig_input = f"{h}.{p}".encode()
    sig = hmac.new(JWT_SECRET.encode(), sig_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_bytes(sig)}"


def jwt_verify(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        h, p, s = parts
        sig_input = f"{h}.{p}".encode()
        expected = hmac.new(JWT_SECRET.encode(), sig_input, hashlib.sha256).digest()
        sig_bytes = base64.urlsafe_b64encode(s.encode() + b"==")
        actual = base64.urlsafe_b64decode(sig_bytes)
        if not hmac.compare_digest(expected, actual):
            return None
        padding = 4 - len(p) % 4
        p_padded = p + "=" * padding
        return json.loads(base64.urlsafe_b64decode(p_padded))
    except Exception:
        return None


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] != ADMIN_SECRET:
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


@app.route("/api/redeem", methods=["POST"])
def redeem():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid json"}), 400

    key = data.get("key", "").strip()
    hwid = data.get("hwid", "").strip()

    if not key or not hwid:
        return jsonify({"error": "missing key or hwid"}), 400

    conn = get_db()
    row = conn.execute("SELECT id, is_used FROM keys WHERE key_value = ?", (key,)).fetchone()

    if not row:
        conn.close()
        return jsonify({"error": "invalid key"}), 403

    if row["is_used"]:
        conn.close()
        return jsonify({"error": "key already used"}), 403

    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE keys SET is_used = 1, used_by_hwid = ?, used_at = ? WHERE id = ?",
        (hwid, now, row["id"])
    )
    conn.commit()
    conn.close()

    exp = datetime.now(timezone.utc) + timedelta(days=TOKEN_EXPIRY_DAYS)
    token = jwt_create({
        "hwid": hwid,
        "iat": int(time.time()),
        "exp": int(exp.timestamp()),
    })

    return jsonify({"token": token, "expires": exp.isoformat()})


@app.route("/api/validate", methods=["POST"])
def validate():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid json"}), 400

    token = data.get("token", "").strip()
    hwid = data.get("hwid", "").strip()

    if not token or not hwid:
        return jsonify({"error": "missing token or hwid"}), 400

    payload = jwt_verify(token)
    if not payload:
        return jsonify({"error": "invalid token"}), 403

    if payload.get("hwid") != hwid:
        return jsonify({"error": "hwid mismatch"}), 403

    exp = payload.get("exp", 0)
    if int(time.time()) > exp:
        return jsonify({"error": "token expired"}), 403

    return jsonify({"ok": True, "expires": datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()})


@app.route("/api/admin/create", methods=["POST"])
@require_admin
def admin_create():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid json"}), 400

    count = data.get("count", 1)
    if not isinstance(count, int) or count < 1 or count > 100:
        return jsonify({"error": "count must be 1-100"}), 400

    conn = get_db()
    created = []
    for _ in range(count):
        key = f"VYX-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
        try:
            conn.execute("INSERT INTO keys (key_value) VALUES (?)", (key,))
            created.append(key)
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()

    return jsonify({"keys": created, "count": len(created)})


@app.route("/api/admin/list", methods=["GET"])
@require_admin
def admin_list():
    conn = get_db()
    rows = conn.execute(
        "SELECT key_value, is_used, used_by_hwid, used_at, created_at FROM keys ORDER BY id DESC"
    ).fetchall()
    conn.close()

    return jsonify({
        "keys": [dict(r) for r in rows],
        "total": len(rows),
        "available": sum(1 for r in rows if not r["is_used"]),
        "used": sum(1 for r in rows if r["is_used"]),
    })


@app.route("/api/admin/revoke", methods=["POST"])
@require_admin
def admin_revoke():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid json"}), 400

    key = data.get("key", "").strip()
    if not key:
        return jsonify({"error": "missing key"}), 400

    conn = get_db()
    conn.execute("DELETE FROM keys WHERE key_value = ?", (key,))
    conn.commit()
    conn.close()

    return jsonify({"ok": True})


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    init_db()
    print(f"[VyX] server starting on port 5000")
    print(f"[VyX] admin secret: {ADMIN_SECRET}")
    app.run(host="0.0.0.0", port=5000, debug=False)
