import os
import json
import time
import hmac
import hashlib
import secrets
import base64
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify

try:
    import psycopg2
    from psycopg2 import pool
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False

app = Flask(__name__)

ADMIN_SECRET = os.environ.get("VYX_ADMIN_SECRET", "vyx_admin_2024")
JWT_SECRET = os.environ.get("VYX_JWT_SECRET", "a3f7c91e8b4d26f0e519abc83d7f624e1b0a95c8d2e4f173b6098a2c5d8e0f34")
DATABASE_URL = os.environ.get("VYX_DATABASE_URL", "")
TOKEN_EXPIRY_DAYS = 36500

_db_pool = None


def get_pool():
    global _db_pool
    if _db_pool is None:
        if not DATABASE_URL:
            raise RuntimeError("VYX_DATABASE_URL environment variable not set")
        _db_pool = pool.SimpleConnectionPool(1, 10, dsn=DATABASE_URL)
    return _db_pool


def get_db():
    return get_pool().getconn()


def put_db(conn):
    get_pool().putconn(conn)


def init_db():
    if not HAS_POSTGRES:
        print("[VyX] WARNING: psycopg2 not installed, database will not persist")
        return
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id SERIAL PRIMARY KEY,
            key_value TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT NOW(),
            is_used BOOLEAN DEFAULT FALSE,
            used_by_hwid TEXT,
            used_at TIMESTAMP
        );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_keys_value ON keys(key_value);")
    conn.commit()
    cur.close()
    put_db(conn)
    print("[VyX] PostgreSQL database initialized")


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
        sig_pad = s + "=" * (4 - len(s) % 4)
        actual = base64.urlsafe_b64decode(sig_pad)
        if not hmac.compare_digest(expected, actual):
            return None
        payload_pad = p + "=" * (4 - len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_pad))
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
    cur = conn.cursor()
    cur.execute("SELECT id, is_used FROM keys WHERE key_value = %s", (key,))
    row = cur.fetchone()

    if not row:
        cur.close()
        put_db(conn)
        return jsonify({"error": "invalid key"}), 403

    if row[1]:
        cur.close()
        put_db(conn)
        return jsonify({"error": "key already used"}), 403

    now = datetime.now(timezone.utc)
    cur.execute(
        "UPDATE keys SET is_used = TRUE, used_by_hwid = %s, used_at = %s WHERE id = %s",
        (hwid, now, row[0])
    )
    conn.commit()
    cur.close()
    put_db(conn)

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
    cur = conn.cursor()
    created = []
    for _ in range(count):
        key = f"VYX-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
        try:
            cur.execute("INSERT INTO keys (key_value) VALUES (%s)", (key,))
            conn.commit()
            created.append(key)
        except Exception:
            conn.rollback()
    cur.close()
    put_db(conn)

    return jsonify({"keys": created, "count": len(created)})


@app.route("/api/admin/list", methods=["GET"])
@require_admin
def admin_list():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT key_value, is_used, used_by_hwid, used_at, created_at FROM keys ORDER BY id DESC"
    )
    rows = cur.fetchall()
    cur.close()
    put_db(conn)

    keys = []
    for r in rows:
        keys.append({
            "key_value": r[0],
            "is_used": r[1],
            "used_by_hwid": r[2],
            "used_at": r[3].isoformat() if r[3] else None,
            "created_at": r[4].isoformat() if r[4] else None,
        })

    return jsonify({
        "keys": keys,
        "total": len(keys),
        "available": sum(1 for r in rows if not r[1]),
        "used": sum(1 for r in rows if r[1]),
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
    cur = conn.cursor()
    cur.execute("DELETE FROM keys WHERE key_value = %s", (key,))
    conn.commit()
    cur.close()
    put_db(conn)

    return jsonify({"ok": True})


@app.route("/api/admin/reset_hwid", methods=["POST"])
@require_admin
def admin_reset_hwid():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid json"}), 400

    key = data.get("key", "").strip()
    if not key:
        return jsonify({"error": "missing key"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE keys SET is_used = FALSE, used_by_hwid = NULL, used_at = NULL WHERE key_value = %s AND is_used = TRUE",
        (key,)
    )
    affected = cur.rowcount
    conn.commit()
    cur.close()
    put_db(conn)

    if affected == 0:
        return jsonify({"error": "key not found or not used"}), 404

    return jsonify({"ok": True, "message": "HWID reset, key can be reused"})


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "database": "postgresql" if HAS_POSTGRES else "none"})


init_db()

if __name__ == "__main__":
    print(f"[VyX] server starting on port 5000")
    print(f"[VyX] admin secret: {ADMIN_SECRET}")
    print(f"[VyX] database: postgresql" if HAS_POSTGRES else "[VyX] database: none (psycopg2 missing)")
    app.run(host="0.0.0.0", port=5000, debug=False)
