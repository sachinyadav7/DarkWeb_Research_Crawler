# auth.py
import sqlite3
import hashlib
import hmac
from functools import wraps
from flask import request, jsonify, g
from config import DATABASE_URL, API_KEY_HEADER, DEFAULT_RATE_LIMIT_PER_MIN

DB_PATH = DATABASE_URL.replace("sqlite:///", "") if DATABASE_URL.startswith("sqlite") else None

def db_connect():
    """Simple sqlite connection helper. Adapt if you move to SQLAlchemy."""
    if DB_PATH:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    raise RuntimeError("Only sqlite DB path supported by this helper. Adapt for your DB.")

def hash_key(plain_key: str) -> str:
    return hashlib.sha256(plain_key.encode('utf-8')).hexdigest()

def get_api_key_record(hashed_key: str):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM api_keys WHERE hashed_key = ? AND active = 1", (hashed_key,))
    row = cur.fetchone()
    conn.close()
    return row

def extract_api_key_from_request():
    # 1) X-Api-Key header
    header_value = request.headers.get(API_KEY_HEADER)
    if header_value:
        return header_value.strip()
    # 2) Authorization: Bearer <key>
    auth = request.headers.get("Authorization", "")
    if auth and auth.lower().startswith("bearer "):
        return auth.split(None, 1)[1].strip()
    # 3) fallback: query param (not recommended)
    key_q = request.args.get("api_key")
    return key_q

def require_api_key(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        key = extract_api_key_from_request()
        if not key:
            return jsonify({"error": "API key required"}), 401

        hashed = hash_key(key)
        record = get_api_key_record(hashed)
        if not record:
            # Do not leak info
            return jsonify({"error": "Invalid or inactive API key"}), 401

        # attach record to flask.g for downstream use (rate limiter)
        g.api_key_record = record
        g.api_key_plain = key  # only store in request context for reference
        return func(*args, **kwargs)
    return wrapper
