# rate_limiter.py
import time
from functools import wraps
from flask import jsonify, g, request, current_app
from config import REDIS_URL, DEFAULT_RATE_LIMIT_PER_MIN
import os

# Try to import redis; if not present or REDIS_URL not configured, use in-memory fallback
USE_REDIS = bool(REDIS_URL)
redis_client = None
if USE_REDIS:
    try:
        import redis
        redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    except Exception as e:
        redis_client = None
        USE_REDIS = False

# Simple in-memory store: { key: [timestamps...] }
_in_memory_store = {}

def _get_limit_from_record():
    """Return allowed count per minute for this API key (from g.api_key_record)"""
    try:
        rec = getattr(g, "api_key_record", None)
        if rec and "rate_limit_per_min" in rec.keys():
            return int(rec["rate_limit_per_min"])
    except Exception:
        pass
    return DEFAULT_RATE_LIMIT_PER_MIN

def _redis_check_and_increment(api_key_id: str, period_seconds=60):
    """
    Use Redis INCR with expiry to maintain a counter per (api_key_id, endpoint, minute window).
    """
    # key includes endpoint path so different endpoints have separate limits if desired
    endpoint = request.path
    # Use minute window aligned to epoch floor to reduce key churn
    window = int(time.time() // period_seconds)
    redis_key = f"rl:{api_key_id}:{endpoint}:{window}"
    # INCR and set TTL only when new
    value = redis_client.incr(redis_key)
    if value == 1:
        redis_client.expire(redis_key, period_seconds + 2)
    return int(value)

def _memory_check_and_increment(api_key_id: str, period_seconds=60):
    now = time.time()
    window_start = now - period_seconds
    key = f"{api_key_id}:{request.path}"
    lst = _in_memory_store.get(key)
    if lst is None:
        lst = []
        _in_memory_store[key] = lst
    # prune old timestamps
    while lst and lst[0] < window_start:
        lst.pop(0)
    lst.append(now)
    count = len(lst)
    return count

def rate_limited(func):
    """Decorator to enforce rate limit using either Redis or in-memory fallback."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not hasattr(g, "api_key_record") or g.api_key_record is None:
            # ensure auth decorator runs first in intended usage
            return jsonify({"error": "API key context missing"}), 401

        api_key_id = str(g.api_key_record["id"])
        limit = _get_limit_from_record()

        # choose Redis if available
        if USE_REDIS and redis_client:
            try:
                current_count = _redis_check_and_increment(api_key_id, 60)
            except Exception as e:
                # Redis error -> fallback to memory
                current_count = _memory_check_and_increment(api_key_id, 60)
        else:
            current_count = _memory_check_and_increment(api_key_id, 60)

        if current_count > limit:
            # optional: include retry-after header
            retry_after = 60  # seconds until next minute window; could be refined
            resp = jsonify({"error": "rate_limit_exceeded", "retry_after_seconds": retry_after})
            return resp, 429
        return func(*args, **kwargs)
    return wrapper

def require_api_key_and_rate_limit(func):
    """Convenience: require auth and apply rate limit."""
    from auth import require_api_key
    @require_api_key
    @wraps(func)
    def wrapper(*args, **kwargs):
        # now g.api_key_record is set
        return rate_limited(func)(*args, **kwargs)
    return wrapper
