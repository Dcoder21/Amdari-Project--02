"""Fix for V-APP-08: a small fixed-window rate limiter backed by Redis
(already a dependency, previously unused), applied to login, register and
OTP request — the three endpoints the finding named as unlimited.
"""

import redis
from flask import jsonify

from app.config import redis_url

_redis_client = None


def _get_redis():
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(redis_url())
    return _redis_client


def too_many_requests(key: str, limit: int, window_seconds: int) -> bool:
    """Fixed-window counter: increments `key`, setting its expiry on first
    use. Returns True once more than `limit` requests have been seen for
    this key within the current window."""
    client = _get_redis()
    count = client.incr(key)
    if count == 1:
        client.expire(key, window_seconds)
    return count > limit


def is_blocked(key: str, limit: int) -> bool:
    """Read-only check, for callers (like login) that only want to count
    failures rather than every attempt — a legitimate successful login
    shouldn't count against the same limit that stops a brute-force guess
    loop."""
    client = _get_redis()
    count = client.get(key)
    return count is not None and int(count) >= limit


def record_failure(key: str, window_seconds: int) -> None:
    client = _get_redis()
    count = client.incr(key)
    if count == 1:
        client.expire(key, window_seconds)


def reset(key: str) -> None:
    _get_redis().delete(key)


def rate_limited_response():
    return jsonify({"error": "too many requests, try again later"}), 429
