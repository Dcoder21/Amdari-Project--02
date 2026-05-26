"""Helpers for signing and verifying internal service-to-service requests."""

import hashlib
import hmac
import os
import time
from functools import wraps

from flask import jsonify, request

INTERNAL_SIGNING_SECRET = os.environ.get("INTERNAL_SIGNING_SECRET")
SIGNATURE_TOLERANCE_SECONDS = int(os.environ.get("SIGNATURE_TOLERANCE_SECONDS", "300"))

if not INTERNAL_SIGNING_SECRET:
    raise RuntimeError("INTERNAL_SIGNING_SECRET must be set")


def _body_hash(body: bytes) -> str:
    return hashlib.sha256(body or b"").hexdigest()


def build_signature(method: str, path: str, timestamp: str, body: bytes) -> str:
    message = "\n".join([
        method.upper(),
        path,
        timestamp,
        _body_hash(body),
    ])

    return hmac.new(
        INTERNAL_SIGNING_SECRET.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_signature(method: str, path: str, timestamp: str, body: bytes, supplied_signature: str) -> bool:
    try:
        request_time = int(timestamp)
    except (TypeError, ValueError):
        return False

    current_time = int(time.time())

    if abs(current_time - request_time) > SIGNATURE_TOLERANCE_SECONDS:
        return False

    expected_signature = build_signature(method, path, timestamp, body)

    return hmac.compare_digest(expected_signature, supplied_signature or "")


def require_internal_signature(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        timestamp = request.headers.get("X-SentinelPay-Timestamp")
        signature = request.headers.get("X-SentinelPay-Signature")

        if not timestamp or not signature:
            return jsonify({"error": "missing internal request signature"}), 401

        valid = verify_signature(
            request.method,
            request.path,
            timestamp,
            request.get_data() or b"",
            signature,
        )

        if not valid:
            return jsonify({"error": "invalid internal request signature"}), 401

        return f(*args, **kwargs)

    return wrapper