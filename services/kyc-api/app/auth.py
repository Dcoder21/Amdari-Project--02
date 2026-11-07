"""Shared auth helpers (duplicated from payments-api — known tech debt,
same as before the fix: see payments-api/app/auth.py for the full writeup).

V-APP-02 fix: kyc-api never issues tokens (there is no login endpoint
here), so it is only ever given the RS256 public key — not the private
key payments-api signs with. It can verify a token came from
payments-api; it cannot forge one. That asymmetry is deliberate and is
the "separate compute identities" piece of the case study's Identity &
Secrets Plane constraints.
"""
import base64
import os

import jwt
from functools import wraps
from flask import request, jsonify

ISSUER = "sentinelpay-payments-api"
AUDIENCE = "sentinelpay-services"


def _load_public_key() -> str:
    encoded = os.environ.get("JWT_PUBLIC_KEY_B64")
    if not encoded:
        raise RuntimeError(
            "JWT_PUBLIC_KEY_B64 is not set. Run scripts/generate_dev_jwt_keys.sh for "
            "local development, or confirm the Secrets Manager binding in production."
        )
    return base64.b64decode(encoded).decode("utf-8")


_PUBLIC_KEY = _load_public_key()


def decode_token(token: str) -> dict:
    """Verify a token issued by payments-api. No alg:none, no HS256
    confusion, no unverified signatures — algorithms is pinned to exactly
    one value, and this service holds no key capable of signing one."""
    return jwt.decode(
        token,
        _PUBLIC_KEY,
        algorithms=["RS256"],
        issuer=ISSUER,
        audience=AUDIENCE,
    )


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "unauthorized"}), 401
        try:
            payload = decode_token(auth.replace("Bearer ", ""))
        except jwt.PyJWTError:
            return jsonify({"error": "unauthorized"}), 401
        request.current_user_id = payload.get("user_id")
        request.current_user_role = payload.get("role")
        return f(*args, **kwargs)
    return wrapper
