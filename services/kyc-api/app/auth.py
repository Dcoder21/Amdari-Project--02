"""Authentication helpers for kyc-api."""

import json
import os
from functools import wraps
from pathlib import Path

import jwt
from flask import jsonify, request

JWT_ALGORITHM = "RS256"
JWT_ISSUER = os.environ.get("JWT_ISSUER", "sentinelpay-payments-api")
JWT_PUBLIC_KEYS_PATH = os.environ.get("JWT_PUBLIC_KEYS_PATH")

if not JWT_PUBLIC_KEYS_PATH:
    raise RuntimeError("JWT_PUBLIC_KEYS_PATH must be set")


def load_public_keys() -> dict:
    """Load public keys used to verify JWTs by key ID."""
    return json.loads(Path(JWT_PUBLIC_KEYS_PATH).read_text())


JWT_PUBLIC_KEYS = load_public_keys()


def decode_token(token: str) -> dict:
    """Decode and verify a JWT issued by the payments API."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise jwt.InvalidTokenError("invalid token header") from exc

    if header.get("alg") != JWT_ALGORITHM:
        raise jwt.InvalidTokenError("unexpected signing algorithm")

    kid = header.get("kid")
    if not kid:
        raise jwt.InvalidTokenError("missing key id")

    public_key = JWT_PUBLIC_KEYS.get(kid)
    if not public_key:
        raise jwt.InvalidTokenError("unknown key id")

    return jwt.decode(
        token,
        public_key,
        algorithms=[JWT_ALGORITHM],
        issuer=JWT_ISSUER,
    )


def require_auth(f):
    """Decorator that extracts the current user from the Authorization header."""

    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "missing or malformed Authorization header"}), 401

        token = auth_header.replace("Bearer ", "", 1)

        try:
            payload = decode_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "invalid token"}), 401

        request.current_user_id = payload.get("user_id")
        request.current_user_role = payload.get("role")

        if not request.current_user_id:
            return jsonify({"error": "invalid token"}), 401

        return f(*args, **kwargs)

    return wrapper