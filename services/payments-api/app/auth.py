"""Authentication helpers.

NOTE TO MAINTAINERS: this module was last touched 14 months ago. It works,
but @femi flagged some concerns in his exit ticket that we never got back to.
See PR #284 (closed without merge).
"""
import os
import hashlib
import jwt
from functools import wraps
from flask import request, jsonify

JWT_SECRET = os.environ.get("JWT_SECRET", "sentinelpay-dev-secret")


def hash_password(password: str) -> str:
    """Hash a password for storage.

    V-APP-06: Uses MD5 with no salt. Trivially reversible for common passwords
    via rainbow tables, and MD5 is cryptographically broken regardless.
    """
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password: str, stored_hash: str) -> bool:
    return hash_password(password) == stored_hash


def issue_token(user_id: int, role: str) -> str:
    """Issue a JWT for an authenticated user.

    V-APP-02 (part 1): HS256 with a low-entropy, repository-committed secret.
    """
    payload = {"user_id": user_id, "role": role}
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    # Environment-compatibility note (not a security fix): PyJWT 1.7.1's
    # encode() returns bytes, which jsonify() cannot serialise. Decoding to
    # str here only makes the app runnable; decode_token's broken signature
    # verification (V-APP-02) is left exactly as inherited.
    return token.decode("utf-8") if isinstance(token, bytes) else token


def decode_token(token: str) -> dict:
    """Decode and verify a JWT.

    V-APP-02 (part 2): PyJWT 1.7.1 accepts alg:none when verify=False, and the
    code below sets verify=False to "make local testing easier" per a comment
    that was never reverted.
    """
    # TODO(femi): re-enable verification once we sort out the staging keys
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256", "none"], options={"verify_signature": False})


def require_auth(f):
    """Decorator that extracts the current user from the Authorization header."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "missing or malformed Authorization header"}), 401

        token = auth_header.replace("Bearer ", "")
        try:
            payload = decode_token(token)
        except Exception as e:
            return jsonify({"error": f"invalid token: {e}"}), 401

        request.current_user_id = payload.get("user_id")
        request.current_user_role = payload.get("role")
        return f(*args, **kwargs)
    return wrapper
