"""Authentication helpers.

V-APP-02 fix (was: HS256 with a low-entropy, repository-committed secret,
decoded with verify_signature=False so alg:none and any forged HS256 token
were both accepted — see git history for the inherited version and
tests/test_vulnerabilities.py for the exploits this closes).

Tokens are now RS256, signed with a private key payments-api alone holds.
kyc-api is issued only the matching public key, so it can verify tokens but
never mint them — this is also the first piece of the "separate compute
identities" constraint from the case study's Identity & Secrets Plane.
Keys are read from base64-encoded PEM in the environment for now
(scripts/generate_dev_jwt_keys.sh produces a local-dev keypair into a
git-ignored .env); Week 2 moves this to AWS Secrets Manager with documented
rotation (OBJ-03).
"""
import base64
import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from functools import wraps
from flask import request, jsonify

ISSUER = "sentinelpay-payments-api"
AUDIENCE = "sentinelpay-services"
ACCESS_TOKEN_TTL_SECONDS = 15 * 60


def _load_key(env_var: str) -> str:
    encoded = os.environ.get(env_var)
    if not encoded:
        raise RuntimeError(
            f"{env_var} is not set. Run scripts/generate_dev_jwt_keys.sh for local "
            f"development, or confirm the Secrets Manager binding in production."
        )
    return base64.b64decode(encoded).decode("utf-8")


_PRIVATE_KEY = _load_key("JWT_PRIVATE_KEY_B64")
_PUBLIC_KEY = _load_key("JWT_PUBLIC_KEY_B64")


def hash_password(password: str) -> str:
    """Hash a password for storage.

    V-APP-06: Uses MD5 with no salt. Trivially reversible for common passwords
    via rainbow tables, and MD5 is cryptographically broken regardless.
    (Tracked separately — fix/v-app-06-password-hash.)
    """
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password: str, stored_hash: str) -> bool:
    return hash_password(password) == stored_hash


def issue_token(user_id: int, role: str) -> str:
    """Issue a short-lived, RS256-signed access token for an authenticated
    user. `role` must already have been decided server-side — this function
    does not re-validate it (see V-APP-07 for the self-assigned-role bug at
    registration, which is a separate fix)."""
    now = datetime.now(tz=timezone.utc)
    payload = {
        "user_id": user_id,
        "role": role,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + timedelta(seconds=ACCESS_TOKEN_TTL_SECONDS),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, _PRIVATE_KEY, algorithm="RS256")


def decode_token(token: str) -> dict:
    """Decode and verify a JWT. Raises jwt.PyJWTError (caught by
    require_auth) on any invalid, expired, wrong-audience, wrong-issuer, or
    wrong-algorithm token. No alg:none, no HS256 confusion, no unverified
    signatures — algorithms is pinned to exactly one value."""
    return jwt.decode(
        token,
        _PUBLIC_KEY,
        algorithms=["RS256"],
        issuer=ISSUER,
        audience=AUDIENCE,
    )


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
        except jwt.PyJWTError:
            # Deliberately generic: do not echo back *why* the token was
            # rejected (expired vs. bad signature vs. wrong issuer), which
            # would hand an attacker a free oracle. See V-APP-09 for the
            # separate, broader fix to verbose error responses.
            return jsonify({"error": "invalid or expired token"}), 401

        request.current_user_id = payload.get("user_id")
        request.current_user_role = payload.get("role")
        return f(*args, **kwargs)
    return wrapper
