"""Authentication routes: registration, login, and OTP."""
from flask import Blueprint, request, jsonify

from app.db import get_connection
from app.auth import hash_password, verify_password, needs_rehash, issue_token
from app.rate_limit import too_many_requests, is_blocked, record_failure, reset, rate_limited_response

auth_bp = Blueprint("auth", __name__)

REGISTER_LIMIT = 50
REGISTER_WINDOW_SECONDS = 60
LOGIN_LIMIT = 5
LOGIN_WINDOW_SECONDS = 60
OTP_LIMIT = 5
OTP_WINDOW_SECONDS = 60


@auth_bp.route("/register", methods=["POST"])
def register():
    """Register a new merchant account.

    Fix for V-APP-08: rate limited per source IP, so the unique-constraint
    error response can no longer be used to enumerate existing emails at
    unlimited speed.

    Fix for V-APP-07: role is no longer client-supplied. Public self-service
    registration always creates a 'merchant' account; privileged roles
    (admin, finance) are provisioned out-of-band, not through this endpoint.
    """
    if too_many_requests(f"ratelimit:register:{request.remote_addr}", REGISTER_LIMIT, REGISTER_WINDOW_SECONDS):
        return rate_limited_response()

    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    full_name = data.get("full_name", "")
    role = "merchant"

    if not email or not password:
        return jsonify({"error": "email and password required"}), 400

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (email, password_hash, full_name, role) VALUES (%s, %s, %s, %s) RETURNING id",
            (email, hash_password(password), full_name, role)
        )
        user_id = cur.fetchone()["id"]
        conn.commit()
        return jsonify({"id": user_id, "email": email, "role": role}), 201
    finally:
        cur.close()
        conn.close()


@auth_bp.route("/login", methods=["POST"])
def login():
    """Authenticate a user and issue a JWT.

    Fix for V-APP-08: rate limited per target email, counting only failed
    attempts (a successful login resets the counter), so brute forcing a
    specific account's password is no longer unlimited. Keyed by email
    rather than source IP so this can't be bypassed by rotating IPs against
    a single victim account, and so legitimate repeated logins to the same
    account from a shared IP are never penalised.
    """
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    rate_limit_key = f"ratelimit:login:{email}"

    if email and is_blocked(rate_limit_key, LOGIN_LIMIT):
        return rate_limited_response()

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id, password_hash, role, is_active FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        if not user or not verify_password(password, user["password_hash"]):
            if email:
                record_failure(rate_limit_key, LOGIN_WINDOW_SECONDS)
            return jsonify({"error": "invalid credentials"}), 401
        if not user["is_active"]:
            return jsonify({"error": "account suspended"}), 403

        reset(rate_limit_key)

        if needs_rehash(user["password_hash"]):
            # Fix for V-APP-06: transparently upgrade a legacy MD5 hash to
            # the new salted format now that we have the plaintext anyway.
            cur.execute(
                "UPDATE users SET password_hash = %s WHERE id = %s",
                (hash_password(password), user["id"]),
            )
            conn.commit()

        token = issue_token(user["id"], user["role"])
        return jsonify({"token": token, "user_id": user["id"], "role": user["role"]})
    finally:
        cur.close()
        conn.close()


@auth_bp.route("/otp", methods=["POST"])
def request_otp():
    """Request an OTP code for step-up authentication.

    Fix for V-APP-08:
    - Rate limited per phone number, so OTP requests (and their SMS cost)
      can no longer be flooded for a single target.
    - The code is generated with `secrets`, not `random` — `random` is a
      deterministic PRNG and not safe for anything security-sensitive.
    - The code is no longer logged anywhere. There's still no SMS gateway
      wired up in this sample app, so there's nowhere else for it to go yet;
      that's a gap for whenever OTP verification is actually implemented,
      not something this fix can paper over with a fake send.
    """
    import secrets

    data = request.get_json() or {}
    phone = data.get("phone")

    if not phone:
        return jsonify({"error": "phone required"}), 400
    if too_many_requests(f"ratelimit:otp:{phone}", OTP_LIMIT, OTP_WINDOW_SECONDS):
        return rate_limited_response()

    secrets.randbelow(900000) + 100000  # generated, not logged or returned

    return jsonify({"status": "sent", "phone": phone})
