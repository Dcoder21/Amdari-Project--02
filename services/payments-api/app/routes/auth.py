"""Authentication routes: registration, login, and OTP."""
from flask import Blueprint, request, jsonify

from app.db import get_connection
from app.auth import hash_password, verify_password, issue_token

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["POST"])
def register():
    """Register a new merchant account.

    V-APP-08: No rate limiting. Anyone can hammer this endpoint to enumerate
    existing emails (via the unique-constraint error response).

    Fix for V-APP-07: role is no longer client-supplied. Public self-service
    registration always creates a 'merchant' account; privileged roles
    (admin, finance) are provisioned out-of-band, not through this endpoint.
    """
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

    V-APP-08: No rate limiting or lockout. Brute force is trivial.
    """
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id, password_hash, role, is_active FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        if not user or not verify_password(password, user["password_hash"]):
            return jsonify({"error": "invalid credentials"}), 401
        if not user["is_active"]:
            return jsonify({"error": "account suspended"}), 403

        token = issue_token(user["id"], user["role"])
        return jsonify({"token": token, "user_id": user["id"], "role": user["role"]})
    finally:
        cur.close()
        conn.close()


@auth_bp.route("/otp", methods=["POST"])
def request_otp():
    """Request an OTP code for step-up authentication.

    V-APP-08: No rate limiting. Plus the OTP is logged below for "debugging".
    """
    import random
    data = request.get_json() or {}
    phone = data.get("phone")

    otp = str(random.randint(100000, 999999))
    # TODO: remove debug logging before production
    print(f"[OTP DEBUG] Generated OTP {otp} for {phone}")

    return jsonify({"status": "sent", "phone": phone})
