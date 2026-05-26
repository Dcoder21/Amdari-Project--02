"""Authentication routes: registration, login, and OTP."""

import secrets

from flask import Blueprint, jsonify, request

from app.audit import audit_log
from app.auth import hash_password, issue_token, verify_password
from app.db import get_connection

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["POST"])
def register():
    """Register a new merchant account."""
    data = request.get_json() or {}

    email = data.get("email")
    password = data.get("password")
    full_name = data.get("full_name", "")

    if not email or not password:
        audit_log(
            "auth.register.failed",
            outcome="failed",
            details={"reason": "missing_email_or_password", "email": email},
        )
        return jsonify({"error": "email and password required"}), 400

    # Do not trust client-supplied roles. New self-service users are merchants.
    role = "merchant"

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            "INSERT INTO users (email, password_hash, full_name, role) "
            "VALUES (%s, %s, %s, %s) RETURNING id",
            (email, hash_password(password), full_name, role),
        )

        user_id = cur.fetchone()["id"]
        conn.commit()

        audit_log(
            "auth.register.success",
            actor_id=user_id,
            outcome="success",
            details={"email": email, "role": role},
        )

        return jsonify({"id": user_id, "email": email, "role": role}), 201

    except Exception as exc:
        conn.rollback()

        audit_log(
            "auth.register.failed",
            outcome="failed",
            details={"email": email, "reason": type(exc).__name__},
        )

        raise

    finally:
        cur.close()
        conn.close()


@auth_bp.route("/login", methods=["POST"])
def login():
    """Authenticate a user and issue a JWT."""
    data = request.get_json() or {}

    email = data.get("email")
    password = data.get("password")

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            "SELECT id, password_hash, role, is_active FROM users WHERE email = %s",
            (email,),
        )
        user = cur.fetchone()

        if not user or not verify_password(password, user["password_hash"]):
            audit_log(
                "auth.login.failed",
                outcome="failed",
                details={"email": email, "reason": "invalid_credentials"},
            )
            return jsonify({"error": "invalid credentials"}), 401

        if not user["is_active"]:
            audit_log(
                "auth.login.failed",
                actor_id=user["id"],
                outcome="failed",
                details={"email": email, "reason": "account_suspended"},
            )
            return jsonify({"error": "account suspended"}), 403

        token = issue_token(user["id"], user["role"])

        audit_log(
            "auth.login.success",
            actor_id=user["id"],
            outcome="success",
            details={"email": email, "role": user["role"]},
        )

        return jsonify({"token": token, "user_id": user["id"], "role": user["role"]})

    finally:
        cur.close()
        conn.close()


@auth_bp.route("/otp", methods=["POST"])
def request_otp():
    """Request an OTP code for step-up authentication.

    This still needs rate limiting and real OTP delivery later.
    """
    data = request.get_json() or {}
    phone = data.get("phone")

    otp = str(secrets.randbelow(900000) + 100000)

    audit_log(
        "auth.otp.requested",
        outcome="success",
        details={"phone": phone},
    )

    # Do not print the OTP in production. This is only a placeholder response.
    return jsonify({"status": "sent", "phone": phone})