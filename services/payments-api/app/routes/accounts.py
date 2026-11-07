"""Account lookup and listing endpoints."""
from flask import Blueprint, request, jsonify

from app.db import get_connection
from app.auth import require_auth

accounts_bp = Blueprint("accounts", __name__)


@accounts_bp.route("/<int:account_id>", methods=["GET"])
@require_auth
def get_account(account_id):
    """Look up an account by ID.

    Fix for V-APP-03: ownership (or admin role) is now required. Previously
    any authenticated user could read any account by guessing or enumerating
    IDs — the finding the researcher publicly disclosed on 14 April 2026.
    """
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT id, user_id, account_number, currency, balance, status, created_at "
            "FROM accounts WHERE id = %s",
            (account_id,)
        )
        account = cur.fetchone()
        if not account:
            return jsonify({"error": "account not found"}), 404
        if account["user_id"] != request.current_user_id and request.current_user_role != "admin":
            return jsonify({"error": "forbidden"}), 403
        return jsonify(dict(account))
    finally:
        cur.close()
        conn.close()


@accounts_bp.route("/", methods=["GET"])
@require_auth
def list_accounts():
    """List accounts belonging to the current user."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT id, account_number, currency, balance, status FROM accounts WHERE user_id = %s",
            (request.current_user_id,)
        )
        rows = cur.fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        cur.close()
        conn.close()


@accounts_bp.route("/<int:account_id>/profile", methods=["PUT"])
@require_auth
def update_profile(account_id):
    """Update account profile fields.

    V-APP-07: Mass assignment. The update accepts an arbitrary dict and writes
    every key the client provides, including 'status', 'user_id', and 'balance'.
    A merchant can transfer an account to themselves or set their balance.
    """
    data = request.get_json() or {}
    conn = get_connection()
    cur = conn.cursor()
    try:
        # Build dynamic SET clause from whatever the client sent
        if not data:
            return jsonify({"error": "no fields supplied"}), 400

        set_clause = ", ".join([f"{k} = %s" for k in data.keys()])
        values = list(data.values()) + [account_id]
        # Note: this is intentionally a parameterised query for the *values*,
        # but the column names are concatenated from user input — see V-APP-07.
        # SQLi on column names is not the bug here; mass assignment is.
        cur.execute(f"UPDATE accounts SET {set_clause} WHERE id = %s RETURNING *", values)
        updated = cur.fetchone()
        conn.commit()
        return jsonify(dict(updated))
    finally:
        cur.close()
        conn.close()
