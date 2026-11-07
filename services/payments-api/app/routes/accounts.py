"""Account lookup and listing endpoints."""
from flask import Blueprint, request, jsonify

from app.db import get_connection
from app.auth import require_auth
from app.audit import log_event

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


# Only these columns may ever be set via this endpoint. 'user_id', 'balance'
# and 'status' are deliberately excluded: they must never be client-writable
# (ownership, funds and account state are changed only by their own
# dedicated, authorised code paths).
UPDATABLE_PROFILE_FIELDS = {"currency"}


@accounts_bp.route("/<int:account_id>/profile", methods=["PUT"])
@require_auth
def update_profile(account_id):
    """Update account profile fields.

    Fix for V-APP-07: the update now requires ownership (or admin role) and
    only accepts a fixed allow-list of columns, bound as query parameters.
    Previously it wrote every key the client supplied straight into the SQL
    column list (letting a caller set 'user_id', 'balance' or 'status' —
    and, since column names were concatenated rather than parameterised, a
    key containing '=' could inject arbitrary SQL).
    """
    data = request.get_json() or {}
    if not data:
        return jsonify({"error": "no fields supplied"}), 400

    disallowed = set(data.keys()) - UPDATABLE_PROFILE_FIELDS
    if disallowed:
        return jsonify({"error": f"fields not updatable via this endpoint: {sorted(disallowed)}"}), 400

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_id FROM accounts WHERE id = %s", (account_id,))
        account = cur.fetchone()
        if not account:
            return jsonify({"error": "account not found"}), 404
        if account["user_id"] != request.current_user_id and request.current_user_role != "admin":
            return jsonify({"error": "forbidden"}), 403

        set_clause = ", ".join(f"{field} = %s" for field in data.keys())
        values = list(data.values()) + [account_id]
        cur.execute(f"UPDATE accounts SET {set_clause} WHERE id = %s RETURNING *", values)
        updated = cur.fetchone()
        conn.commit()

        log_event(request.current_user_id, "account.profile_update", "account", account_id, dict(data))
        return jsonify(dict(updated))
    finally:
        cur.close()
        conn.close()
