"""Account lookup and listing endpoints."""

from flask import Blueprint, jsonify, request

from app.audit import audit_log
from app.auth import require_auth
from app.db import get_connection

accounts_bp = Blueprint("accounts", __name__)


@accounts_bp.route("/<int:account_id>", methods=["GET"])
@require_auth
def get_account(account_id):
    """Look up an account by ID with ownership enforcement."""
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            "SELECT id, user_id, account_number, currency, balance, status, created_at "
            "FROM accounts WHERE id = %s AND user_id = %s",
            (account_id, request.current_user_id),
        )

        account = cur.fetchone()

        if not account:
            audit_log(
                "account.lookup.denied",
                actor_id=request.current_user_id,
                target={"account_id": account_id},
                outcome="denied",
                details={"reason": "not_found_or_not_owner"},
            )
            return jsonify({"error": "account not found"}), 404

        audit_log(
            "account.lookup.success",
            actor_id=request.current_user_id,
            target={"account_id": account_id},
            outcome="success",
        )

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
            "SELECT id, account_number, currency, balance, status "
            "FROM accounts WHERE user_id = %s",
            (request.current_user_id,),
        )

        rows = cur.fetchall()

        audit_log(
            "account.list.success",
            actor_id=request.current_user_id,
            outcome="success",
            details={"account_count": len(rows)},
        )

        return jsonify([dict(r) for r in rows])

    finally:
        cur.close()
        conn.close()


@accounts_bp.route("/<int:account_id>/profile", methods=["PUT"])
@require_auth
def update_profile(account_id):
    """Reject unsafe account profile updates.

    The original implementation allowed mass assignment. In the current schema,
    account_number, balance, status, currency, and user_id should not be
    user-editable.
    """
    data = request.get_json() or {}

    if not data:
        return jsonify({"error": "no fields supplied"}), 400

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            "SELECT id FROM accounts WHERE id = %s AND user_id = %s",
            (account_id, request.current_user_id),
        )

        if not cur.fetchone():
            audit_log(
                "account.profile_update.denied",
                actor_id=request.current_user_id,
                target={"account_id": account_id},
                outcome="denied",
                details={"reason": "not_found_or_not_owner"},
            )
            return jsonify({"error": "account not found"}), 404

        audit_log(
            "account.profile_update.rejected",
            actor_id=request.current_user_id,
            target={"account_id": account_id},
            outcome="rejected",
            details={"reason": "no_user_editable_fields", "submitted_fields": list(data.keys())},
        )

        return jsonify({"error": "no account profile fields are user-editable"}), 400

    finally:
        cur.close()
        conn.close()