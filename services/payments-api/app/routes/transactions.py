"""Transaction search and listing endpoints."""
from flask import Blueprint, request, jsonify

from app.db import get_connection
from app.auth import require_auth

transactions_bp = Blueprint("transactions", __name__)


@transactions_bp.route("/search", methods=["GET"])
@require_auth
def search_transactions():
    """Search transactions by reference, counterparty, or description.

    Fix for V-APP-01: `q` and `account_id` are now bound as query parameters
    instead of interpolated into the SQL string.
    """
    q = request.args.get("q", "")
    account_id = request.args.get("account_id", "")

    conn = get_connection()
    cur = conn.cursor()
    try:
        like_pattern = f"%{q}%"
        query = (
            "SELECT id, account_id, reference, amount, currency, direction, "
            "counterparty, description, status, created_at "
            "FROM transactions WHERE (reference LIKE %s "
            "OR counterparty LIKE %s OR description LIKE %s)"
        )
        params = [like_pattern, like_pattern, like_pattern]
        if account_id:
            try:
                account_id_int = int(account_id)
            except ValueError:
                return jsonify({"error": "account_id must be an integer"}), 400
            query += " AND account_id = %s"
            params.append(account_id_int)
        query += " ORDER BY created_at DESC LIMIT 50"

        cur.execute(query, params)
        rows = cur.fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        cur.close()
        conn.close()


@transactions_bp.route("/<reference>", methods=["GET"])
@require_auth
def get_transaction(reference):
    """Fetch a single transaction by reference.

    Fix for V-APP-03: ownership (via the transaction's account, or admin
    role) is now required — previously any authenticated caller could fetch
    any transaction by guessing its reference.
    """
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT t.*, a.user_id AS account_user_id "
            "FROM transactions t JOIN accounts a ON a.id = t.account_id "
            "WHERE t.reference = %s",
            (reference,)
        )
        txn = cur.fetchone()
        if not txn:
            return jsonify({"error": "transaction not found"}), 404
        txn = dict(txn)
        account_user_id = txn.pop("account_user_id")
        if account_user_id != request.current_user_id and request.current_user_role != "admin":
            return jsonify({"error": "forbidden"}), 403
        return jsonify(txn)
    finally:
        cur.close()
        conn.close()
