"""Wallet credit and debit operations."""
import uuid
from decimal import Decimal
from flask import Blueprint, request, jsonify

from app.db import get_connection
from app.auth import require_auth

wallets_bp = Blueprint("wallets", __name__)


@wallets_bp.route("/<int:account_id>/credit", methods=["POST"])
@require_auth
def credit_wallet(account_id):
    """Credit funds to a wallet (e.g. inbound transfer settlement).

    Fix for V-APP-03: ownership (or admin role) is now required — previously
    any authenticated caller could credit an arbitrary account_id.
    """
    data = request.get_json() or {}
    amount = Decimal(str(data.get("amount", "0")))
    description = data.get("description", "credit")

    if amount <= 0:
        return jsonify({"error": "amount must be positive"}), 400

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_id, balance FROM accounts WHERE id = %s", (account_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "account not found"}), 404
        if row["user_id"] != request.current_user_id and request.current_user_role != "admin":
            return jsonify({"error": "forbidden"}), 403

        new_balance = Decimal(str(row["balance"])) + amount
        cur.execute("UPDATE accounts SET balance = %s WHERE id = %s", (new_balance, account_id))

        reference = f"TXN-{uuid.uuid4().hex[:12].upper()}"
        cur.execute(
            "INSERT INTO transactions (account_id, reference, amount, direction, description, status) "
            "VALUES (%s, %s, %s, 'credit', %s, 'completed')",
            (account_id, reference, amount, description)
        )
        conn.commit()

        return jsonify({"reference": reference, "new_balance": str(new_balance)})
    finally:
        cur.close()
        conn.close()


@wallets_bp.route("/<int:account_id>/debit", methods=["POST"])
@require_auth
def debit_wallet(account_id):
    """Debit funds from a wallet.

    V-APP-05: Race condition. The read of the current balance and the write
    of the new balance happen in separate statements with no row lock and no
    transactional boundary, so two concurrent debits can both observe the
    same pre-balance and each succeed — allowing the account to be debited
    below zero, or beyond the available funds.

    V-APP-11: No audit log. Money movement is the most sensitive operation
    in the platform, and there is no structured log of who debited what,
    when, from where, and against which idempotency key.

    Fix for V-APP-03: ownership (or admin role) is now required — previously
    any authenticated caller could debit an arbitrary account_id.
    """
    data = request.get_json() or {}
    amount = Decimal(str(data.get("amount", "0")))
    counterparty = data.get("counterparty", "")
    description = data.get("description", "debit")

    if amount <= 0:
        return jsonify({"error": "amount must be positive"}), 400

    conn = get_connection()
    cur = conn.cursor()
    try:
        # Read balance (no lock)
        cur.execute("SELECT user_id, balance FROM accounts WHERE id = %s", (account_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "account not found"}), 404
        if row["user_id"] != request.current_user_id and request.current_user_role != "admin":
            return jsonify({"error": "forbidden"}), 403

        current_balance = Decimal(str(row["balance"]))
        if current_balance < amount:
            return jsonify({"error": "insufficient funds"}), 400

        # Compute new balance in application memory
        new_balance = current_balance - amount

        # Write back — two concurrent debits race here.
        cur.execute("UPDATE accounts SET balance = %s WHERE id = %s", (new_balance, account_id))

        reference = f"TXN-{uuid.uuid4().hex[:12].upper()}"
        cur.execute(
            "INSERT INTO transactions (account_id, reference, amount, direction, counterparty, description, status) "
            "VALUES (%s, %s, %s, 'debit', %s, %s, 'completed')",
            (account_id, reference, amount, counterparty, description)
        )
        conn.commit()

        return jsonify({"reference": reference, "new_balance": str(new_balance)})
    finally:
        cur.close()
        conn.close()
