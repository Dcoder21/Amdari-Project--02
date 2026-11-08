"""Wallet credit and debit operations."""
import uuid
from decimal import Decimal
from flask import Blueprint, request, jsonify

from app.db import get_connection
from app.auth import require_auth
from app.audit import log_event

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
        # FOR UPDATE locks the row for the rest of this transaction, so a
        # concurrent credit/debit against the same account blocks here
        # until this one commits — closing the same race V-APP-05 fixes.
        cur.execute("SELECT user_id, balance FROM accounts WHERE id = %s FOR UPDATE", (account_id,))
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

        log_event(
            request.current_user_id, "wallet.credit", "account", account_id,
            {"amount": str(amount), "new_balance": str(new_balance), "reference": reference, "description": description},
        )
        return jsonify({"reference": reference, "new_balance": str(new_balance)})
    finally:
        cur.close()
        conn.close()


@wallets_bp.route("/<int:account_id>/debit", methods=["POST"])
@require_auth
def debit_wallet(account_id):
    """Debit funds from a wallet.

    Fix for V-APP-05: the balance read now takes a row lock (SELECT ... FOR
    UPDATE), so a concurrent debit/credit against the same account blocks
    until this transaction commits — the read-check-write is no longer
    split across an unprotected window. Previously two concurrent debits
    could both observe the same pre-balance and each succeed, debiting the
    account below zero or beyond available funds.

    Fix for V-APP-11: a structured audit_log row now records who debited
    what, when, and against which reference, instead of leaving no record
    of money movement at all.

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
        # FOR UPDATE locks the row for the rest of this transaction.
        cur.execute("SELECT user_id, balance FROM accounts WHERE id = %s FOR UPDATE", (account_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "account not found"}), 404
        if row["user_id"] != request.current_user_id and request.current_user_role != "admin":
            return jsonify({"error": "forbidden"}), 403

        current_balance = Decimal(str(row["balance"]))
        if current_balance < amount:
            return jsonify({"error": "insufficient funds"}), 400

        new_balance = current_balance - amount
        cur.execute("UPDATE accounts SET balance = %s WHERE id = %s", (new_balance, account_id))

        reference = f"TXN-{uuid.uuid4().hex[:12].upper()}"
        cur.execute(
            "INSERT INTO transactions (account_id, reference, amount, direction, counterparty, description, status) "
            "VALUES (%s, %s, %s, 'debit', %s, %s, 'completed')",
            (account_id, reference, amount, counterparty, description)
        )
        conn.commit()

        log_event(
            request.current_user_id, "wallet.debit", "account", account_id,
            {"amount": str(amount), "new_balance": str(new_balance), "reference": reference,
             "counterparty": counterparty, "description": description},
        )
        return jsonify({"reference": reference, "new_balance": str(new_balance)})
    finally:
        cur.close()
        conn.close()
