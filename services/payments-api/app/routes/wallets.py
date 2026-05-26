"""Wallet credit and debit operations."""

import uuid
from decimal import Decimal, InvalidOperation

from flask import Blueprint, jsonify, request

from app.audit import audit_log
from app.auth import require_auth
from app.db import get_connection

wallets_bp = Blueprint("wallets", __name__)


def parse_positive_amount(value):
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None

    if not amount.is_finite() or amount <= 0:
        return None

    return amount


@wallets_bp.route("/<int:account_id>/credit", methods=["POST"])
@require_auth
def credit_wallet(account_id):
    """Credit funds to a wallet with ownership check and row locking."""
    data = request.get_json() or {}

    amount = parse_positive_amount(data.get("amount", "0"))
    description = data.get("description", "credit")

    if amount is None:
        audit_log(
            "wallet.credit.failed",
            actor_id=request.current_user_id,
            target={"account_id": account_id},
            outcome="failed",
            details={"reason": "invalid_amount"},
        )
        return jsonify({"error": "amount must be a positive number"}), 400

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute("BEGIN")

        cur.execute(
            "SELECT balance FROM accounts WHERE id = %s AND user_id = %s FOR UPDATE",
            (account_id, request.current_user_id),
        )

        row = cur.fetchone()

        if not row:
            conn.rollback()
            audit_log(
                "wallet.credit.denied",
                actor_id=request.current_user_id,
                target={"account_id": account_id},
                outcome="denied",
                details={"reason": "not_found_or_not_owner"},
            )
            return jsonify({"error": "account not found"}), 404

        new_balance = Decimal(str(row["balance"])) + amount

        cur.execute(
            "UPDATE accounts SET balance = %s WHERE id = %s AND user_id = %s",
            (new_balance, account_id, request.current_user_id),
        )

        reference = f"TXN-{uuid.uuid4().hex[:12].upper()}"

        cur.execute(
            "INSERT INTO transactions "
            "(account_id, reference, amount, direction, description, status) "
            "VALUES (%s, %s, %s, 'credit', %s, 'completed')",
            (account_id, reference, amount, description),
        )

        conn.commit()

        audit_log(
            "wallet.credit.success",
            actor_id=request.current_user_id,
            target={"account_id": account_id, "reference": reference},
            outcome="success",
            details={"amount": str(amount), "new_balance": str(new_balance)},
        )

        return jsonify({"reference": reference, "new_balance": str(new_balance)})

    except Exception as exc:
        conn.rollback()
        audit_log(
            "wallet.credit.failed",
            actor_id=request.current_user_id,
            target={"account_id": account_id},
            outcome="failed",
            details={"reason": type(exc).__name__},
        )
        raise

    finally:
        cur.close()
        conn.close()


@wallets_bp.route("/<int:account_id>/debit", methods=["POST"])
@require_auth
def debit_wallet(account_id):
    """Debit funds from a wallet with ownership check and row locking."""
    data = request.get_json() or {}

    amount = parse_positive_amount(data.get("amount", "0"))
    counterparty = data.get("counterparty", "")
    description = data.get("description", "debit")

    if amount is None:
        audit_log(
            "wallet.debit.failed",
            actor_id=request.current_user_id,
            target={"account_id": account_id},
            outcome="failed",
            details={"reason": "invalid_amount"},
        )
        return jsonify({"error": "amount must be a positive number"}), 400

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute("BEGIN")

        cur.execute(
            "SELECT balance FROM accounts WHERE id = %s AND user_id = %s FOR UPDATE",
            (account_id, request.current_user_id),
        )

        row = cur.fetchone()

        if not row:
            conn.rollback()
            audit_log(
                "wallet.debit.denied",
                actor_id=request.current_user_id,
                target={"account_id": account_id},
                outcome="denied",
                details={"reason": "not_found_or_not_owner"},
            )
            return jsonify({"error": "account not found"}), 404

        current_balance = Decimal(str(row["balance"]))

        if current_balance < amount:
            conn.rollback()
            audit_log(
                "wallet.debit.failed",
                actor_id=request.current_user_id,
                target={"account_id": account_id},
                outcome="failed",
                details={"reason": "insufficient_funds", "amount": str(amount)},
            )
            return jsonify({"error": "insufficient funds"}), 400

        new_balance = current_balance - amount

        cur.execute(
            "UPDATE accounts SET balance = %s WHERE id = %s AND user_id = %s",
            (new_balance, account_id, request.current_user_id),
        )

        reference = f"TXN-{uuid.uuid4().hex[:12].upper()}"

        cur.execute(
            "INSERT INTO transactions "
            "(account_id, reference, amount, direction, counterparty, description, status) "
            "VALUES (%s, %s, %s, 'debit', %s, %s, 'completed')",
            (account_id, reference, amount, counterparty, description),
        )

        conn.commit()

        audit_log(
            "wallet.debit.success",
            actor_id=request.current_user_id,
            target={"account_id": account_id, "reference": reference},
            outcome="success",
            details={"amount": str(amount), "new_balance": str(new_balance)},
        )

        return jsonify({"reference": reference, "new_balance": str(new_balance)})

    except Exception as exc:
        conn.rollback()
        audit_log(
            "wallet.debit.failed",
            actor_id=request.current_user_id,
            target={"account_id": account_id},
            outcome="failed",
            details={"reason": type(exc).__name__},
        )
        raise

    finally:
        cur.close()
        conn.close()