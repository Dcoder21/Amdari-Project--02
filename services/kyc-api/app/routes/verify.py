"""Identity verification endpoints."""

import os

import requests
from flask import Blueprint, jsonify, request

from app.audit import audit_log
from app.auth import require_auth
from app.db import get_connection
from app.request_signing import require_internal_signature

verify_bp = Blueprint("verify", __name__)

BVN_LOOKUP_URL = os.environ.get("BVN_LOOKUP_URL", "https://api.mock-cbn.local/bvn")


def _verify_bvn_logic():
    """Shared BVN verification logic for public and internal routes."""
    data = request.get_json() or {}
    bvn = data.get("bvn")
    provider_url = data.get("provider", BVN_LOOKUP_URL)

    if not bvn or len(bvn) != 11:
        audit_log(
            "kyc.bvn.failed",
            actor_id=getattr(request, "current_user_id", None),
            outcome="failed",
            details={"reason": "invalid_bvn"},
        )
        return jsonify({"error": "valid 11-digit BVN required"}), 400

    try:
        resp = requests.post(provider_url, json={"bvn": bvn}, timeout=10)

        audit_log(
            "kyc.bvn.success",
            actor_id=getattr(request, "current_user_id", None),
            outcome="success",
            details={"provider_url": provider_url, "status_code": resp.status_code},
        )

        return jsonify({"status": "ok", "provider_response": resp.text[:2000]})

    except Exception as exc:
        audit_log(
            "kyc.bvn.failed",
            actor_id=getattr(request, "current_user_id", None),
            outcome="failed",
            details={"reason": "provider_error", "error": str(exc)},
        )
        return jsonify({"error": str(exc)}), 500


@verify_bp.route("/bvn", methods=["POST"])
@require_auth
def verify_bvn():
    """Verify a BVN against the upstream lookup service.

    Note: The provider_url behaviour still needs SSRF remediation later.
    """
    return _verify_bvn_logic()


@verify_bp.route("/internal/bvn", methods=["POST"])
@require_auth
@require_internal_signature
def verify_bvn_internal():
    """Internal BVN verification endpoint requiring JWT and signed request."""
    return _verify_bvn_logic()


@verify_bp.route("/lookup", methods=["GET"])
@require_auth
def lookup_kyc():
    bvn = request.args.get("bvn", "")
    nin = request.args.get("nin", "")

    conn = get_connection()
    cur = conn.cursor()

    try:
        if bvn:
            cur.execute("SELECT * FROM kyc_records WHERE bvn = %s", (bvn,))
            lookup_type = "bvn"
        elif nin:
            cur.execute("SELECT * FROM kyc_records WHERE nin = %s", (nin,))
            lookup_type = "nin"
        else:
            audit_log(
                "kyc.lookup.failed",
                actor_id=request.current_user_id,
                outcome="failed",
                details={"reason": "missing_bvn_or_nin"},
            )
            return jsonify({"error": "bvn or nin required"}), 400

        records = cur.fetchall()

        audit_log(
            "kyc.lookup.success",
            actor_id=request.current_user_id,
            outcome="success",
            details={"lookup_type": lookup_type, "record_count": len(records)},
        )

        return jsonify([dict(r) for r in records])

    finally:
        cur.close()
        conn.close()