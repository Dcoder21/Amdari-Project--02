"""Identity verification endpoints."""
import os
import requests
from flask import Blueprint, request, jsonify

from app.db import get_connection
from app.auth import require_auth

verify_bp = Blueprint("verify", __name__)

BVN_LOOKUP_URL = os.environ.get("BVN_LOOKUP_URL", "https://api.mock-cbn.local/bvn")


@verify_bp.route("/bvn", methods=["POST"])
@require_auth
def verify_bvn():
    """Verify a BVN against the upstream lookup service.

    The 'provider' field allows merchants to specify alternative providers
    for regions where the default CBN endpoint isn't applicable.
    SSRF variant: an attacker controls the URL the server fetches.
    """
    data = request.get_json() or {}
    bvn = data.get("bvn")
    provider_url = data.get("provider", BVN_LOOKUP_URL)

    if not bvn or len(bvn) != 11:
        return jsonify({"error": "valid 11-digit BVN required"}), 400

    try:
        resp = requests.post(provider_url, json={"bvn": bvn}, timeout=10)
        return jsonify({"status": "ok", "provider_response": resp.text[:2000]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@verify_bp.route("/lookup", methods=["GET"])
@require_auth
def lookup_kyc():
    """Look up a KYC record by BVN or NIN.

    Fix for V-APP-01 (kyc-api variant): the filter value is now bound as a
    query parameter instead of interpolated into the SQL string.
    """
    bvn = request.args.get("bvn", "")
    nin = request.args.get("nin", "")

    conn = get_connection()
    cur = conn.cursor()
    try:
        if bvn:
            query = "SELECT * FROM kyc_records WHERE bvn = %s"
            params = (bvn,)
        elif nin:
            query = "SELECT * FROM kyc_records WHERE nin = %s"
            params = (nin,)
        else:
            return jsonify({"error": "bvn or nin required"}), 400

        cur.execute(query, params)
        records = cur.fetchall()
        return jsonify([dict(r) for r in records])
    finally:
        cur.close()
        conn.close()
