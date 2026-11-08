"""Identity verification endpoints."""
import os
import requests
from flask import Blueprint, request, jsonify

from app.db import get_connection
from app.auth import require_auth
from app.ssrf_guard import is_safe_external_url

verify_bp = Blueprint("verify", __name__)

BVN_LOOKUP_URL = os.environ.get("BVN_LOOKUP_URL", "https://api.mock-cbn.local/bvn")


@verify_bp.route("/bvn", methods=["POST"])
@require_auth
def verify_bvn():
    """Verify a BVN against the upstream lookup service.

    The 'provider' field allows merchants to specify alternative providers
    for regions where the default CBN endpoint isn't applicable.

    Fix for V-APP-04: a client-supplied provider override is now validated
    against private/loopback/link-local/reserved destinations before being
    fetched. The operator-configured default (BVN_LOOKUP_URL) is trusted
    config, not user input, so it is not subject to the same check.
    """
    data = request.get_json() or {}
    bvn = data.get("bvn")
    provider_url = data.get("provider")

    if not bvn or len(bvn) != 11:
        return jsonify({"error": "valid 11-digit BVN required"}), 400

    if provider_url:
        if not is_safe_external_url(provider_url):
            return jsonify({"error": "provider must be a public http(s) URL"}), 400
    else:
        provider_url = BVN_LOOKUP_URL

    try:
        resp = requests.post(provider_url, json={"bvn": bvn}, timeout=10, allow_redirects=False)
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
