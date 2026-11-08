"""Webhook registration and callback testing."""
import os
import requests
from flask import Blueprint, request, jsonify

from app.db import get_connection
from app.auth import require_auth
from app.ssrf_guard import is_safe_external_url
from app.audit import log_event

webhooks_bp = Blueprint("webhooks", __name__)

WEBHOOK_TIMEOUT = int(os.environ.get("WEBHOOK_TIMEOUT", "10"))


@webhooks_bp.route("/", methods=["POST"])
@require_auth
def register_webhook():
    """Register a callback URL for transaction events.

    Fix for V-APP-04: the callback URL is now validated at registration
    time too, so an internal/private destination can never be stored for
    later delivery, not just blocked at the point of an immediate fetch.
    """
    data = request.get_json() or {}
    callback_url = data.get("callback_url")
    event_type = data.get("event_type", "transaction.completed")

    if not callback_url:
        return jsonify({"error": "callback_url required"}), 400
    if not is_safe_external_url(callback_url):
        return jsonify({"error": "callback_url must be a public http(s) URL"}), 400

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO webhooks (user_id, callback_url, event_type) VALUES (%s, %s, %s) RETURNING id",
            (request.current_user_id, callback_url, event_type)
        )
        webhook_id = cur.fetchone()["id"]
        conn.commit()

        log_event(
            request.current_user_id, "webhook.register", "webhook", webhook_id,
            {"callback_url": callback_url, "event_type": event_type},
        )
        return jsonify({"id": webhook_id, "callback_url": callback_url}), 201
    finally:
        cur.close()
        conn.close()


@webhooks_bp.route("/test", methods=["POST"])
@require_auth
def test_webhook():
    """Test-fire a webhook by fetching the supplied URL with a sample payload.

    Fix for V-APP-04: the URL's resolved address is now checked against
    private/loopback/link-local/reserved ranges before it is ever fetched —
    this is what would have blocked
    {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
    from reaching the EC2/Fargate instance metadata endpoint.
    """
    data = request.get_json() or {}
    url = data.get("url")

    if not url:
        return jsonify({"error": "url required"}), 400
    if not is_safe_external_url(url):
        return jsonify({"error": "url must be a public http(s) URL"}), 400

    try:
        # allow_redirects=False: a redirect to an internal address would
        # otherwise bypass the pre-fetch check above.
        resp = requests.get(url, timeout=WEBHOOK_TIMEOUT, allow_redirects=False)
        return jsonify({
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:5000]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
