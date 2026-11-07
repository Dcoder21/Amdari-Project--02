"""SentinelPay KYC API — identity verification service."""
import os
from flask import Flask, jsonify

from app.routes.verify import verify_bp
from app.routes.documents import documents_bp


def create_app():
    app = Flask(__name__)

    app.register_blueprint(verify_bp, url_prefix="/v1/verify")
    app.register_blueprint(documents_bp, url_prefix="/v1/documents")

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "service": "kyc-api"})

    return app


if __name__ == "__main__":
    app = create_app()
    # Fix for V-APP-09: debug mode (Werkzeug's interactive debugger, which
    # can expose source and execute code) is now gated on ENVIRONMENT,
    # not hardcoded on.
    debug_mode = os.environ.get("ENVIRONMENT", "development") == "development"
    app.run(host="0.0.0.0", port=8002, debug=debug_mode)
