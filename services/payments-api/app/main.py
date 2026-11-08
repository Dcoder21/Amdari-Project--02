"""SentinelPay Payments API — main entrypoint."""
import os
from decimal import Decimal
from flask import Flask, jsonify
from flask.json import JSONEncoder

from app.routes.auth import auth_bp
from app.routes.accounts import accounts_bp
from app.routes.transactions import transactions_bp
from app.routes.wallets import wallets_bp
from app.routes.webhooks import webhooks_bp
from app.routes.admin import admin_bp


class DecimalJSONEncoder(JSONEncoder):
    """Environment-compatibility note (not a security fix): NUMERIC columns
    come back from psycopg2 as Decimal, which Flask 2.0's default encoder
    cannot serialise. Without this every route that returns a balance
    crashes with a 500, regardless of any vulnerability. Route logic and
    authorisation are untouched."""

    def default(self, obj):
        if isinstance(obj, Decimal):
            return str(obj)
        return super().default(obj)


def create_app():
    app = Flask(__name__)
    app.json_encoder = DecimalJSONEncoder
    app.config["JWT_SECRET"] = os.environ.get("JWT_SECRET", "sentinelpay-dev-secret")
    app.config["ENVIRONMENT"] = os.environ.get("ENVIRONMENT", "development")

    app.register_blueprint(auth_bp, url_prefix="/v1/auth")
    app.register_blueprint(accounts_bp, url_prefix="/v1/accounts")
    app.register_blueprint(transactions_bp, url_prefix="/v1/transactions")
    app.register_blueprint(wallets_bp, url_prefix="/v1/wallets")
    app.register_blueprint(webhooks_bp, url_prefix="/v1/webhooks")
    app.register_blueprint(admin_bp, url_prefix="/v1/admin")

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "service": "payments-api"})

    @app.errorhandler(Exception)
    def handle_exception(e):
        """Fix for V-APP-09: the stack trace is now logged server-side
        instead of being returned in the response body. The client gets a
        generic message and a request id it can quote to support, not the
        implementation details that used to come back in 'trace'."""
        app.logger.error("Unhandled exception: %s", e, exc_info=True)
        return jsonify({"error": "internal server error"}), 500

    return app


if __name__ == "__main__":
    app = create_app()
    debug_mode = os.environ.get("ENVIRONMENT", "development") == "development"
    app.run(host="0.0.0.0", port=8001, debug=debug_mode)
