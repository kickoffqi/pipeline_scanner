from __future__ import annotations

import os
from flask import Flask, jsonify

from .routes.health import bp as health_bp
from .routes.scan import bp as scan_bp
from .routes.ui import bp as ui_bp
from .errors import register_error_handlers
from .routes.policy import bp as policy_bp


def create_app() -> Flask:
    app = Flask(__name__)

    # Basic hardening
    max_bytes = int(os.environ.get("MAX_REQUEST_BYTES", str(1 * 1024 * 1024)))  # 1MB default
    app.config["MAX_CONTENT_LENGTH"] = max_bytes

    # Register blueprints
    app.register_blueprint(ui_bp)
    app.register_blueprint(health_bp, url_prefix="/api")
    app.register_blueprint(scan_bp, url_prefix="/api")
    app.register_blueprint(policy_bp, url_prefix="/api")

    @app.errorhandler(413)
    def too_large(_):
        return jsonify({
            "error": "request_too_large",
            "message": f"Request too large. MAX_REQUEST_BYTES={max_bytes}",
        }), 413

    @app.errorhandler(404)
    def not_found(_):
        return jsonify({"error": "not_found"}), 404

    @app.errorhandler(500)
    def internal_error(e):
        debug = os.environ.get("FLASK_DEBUG", "0") == "1"
        return jsonify({
            "error": "internal_error",
            "message": str(e) if debug else "Internal server error",
        }), 500

    return app
