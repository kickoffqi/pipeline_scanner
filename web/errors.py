from __future__ import annotations

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException


def register_error_handlers(app: Flask) -> None:
    """Return JSON errors instead of HTML (especially important in production)."""

    @app.errorhandler(HTTPException)
    def handle_http_exception(e: HTTPException):
        payload = {
            "error": "http_error",
            "message": e.description,
            "status_code": e.code,
            "path": request.path,
            "method": request.method,
        }
        return jsonify(payload), e.code or 500

    @app.errorhandler(Exception)
    def handle_unexpected_exception(e: Exception):
        # Do not leak traceback details to clients.
        payload = {
            "error": "internal_error",
            "message": "An unexpected error occurred.",
            "path": request.path,
            "method": request.method,
        }
        return jsonify(payload), 500
