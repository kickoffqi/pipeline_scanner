from __future__ import annotations

from flask import Blueprint, jsonify, request

from scanner.policy.loader import validate_policy, PolicyValidationError

bp = Blueprint("policy", __name__)


@bp.post("/policy/validate")
def policy_validate():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "invalid_json", "message": "JSON body must be an object"}), 400

    try:
        validated = validate_policy(data)
    except PolicyValidationError as e:
        return jsonify({"valid": False, "error": "policy_invalid", "message": str(e)}), 400

    return jsonify({"valid": True, "policy": validated})
