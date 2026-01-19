from __future__ import annotations

from flask import Blueprint, jsonify, request

from scanner.engine import scan_workflow_text, LEVELS
from scanner.policy.loader import validate_policy, PolicyValidationError

bp = Blueprint("scan", __name__)


@bp.post("/scan")
def scan():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "invalid_json", "message": "JSON body must be an object"}), 400

    workflow = data.get("workflow")
    if not isinstance(workflow, str) or not workflow.strip():
        return jsonify({"error": "missing_workflow", "message": "Field `workflow` (string) is required."}), 400

    file_path = data.get("file_path") or "workflow.yml"
    if not isinstance(file_path, str):
        file_path = "workflow.yml"

    level = (data.get("level") or "L1")
    if not isinstance(level, str):
        level = "L1"
    level = level.upper()
    if level not in LEVELS:
        return jsonify({"error": "invalid_level", "message": f"level must be one of {sorted(LEVELS)}"}), 400

    policy_raw = data.get("policy") or {}
    if policy_raw is None:
        policy_raw = {}
    if not isinstance(policy_raw, dict):
        return jsonify({"error": "invalid_policy", "message": "policy must be an object"}), 400

    try:
        policy = validate_policy(policy_raw)
    except PolicyValidationError as e:
        return jsonify({"error": "policy_invalid", "message": str(e)}), 400

    findings = scan_workflow_text(
        file_path=file_path,
        text=workflow,
        policy=policy,
        level=level,
    )

    return jsonify({
        "level": level,
        "findings": [f.to_dict() for f in findings],
    })
