from __future__ import annotations

from typing import Any, Dict, List, Optional, Set
import json

from flask import Blueprint, jsonify, request

from scanner.engine import scan_workflow_text, LEVELS
from scanner.policy.loader import validate_policy, PolicyValidationError


bp = Blueprint("scan", __name__, url_prefix="/api")


def _coerce_status_set(value: Any) -> Optional[Set[str]]:
    """Normalize a user-provided status filter to an uppercase set.

    Accepts:
      - list[str] e.g. ["FAIL","WARN"]
      - comma-separated string e.g. "fail,warn"
    """
    if value is None:
        return None
    if isinstance(value, str):
        parts = [p.strip().upper() for p in value.split(",") if p.strip()]
        return set(parts) if parts else None
    if isinstance(value, list):
        parts: List[str] = []
        for x in value:
            if isinstance(x, str):
                parts.append(x.strip().upper())
        return set([p for p in parts if p]) if parts else None
    return None


def _filter_findings(findings: List[Dict[str, Any]], only_status: Optional[Set[str]]) -> List[Dict[str, Any]]:
    if not only_status:
        return findings
    return [f for f in findings if str(f.get("status", "")).upper() in only_status]


def _validate_level(level_raw: Any) -> tuple[Optional[str], Optional[tuple[Dict[str, Any], int]]]:
    if level_raw is None:
        return "L1", None
    if not isinstance(level_raw, str):
        return None, ({"error": "invalid_request", "message": "`level` must be a string."}, 400)
    level = level_raw.strip().upper()
    if level not in LEVELS:
        return None, ({"error": "invalid_request", "message": f"Unsupported level '{level}'. Valid: {sorted(LEVELS)}"}, 400)
    return level, None


def _validate_policy(policy_raw: Any) -> tuple[Optional[Dict[str, Any]], Optional[tuple[Dict[str, Any], int]]]:
    if policy_raw is None:
        policy_raw = {}
    if not isinstance(policy_raw, dict):
        return None, ({"error": "invalid_request", "message": "`policy` must be an object if provided."}, 400)
    try:
        policy = validate_policy(policy_raw)
    except PolicyValidationError as e:
        return None, ({"error": "policy_invalid", "message": str(e)}, 400)
    return policy, None


@bp.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "GET":
        # Developer-friendly help payload to avoid 405 confusion.
        return jsonify({
            "endpoints": {
                "/api/scan": {
                    "methods": ["POST"],
                    "content_type": "application/json",
                },
                "/api/scan/file": {
                    "methods": ["POST"],
                    "content_type": "multipart/form-data",
                },
            },
            "scan_body_schema": {
                "level": "L1|L2|L3 (default: L1)",
                "file_path": "string (optional)",
                "workflow": "string (required) - GitHub Actions YAML text",
                "policy": "object (optional) - policy override",
                "only_status": ["FAIL", "WARN", "PASS", "SKIP"],
            },
            "scan_example_curl": (
                "curl -s -X POST http://localhost:5001/api/scan \\n"
                "  -H \"Content-Type: application/json\" \\n"
                "  -d '{\"level\":\"L1\",\"file_path\":\"ci.yml\",\"workflow\":\"name: CI\\non: [push]\\n...\"}'"
            ),
            "scan_file_example_curl": (
                "curl -s -X POST http://localhost:5001/api/scan/file \\\n"
                "  -F level=L1 \\\n"
                "  -F only_status=fail,warn \\\n"
                "  -F file=@.github/workflows/ci.yml | jq"
            ),
        }), 200

    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "invalid_request", "message": "JSON body must be an object."}), 400

    level, err = _validate_level(payload.get("level", "L1"))
    if err:
        body, code = err
        return jsonify(body), code
    assert level is not None

    file_path = payload.get("file_path", "workflow.yml")
    if not isinstance(file_path, str):
        return jsonify({"error": "invalid_request", "message": "`file_path` must be a string."}), 400

    workflow = payload.get("workflow")
    if not isinstance(workflow, str) or not workflow.strip():
        return jsonify({"error": "invalid_request", "message": "`workflow` must be a non-empty string containing YAML text."}), 400

    policy, err = _validate_policy(payload.get("policy", {}))
    if err:
        body, code = err
        return jsonify(body), code
    assert policy is not None

    only_status = _coerce_status_set(payload.get("only_status"))

    findings = scan_workflow_text(
        file_path=file_path,
        text=workflow,
        policy=policy,
        level=level,
    )

    findings_dict = _filter_findings([f.to_dict() for f in findings], only_status)

    return jsonify({
        "level": level,
        "findings": findings_dict,
    }), 200


@bp.route("/scan/file", methods=["POST"])
def scan_file():
    """Scan a workflow uploaded as multipart/form-data.

    Form fields:
      - file: required (YAML file)
      - level: optional (L1|L2|L3), default L1
      - only_status: optional ("fail,warn" or "FAIL,WARN")
      - file_path: optional (override the returned file_path; defaults to uploaded filename)
      - policy: optional (JSON string of policy override)
    """
    upload = request.files.get("file")
    if upload is None:
        return jsonify({"error": "invalid_request", "message": "Missing form field `file`."}), 400

    try:
        raw = upload.read()
    except Exception:
        return jsonify({"error": "invalid_request", "message": "Failed to read uploaded file."}), 400

    try:
        workflow = raw.decode("utf-8")
    except UnicodeDecodeError:
        workflow = raw.decode("latin-1")

    if not workflow.strip():
        return jsonify({"error": "invalid_request", "message": "Uploaded file is empty."}), 400

    level, err = _validate_level(request.form.get("level", "L1"))
    if err:
        body, code = err
        return jsonify(body), code
    assert level is not None

    file_path = request.form.get("file_path") or (upload.filename or "workflow.yml")
    if not isinstance(file_path, str) or not file_path.strip():
        file_path = upload.filename or "workflow.yml"

    only_status = _coerce_status_set(request.form.get("only_status"))

    policy_raw: Dict[str, Any] = {}
    policy_str = request.form.get("policy")
    if policy_str:
        try:
            parsed = json.loads(policy_str)
        except json.JSONDecodeError as e:
            return jsonify({"error": "invalid_request", "message": f"`policy` must be valid JSON: {e}"}), 400
        if not isinstance(parsed, dict):
            return jsonify({"error": "invalid_request", "message": "`policy` JSON must be an object."}), 400
        policy_raw = parsed

    policy, err = _validate_policy(policy_raw)
    if err:
        body, code = err
        return jsonify(body), code
    assert policy is not None

    findings = scan_workflow_text(
        file_path=file_path,
        text=workflow,
        policy=policy,
        level=level,
    )

    findings_dict = _filter_findings([f.to_dict() for f in findings], only_status)

    return jsonify({
        "level": level,
        "file_path": file_path,
        "findings": findings_dict,
    }), 200
