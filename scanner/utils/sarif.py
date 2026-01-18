from __future__ import annotations

from typing import Any, Dict, List
from datetime import datetime, timezone


def _sarif_level(status: str, severity: str) -> str:
    # SARIF levels: none, note, warning, error
    if status == "FAIL":
        return "error"
    if status == "WARN":
        return "warning"
    if status == "PASS":
        return "note"
    return "none"


def _markdown_explain(explain: Dict[str, Any]) -> str:
    if not explain:
        return ""
    parts = []
    for k in ["why", "detect", "fix", "verify", "difficulty"]:
        v = explain.get(k)
        if v:
            parts.append(f"**{k.capitalize()}**: {v}")
    return "\n\n".join(parts)


def findings_to_sarif(findings: List[Dict[str, Any]], *, tool_name: str = "gh-actions-security-scanner", tool_version: str = "0.1.0") -> Dict[str, Any]:
    # Build a minimal SARIF v2.1.0 document compatible with GitHub Code Scanning.
    rules = {}
    results = []

    for f in findings:
        rule_id = f.get("rule_id") or f.get("control_id") or "UNKNOWN"
        control_id = f.get("control_id") or "UNKNOWN"
        status = f.get("status") or "WARN"
        severity = f.get("severity") or "Medium"
        level = _sarif_level(status, severity)

        # Add rule metadata once
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": control_id,
                "shortDescription": {"text": f"{control_id}"},
                "fullDescription": {"text": f"{control_id}"},
                "help": {"text": _markdown_explain(f.get("explain") or {})},
                "properties": {
                    "controlId": control_id,
                },
            }

        file_path = f.get("file_path") or ""
        start_line = f.get("start_line")
        end_line = f.get("end_line")

        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": file_path},
            }
        }
        if isinstance(start_line, int):
            region = {"startLine": start_line}
            if isinstance(end_line, int):
                region["endLine"] = end_line
            location["physicalLocation"]["region"] = region

        message = f.get("message") or ""
        md_explain = _markdown_explain(f.get("explain") or {})
        if md_explain:
            message = f"{message}\n\n{md_explain}"

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "locations": [location],
            "properties": {
                "status": status,
                "severity": severity,
                "controlId": control_id,
                "metadata": f.get("metadata") or {},
            },
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "automationDetails": {
                "id": tool_name,
            },
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }],
        }],
    }
    return sarif
