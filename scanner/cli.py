from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

import yaml

from .engine import scan_workflow_text, LEVELS
from .utils.sarif import findings_to_sarif
from .policy.loader import validate_policy, PolicyValidationError


def _load_policy(policy_path: str | None) -> Dict[str, Any]:
    if not policy_path:
        return {}
    p = Path(policy_path)
    if not p.exists():
        raise FileNotFoundError(f"Policy file not found: {p}")

    raw_text = p.read_text(encoding="utf-8")

    if p.suffix.lower() in {".yml", ".yaml"}:
        raw = yaml.safe_load(raw_text) or {}
    elif p.suffix.lower() == ".json":
        raw = json.loads(raw_text) or {}
    else:
        raw = yaml.safe_load(raw_text) or {}

    if not isinstance(raw, dict):
        raise ValueError("Policy file must be a mapping/object at top level.")

    try:
        return validate_policy(raw)
    except PolicyValidationError as e:
        raise ValueError(f"Invalid policy file: {e}") from e


def _collect_workflow_paths(base: Path) -> List[Path]:
    if base.is_file() and base.suffix in {".yml", ".yaml"}:
        return [base]
    return list(base.rglob("*.yml")) + list(base.rglob("*.yaml"))


def _write_output(payload: Dict[str, Any], *, out_path: str | None) -> None:
    text = json.dumps(payload, indent=2)
    if out_path:
        Path(out_path).write_text(text, encoding="utf-8")
    else:
        print(text)


def cmd_scan(args: argparse.Namespace) -> int:
    base = Path(args.path)
    policy = _load_policy(args.policy)

    paths = sorted(set(_collect_workflow_paths(base)))

    all_findings: List[Dict[str, Any]] = []
    has_fail = False

    for fp in paths:
        text = fp.read_text(encoding="utf-8")
        findings = scan_workflow_text(
            file_path=str(fp),
            text=text,
            policy=policy,
            level=args.level,
        )
        for f in findings:
            d = f.to_dict()
            all_findings.append(d)
            if d["status"] == "FAIL":
                has_fail = True

    if args.format == "json":
        payload = {"level": args.level, "findings": all_findings}
        _write_output(payload, out_path=args.out)
    elif args.format == "sarif":
        payload = findings_to_sarif(all_findings, tool_version="0.1.0")
        _write_output(payload, out_path=args.out)
    else:
        raise ValueError(f"Unknown format: {args.format}")

    return 2 if has_fail else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scanner", description="GitHub Actions pipeline security scanner (MVP).")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Scan a workflow file or a directory containing workflows.")
    s.add_argument("path", help="Path to workflow file or directory (e.g. .github/workflows).")
    s.add_argument("--policy", help="Path to policy YAML/JSON file (optional).", default=None)
    s.add_argument("--level", choices=sorted(LEVELS), default="L1", help="Security level to evaluate (L1/L2/L3).")
    s.add_argument("--format", choices=["json", "sarif"], default="json", help="Output format.")
    s.add_argument("--out", default=None, help="Write output to a file instead of stdout.")
    s.set_defaults(func=cmd_scan)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
