from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from .engine import scan_workflow_text


def _load_policy(policy_path: str | None) -> Dict[str, Any]:
    if not policy_path:
        return {}
    p = Path(policy_path)
    if not p.exists():
        raise FileNotFoundError(f"Policy file not found: {p}")
    # v1: allow JSON policy file (keeps dependencies minimal)
    return json.loads(p.read_text(encoding="utf-8"))


def cmd_scan(args: argparse.Namespace) -> int:
    base = Path(args.path)
    policy = _load_policy(args.policy)

    paths: List[Path] = []
    if base.is_file() and base.suffix in {".yml", ".yaml"}:
        paths = [base]
    else:
        paths = list(base.rglob("*.yml")) + list(base.rglob("*.yaml"))

    all_findings = []
    has_fail = False

    for fp in sorted(set(paths)):
        text = fp.read_text(encoding="utf-8")
        findings = scan_workflow_text(file_path=str(fp), text=text, policy=policy)
        for f in findings:
            d = f.to_dict()
            all_findings.append(d)
            if d["status"] == "FAIL":
                has_fail = True

    print(json.dumps({"findings": all_findings}, indent=2))
    return 2 if has_fail else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scanner", description="GitHub Actions pipeline security scanner (MVP).")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Scan a workflow file or a directory containing workflows.")
    s.add_argument("path", help="Path to workflow file or directory (e.g. .github/workflows).")
    s.add_argument("--policy", help="Path to policy JSON file (optional).", default=None)
    s.set_defaults(func=cmd_scan)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
