from __future__ import annotations

from typing import Dict, Any, List
from .ir.parser import parse_workflow_yaml
from .ir.derivation import derive_workflow
from .findings import Finding
from .controls.l1_01_action_pin import L101ActionPin


DEFAULT_POLICY: Dict[str, Any] = {
    "allow_semver_tags": False,
}


def scan_workflow_text(file_path: str, text: str, policy: Dict[str, Any] | None = None) -> List[Finding]:
    pol = dict(DEFAULT_POLICY)
    if policy:
        pol.update(policy)

    wf = parse_workflow_yaml(file_path=file_path, text=text)
    wf = derive_workflow(wf)

    controls = [
        L101ActionPin(),
    ]

    findings: List[Finding] = []
    for c in controls:
        findings.extend(c.evaluate(wf, pol))

    return findings
