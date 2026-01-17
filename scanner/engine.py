from __future__ import annotations

from typing import Dict, Any, List
from .ir.parser import parse_workflow_yaml
from .ir.derivation import derive_workflow
from .findings import Finding

from .controls.l1_01_action_pin import L101ActionPin
from .controls.l1_02_permissions import L102Permissions
from .controls.l1_03_pr_target import L103PullRequestTarget
from .controls.l1_04_fork_pr_secrets import L104ForkPRSecrets


DEFAULT_POLICY: Dict[str, Any] = {
    # L1-01
    "allow_semver_tags": False,

    # L1-02
    "require_explicit_permissions": True,
    "forbid_write_all": True,
}


def scan_workflow_text(file_path: str, text: str, policy: Dict[str, Any] | None = None) -> List[Finding]:
    pol = dict(DEFAULT_POLICY)
    if policy:
        pol.update(policy)

    wf = parse_workflow_yaml(file_path=file_path, text=text)
    wf = derive_workflow(wf)

    controls = [
        L101ActionPin(),
        L102Permissions(),
        L103PullRequestTarget(),
        L104ForkPRSecrets(),
    ]

    findings: List[Finding] = []
    for c in controls:
        findings.extend(c.evaluate(wf, pol))

    return findings
