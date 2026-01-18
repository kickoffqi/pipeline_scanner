from __future__ import annotations

from typing import Dict, Any, List

from .ir.parser import parse_workflow_yaml
from .ir.derivation import derive_workflow
from .findings import Finding

from .controls.l1_01_action_pin import L101ActionPin
from .controls.l1_02_permissions import L102Permissions
from .controls.l1_03_pr_target import L103PullRequestTarget
from .controls.l1_04_fork_pr_secrets import L104ForkPRSecrets
from .controls.l2_09_azure_oidc import L209AzureOIDC


LEVELS = {"L1", "L2", "L3"}


DEFAULT_POLICY_BY_LEVEL: Dict[str, Dict[str, Any]] = {
    "L1": {
        # L1-01: allow semver tags as WARN (more permissive)
        "allow_semver_tags": True,

        # L1-02
        "require_explicit_permissions": True,
        "forbid_write_all": True,

        # L2-09 defaults are irrelevant at L1 (control not run), but keep safe defaults anyway
        "require_azure_oidc": True,
        "forbid_azure_credentials_secret": True,
        "require_id_token_write": True,
        "forbid_oidc_on_untrusted_triggers": False,
        "trusted_triggers_for_oidc": ["push", "workflow_dispatch", "schedule"],
    },
    "L2": {
        # L1-01: require SHA pinning (stricter)
        "allow_semver_tags": False,

        # L1-02
        "require_explicit_permissions": True,
        "forbid_write_all": True,

        # L2-09: enforce OIDC for Azure
        "require_azure_oidc": True,
        "forbid_azure_credentials_secret": True,
        "require_id_token_write": True,
        "forbid_oidc_on_untrusted_triggers": True,
        "trusted_triggers_for_oidc": ["push", "workflow_dispatch", "schedule"],
    },
    "L3": {
        # L3 reserved; start with L2 strict defaults
        "allow_semver_tags": False,

        "require_explicit_permissions": True,
        "forbid_write_all": True,

        "require_azure_oidc": True,
        "forbid_azure_credentials_secret": True,
        "require_id_token_write": True,
        # L3: strongest posture
        "forbid_oidc_on_untrusted_triggers": True,
        "trusted_triggers_for_oidc": ["push", "workflow_dispatch", "schedule"],
    },
}


def controls_for_level(level: str) -> List[Any]:
    lvl = (level or "L1").upper()
    if lvl not in LEVELS:
        raise ValueError(f"Unknown level: {level}. Expected one of: {sorted(LEVELS)}")

    l1 = [
        L101ActionPin(),
        L102Permissions(),
        L103PullRequestTarget(),
        L104ForkPRSecrets(),
    ]
    l2 = [
        L209AzureOIDC(),
    ]

    if lvl == "L1":
        return l1
    if lvl == "L2":
        return l1 + l2
    return l1 + l2


def policy_for_level(level: str, override: Dict[str, Any] | None = None) -> Dict[str, Any]:
    lvl = (level or "L1").upper()
    if lvl not in LEVELS:
        raise ValueError(f"Unknown level: {level}. Expected one of: {sorted(LEVELS)}")

    pol = dict(DEFAULT_POLICY_BY_LEVEL.get(lvl, {}))
    if override:
        pol.update(override)
    return pol


def scan_workflow_text(
    file_path: str,
    text: str,
    policy: Dict[str, Any] | None = None,
    *,
    level: str = "L1",
) -> List[Finding]:
    pol = policy_for_level(level, policy)

    wf = parse_workflow_yaml(file_path=file_path, text=text)
    wf = derive_workflow(wf)

    controls = controls_for_level(level)

    findings: List[Finding] = []
    for c in controls:
        findings.extend(c.evaluate(wf, pol))

    return findings
