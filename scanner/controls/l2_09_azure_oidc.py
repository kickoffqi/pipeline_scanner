from __future__ import annotations

from typing import Dict, Any, List
import re

from .base import Control
from ..findings import Finding
from ..ir.models import WorkflowIR, JobIR
from ..utils.explain import explain_pack

AZ_CLI_RE = re.compile(r"\baz\s+(login|account|deployment|keyvault|aks|acr)\b", re.IGNORECASE)


def _is_azure_job(job: JobIR) -> bool:
    if "azure_login" in job.derived.dangerous_patterns:
        return True
    if "azure_cli" in job.derived.dangerous_patterns:
        return True
    for s in job.steps:
        if s.kind == "run" and s.run is not None and AZ_CLI_RE.search(s.run.command or ""):
            return True
    return False


def _has_secret_based_azure_auth(job: JobIR) -> bool:
    if "azure_secret_auth" in job.derived.dangerous_patterns:
        return True
    for s in job.steps:
        if any(k.upper() in {"AZURE_CREDENTIALS", "AZURE_CLIENT_SECRET", "AZURE_SECRET"} for k in s.env_keys):
            return True
        if s.kind == "uses" and s.uses is not None and (s.uses.owner_repo or "").lower() == "azure/login":
            if any(k.lower() in {"creds", "client-secret", "client_secret", "password", "secret"} for k in s.with_keys):
                return True
    return False


def _has_excessive_write_perms(job: JobIR) -> bool:
    eff = job.derived.effective_permissions or {}
    if eff.get("__all__") == "write":
        return True
    if eff.get("contents") == "write":
        return True
    return False


class L209AzureOIDC(Control):
    control_id = "L2-09"

    def evaluate(self, wf: WorkflowIR, policy: Dict[str, Any]) -> List[Finding]:
        require_oidc = bool(policy.get("require_azure_oidc", True))
        forbid_secret_creds = bool(policy.get("forbid_azure_credentials_secret", True))
        require_id_token_write = bool(policy.get("require_id_token_write", True))
        forbid_oidc_on_untrusted = bool(policy.get("forbid_oidc_on_untrusted_triggers", False))

        findings: List[Finding] = []
        any_applicable = False

        for job in wf.jobs:
            if not _is_azure_job(job):
                continue
            any_applicable = True

            if forbid_oidc_on_untrusted and any(ev in wf.triggers.events for ev in ["pull_request", "pull_request_target"]):
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="Critical",
                    rule_id="L2-09.R4",
                    message="Azure authentication must not run on untrusted PR triggers. Split workflows by trust boundary.",
                    file_path=wf.file_path,
                    explain=explain_pack(
                        why="Cloud authentication in PR contexts increases risk of token abuse and secret exfiltration.",
                        detect=f"Azure auth detected and workflow triggers include: {sorted(wf.triggers.events)}.",
                        fix="Split workflows: pull_request for tests; push/workflow_dispatch for deploy with OIDC.",
                        verify="Re-run the scanner and confirm Azure auth is not present under PR triggers.",
                        difficulty="Medium",
                    ),
                    metadata={"job": job.job_id, "triggers": sorted(wf.triggers.events)},
                ))
                continue

            if forbid_secret_creds and _has_secret_based_azure_auth(job):
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="Critical",
                    rule_id="L2-09.R1",
                    message="Azure authentication must use OIDC. Long-lived Azure credentials (client secrets / creds) are forbidden.",
                    file_path=wf.file_path,
                    explain=explain_pack(
                        why="Long-lived Azure credentials can be reused if leaked; OIDC uses short-lived tokens without stored secrets.",
                        detect="Secret-based Azure auth indicators detected (AZURE_* env keys or azure/login secret inputs).",
                        fix="Migrate to OIDC with federated credentials in Entra ID. Remove client secrets/creds from workflows.",
                        verify="Re-run the scanner and confirm the Azure job no longer triggers this rule and uses id-token: write.",
                        difficulty="Medium",
                    ),
                    metadata={"job": job.job_id},
                ))
                continue

            eff = job.derived.effective_permissions or {}
            if require_oidc and require_id_token_write and eff.get("id-token") != "write":
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="High",
                    rule_id="L2-09.R2",
                    message="OIDC requires `permissions: id-token: write`. Add minimal id-token permission to the Azure job.",
                    file_path=wf.file_path,
                    explain=explain_pack(
                        why="GitHub OIDC token issuance requires the workflow to request `id-token: write`.",
                        detect=f"Azure auth detected but effective permissions lack `id-token: write` (found: {eff.get('id-token')}).",
                        fix="Add `permissions: id-token: write` (and keep `contents: read` unless more is required).",
                        verify="Re-run the scanner and confirm L2-09 becomes PASS/WARN and id-token is write.",
                        difficulty="Easy",
                    ),
                    metadata={"job": job.job_id, "effective_permissions": eff},
                ))
                continue

            if _has_excessive_write_perms(job):
                findings.append(Finding(
                    control_id=self.control_id,
                    status="WARN",
                    severity="Medium",
                    rule_id="L2-09.R3",
                    message="Azure deploy jobs should use least-privilege permissions. Review write scopes in this job.",
                    file_path=wf.file_path,
                    explain=explain_pack(
                        why="Unnecessary repo write permissions increase blast radius without improving deployment correctness.",
                        detect=f"Azure job has broad write scopes (e.g., write-all or contents: write). Effective: {eff}.",
                        fix="Remove write-all and reduce unnecessary write scopes. Keep only what the job truly needs.",
                        verify="Re-run the scanner and confirm the warning disappears after permission reduction.",
                        difficulty="Easy",
                    ),
                    metadata={"job": job.job_id, "effective_permissions": eff},
                ))
                continue

            findings.append(Finding(
                control_id=self.control_id,
                status="PASS",
                severity="None",
                rule_id="L2-09.PASS",
                message="Azure authentication appears compatible with OIDC and least-privilege policy.",
                file_path=wf.file_path,
                explain=explain_pack(
                    why="OIDC avoids storing long-lived cloud secrets and reduces compromise impact.",
                    detect="Azure auth detected with no secret-based indicators and with required id-token permission.",
                    fix="No change required.",
                    verify="Keep Azure auth on trusted triggers and maintain least-privilege permissions.",
                    difficulty="Easy",
                ),
                metadata={"job": job.job_id},
            ))

        if not any_applicable:
            findings.append(Finding(
                control_id=self.control_id,
                status="SKIP",
                severity="None",
                rule_id="L2-09.R0",
                message="No Azure authentication detected in workflow.",
                file_path=wf.file_path,
                explain=explain_pack(
                    why="This control only applies when Azure authentication is present.",
                    detect="No azure/login action and no Azure CLI usage patterns were detected.",
                    fix="No change required.",
                    verify="N/A",
                    difficulty="Easy",
                ),
            ))

        return findings
