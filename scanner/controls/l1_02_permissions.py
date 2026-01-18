from __future__ import annotations

from typing import Dict, Any, List

from .base import Control
from ..findings import Finding
from ..ir.models import WorkflowIR, JobIR
from ..utils.explain import explain_pack


def _job_category(job: JobIR) -> str:
    text = f"{job.job_id} {job.name or ''}".lower()
    if any(k in text for k in ["deploy", "prod", "production", "rollout"]):
        return "deploy"
    if any(k in text for k in ["release", "publish", "package", "docker", "image"]):
        return "release"
    return "ci"


def _write_scopes(eff: Dict[str, str]) -> List[str]:
    return sorted([k for k, v in eff.items() if isinstance(v, str) and v.lower() == "write" and k != "__raw__"])


class L102Permissions(Control):
    control_id = "L1-02"

    def evaluate(self, wf: WorkflowIR, policy: Dict[str, Any]) -> List[Finding]:
        require_explicit = bool(policy.get("require_explicit_permissions", True))
        forbid_write_all = bool(policy.get("forbid_write_all", True))

        findings: List[Finding] = []

        for job in wf.jobs:
            eff = job.derived.effective_permissions or {}
            eff_mode = job.derived.effective_permissions_mode
            cat = _job_category(job)

            if require_explicit and eff_mode == "implicit":
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="High",
                    rule_id="L1-02.R0",
                    message="Permissions are implicit. Explicit minimal permissions must be declared.",
                    file_path=wf.file_path,
                    explain=explain_pack(
                        why="Implicit GITHUB_TOKEN permissions depend on repo/org defaults and are difficult to audit.",
                        detect="No explicit `permissions:` block was found at workflow/job level (effective mode=implicit).",
                        fix="Add an explicit `permissions:` block with the minimum required scopes (often `contents: read`).",
                        verify="Re-run the scanner and confirm L1-02 is PASS for the job.",
                        difficulty="Easy",
                    ),
                    metadata={"job": job.job_id, "category": cat},
                ))
                continue

            if forbid_write_all and eff.get("__all__") == "write":
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="Critical",
                    rule_id="L1-02.R1",
                    message="write-all permissions are forbidden. Declare minimal scopes explicitly.",
                    file_path=wf.file_path,
                    explain=explain_pack(
                        why="write-all greatly increases blast radius if a workflow is compromised.",
                        detect="Effective permissions include `write-all` (`__all__: write`).",
                        fix="Replace write-all with explicit minimal scopes (e.g., `contents: read`, plus only what is needed).",
                        verify="Re-run the scanner and confirm no write-all and only expected scopes remain.",
                        difficulty="Easy",
                    ),
                    metadata={"job": job.job_id, "category": cat, "effective_permissions": eff},
                ))
                continue

            ws = _write_scopes(eff)

            if cat == "ci" and ws:
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="High",
                    rule_id="L1-02.R2",
                    message=f"CI jobs must not require write permissions. Found write scopes: {', '.join(ws)}.",
                    file_path=wf.file_path,
                    explain=explain_pack(
                        why="CI jobs typically only need read access. Write scopes allow attackers to modify repo state.",
                        detect=f"Job category=ci and effective permissions include write scopes: {', '.join(ws)}.",
                        fix="Remove write scopes from CI jobs. Split deploy/release steps into separate jobs with stricter triggers.",
                        verify="Re-run the scanner and confirm CI jobs have no write scopes.",
                        difficulty="Medium",
                    ),
                    metadata={"job": job.job_id, "category": cat, "write_scopes": ws, "effective_permissions": eff},
                ))
                continue

            if cat == "deploy":
                if eff.get("__all__") == "write":
                    findings.append(Finding(
                        control_id=self.control_id,
                        status="FAIL",
                        severity="Critical",
                        rule_id="L1-02.R3a",
                        message="Deploy job uses write-all. Declare minimal scopes explicitly.",
                        file_path=wf.file_path,
                        explain=explain_pack(
                            why="Deploy jobs are high-value targets. write-all enables repo modification and token abuse.",
                            detect="Deploy job has `__all__: write`.",
                            fix="Replace with explicit minimal scopes. Add only the write scopes required for deployment.",
                            verify="Re-run the scanner and confirm no write-all remains.",
                            difficulty="Easy",
                        ),
                        metadata={"job": job.job_id, "category": cat, "effective_permissions": eff},
                    ))
                    continue

                if eff.get("contents") == "write":
                    findings.append(Finding(
                        control_id=self.control_id,
                        status="WARN",
                        severity="Medium",
                        rule_id="L1-02.R3b",
                        message="Deploy jobs often do not need contents: write. Review if this is required.",
                        file_path=wf.file_path,
                        explain=explain_pack(
                            why="Unnecessary write scopes increase blast radius without improving functionality.",
                            detect="Deploy job has `contents: write`.",
                            fix="If not needed, downgrade to `contents: read`. Keep only required write scopes.",
                            verify="Re-run the scanner; warning should disappear if write scope removed.",
                            difficulty="Easy",
                        ),
                        metadata={"job": job.job_id, "category": cat, "effective_permissions": eff},
                    ))
                    continue

            findings.append(Finding(
                control_id=self.control_id,
                status="PASS",
                severity="None",
                rule_id="L1-02.PASS",
                message="Permissions are explicit and comply with least-privilege policy.",
                file_path=wf.file_path,
                explain=explain_pack(
                    why="Least-privilege permissions reduce the impact of workflow compromise.",
                    detect="Effective permissions are explicit and no forbidden/broad write scopes were detected.",
                    fix="No change required.",
                    verify="Keep permissions explicit and minimal as workflows evolve.",
                    difficulty="Easy",
                ),
                metadata={"job": job.job_id, "category": cat, "effective_permissions": eff},
            ))

        return findings
