from __future__ import annotations

from typing import Dict, Any, List, Optional

from .base import Control
from ..findings import Finding
from ..ir.models import WorkflowIR, JobIR


def _job_category(job: JobIR) -> str:
    # v1 heuristic category for permissions expectations
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

            # Rule 0: explicit required
            if require_explicit and eff_mode == "implicit":
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="High",
                    message="Permissions are implicit. Explicit minimal permissions must be declared.",
                    file_path=wf.file_path,
                    metadata={"job": job.job_id, "category": cat},
                ))
                # continue evaluating other rules? We can still check write-all etc if present; but implicit has none.
                continue

            # Rule 1: write-all forbidden
            if forbid_write_all and eff.get("__all__") == "write":
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="Critical",
                    message="write-all permissions are forbidden. Declare minimal scopes explicitly.",
                    file_path=wf.file_path,
                    metadata={"job": job.job_id, "category": cat},
                ))
                continue

            ws = _write_scopes(eff)

            # Rule 2: CI jobs read-only
            if cat == "ci" and ws:
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="High",
                    message=f"CI jobs must not require write permissions. Found write scopes: {', '.join(ws)}.",
                    file_path=wf.file_path,
                    metadata={"job": job.job_id, "category": cat, "write_scopes": ws},
                ))
                continue

            # Rule 3: Deploy jobs guidance
            if cat == "deploy":
                if eff.get("__all__") == "write":
                    findings.append(Finding(
                        control_id=self.control_id,
                        status="FAIL",
                        severity="Critical",
                        message="Deploy job uses write-all. Declare minimal scopes explicitly.",
                        file_path=wf.file_path,
                        metadata={"job": job.job_id, "category": cat},
                    ))
                    continue
                if eff.get("contents") == "write":
                    findings.append(Finding(
                        control_id=self.control_id,
                        status="WARN",
                        severity="Medium",
                        message="Deploy jobs often do not need contents: write. Review if this is required.",
                        file_path=wf.file_path,
                        metadata={"job": job.job_id, "category": cat},
                    ))
                    continue

            # PASS if explicit and no violations
            findings.append(Finding(
                control_id=self.control_id,
                status="PASS",
                severity="None",
                message="Permissions are explicit and comply with least-privilege policy.",
                file_path=wf.file_path,
                metadata={"job": job.job_id, "category": cat},
            ))

        return findings
