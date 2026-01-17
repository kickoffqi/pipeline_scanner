from __future__ import annotations

from typing import Dict, Any, List

from .base import Control
from ..findings import Finding
from ..ir.models import WorkflowIR


class L103PullRequestTarget(Control):
    control_id = "L1-03"

    def evaluate(self, wf: WorkflowIR, policy: Dict[str, Any]) -> List[Finding]:
        if "pull_request_target" not in wf.triggers.events:
            return [Finding(
                control_id=self.control_id,
                status="SKIP",
                severity="None",
                message="Workflow is not triggered by pull_request_target.",
                file_path=wf.file_path,
            )]

        findings: List[Finding] = []

        for job in wf.jobs:
            # Rule: secrets usage forbidden
            if job.derived.uses_secrets:
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="Critical",
                    message="Secrets must not be accessed in pull_request_target workflows.",
                    file_path=wf.file_path,
                    metadata={"job": job.job_id},
                ))
                continue

            # Rule: any run step forbidden (conservative)
            has_run = any(s.kind == "run" for s in job.steps)
            if has_run:
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="Critical",
                    message="Executing shell commands under pull_request_target may execute untrusted code.",
                    file_path=wf.file_path,
                    metadata={"job": job.job_id},
                ))
                continue

            # Rule: checkout forbidden (conservative)
            has_checkout = any(
                s.kind == "uses" and s.uses is not None and (s.uses.owner_repo or "").lower() == "actions/checkout"
                for s in job.steps
            )
            if has_checkout:
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="Critical",
                    message="Checking out pull request code under pull_request_target is unsafe.",
                    file_path=wf.file_path,
                    metadata={"job": job.job_id},
                ))
                continue

            findings.append(Finding(
                control_id=self.control_id,
                status="PASS",
                severity="None",
                message="pull_request_target usage appears metadata-only (no run steps, no secrets, no checkout).",
                file_path=wf.file_path,
                metadata={"job": job.job_id},
            ))

        return findings
