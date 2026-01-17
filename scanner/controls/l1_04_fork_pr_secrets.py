from __future__ import annotations

from typing import Dict, Any, List

from .base import Control
from ..findings import Finding
from ..ir.models import WorkflowIR


class L104ForkPRSecrets(Control):
    control_id = "L1-04"

    def evaluate(self, wf: WorkflowIR, policy: Dict[str, Any]) -> List[Finding]:
        if "pull_request" not in wf.triggers.events:
            return [Finding(
                control_id=self.control_id,
                status="SKIP",
                severity="None",
                message="Workflow is not triggered by pull_request.",
                file_path=wf.file_path,
            )]

        # v1: treat pull_request as fork-risk surface unless additional context is available
        findings: List[Finding] = []

        for job in wf.jobs:
            if job.environment:
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="Critical",
                    message="Jobs using environments with secrets must not run on fork pull requests.",
                    file_path=wf.file_path,
                    metadata={"job": job.job_id, "environment": job.environment},
                ))
                continue

            if job.derived.uses_secrets:
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="Critical",
                    message="Secrets must not be accessed in fork-based pull request workflows.",
                    file_path=wf.file_path,
                    metadata={"job": job.job_id},
                ))
                continue

            # step-level secret reference
            if any(s.derived.references_secrets for s in job.steps):
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="Critical",
                    message="Secrets must not be referenced at step level in fork pull request workflows.",
                    file_path=wf.file_path,
                    metadata={"job": job.job_id},
                ))
                continue

            findings.append(Finding(
                control_id=self.control_id,
                status="PASS",
                severity="None",
                message="No secret usage detected in pull_request workflow job.",
                file_path=wf.file_path,
                metadata={"job": job.job_id},
            ))

        return findings
