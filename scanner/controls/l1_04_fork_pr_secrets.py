from __future__ import annotations

from typing import Dict, Any, List

from .base import Control
from ..findings import Finding
from ..ir.models import WorkflowIR
from ..utils.explain import explain_pack
from ..utils.locator import find_trigger_line, find_on_line


class L104ForkPRSecrets(Control):
    control_id = "L1-04"

    def evaluate(self, wf: WorkflowIR, policy: Dict[str, Any]) -> List[Finding]:
        trigger_line = find_trigger_line(getattr(wf, 'source_text', None), 'pull_request')
        on_line = find_on_line(getattr(wf, 'source_text', None))
        loc_line = trigger_line or on_line
        if "pull_request" not in wf.triggers.events:
            return [Finding(
                control_id=self.control_id,
                status="SKIP",
                severity="None",
                rule_id="L1-04.R0",
                message="Workflow is not triggered by pull_request.",
                file_path=wf.file_path,
                start_line=loc_line,
                end_line=None,
                explain=explain_pack(
                    why="Fork PR secret exposure is specific to pull_request-triggered workflows.",
                    detect="No `pull_request` trigger found.",
                    fix="No change required.",
                    verify="N/A",
                    difficulty="Easy",
                ),
            )]

        findings: List[Finding] = []

        for job in wf.jobs:
            if job.environment:
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="Critical",
                    rule_id="L1-04.R2",
                    message="Jobs using environments with secrets must not run on fork pull requests.",
                    file_path=wf.file_path,
                    start_line=loc_line,
                    end_line=None,
                    explain=explain_pack(
                        why="Environments often gate access to secrets and protected deployments. Fork PRs must not reach them.",
                        detect=f"Job binds to environment `{job.environment}` under pull_request trigger.",
                        fix="Split workflows: pull_request for tests without environments; push/workflow_dispatch for deploy jobs with environments.",
                        verify="Re-run the scanner and confirm pull_request workflows no longer bind environments.",
                        difficulty="Medium",
                    ),
                    metadata={"job": job.job_id, "environment": job.environment},
                ))
                continue

            if job.derived.uses_secrets:
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="Critical",
                    rule_id="L1-04.R1",
                    message="Secrets must not be accessed in fork-based pull request workflows.",
                    file_path=wf.file_path,
                    start_line=loc_line,
                    end_line=None,
                    explain=explain_pack(
                        why="Fork PR code is attacker-controlled; any secrets exposed can be exfiltrated via logs or network calls.",
                        detect="Job appears to reference secrets (derived uses_secrets=true).",
                        fix="Remove secrets from pull_request workflows. Move secret usage to trusted triggers (push to protected branches / workflow_dispatch).",
                        verify="Re-run the scanner and confirm no secret references exist in pull_request jobs.",
                        difficulty="Medium",
                    ),
                    metadata={"job": job.job_id},
                ))
                continue

            if any(s.derived.references_secrets for s in job.steps):
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="Critical",
                    rule_id="L1-04.R3",
                    message="Secrets must not be referenced at step level in fork pull request workflows.",
                    file_path=wf.file_path,
                    start_line=loc_line,
                    end_line=None,
                    explain=explain_pack(
                        why="Even a single step-level secret reference can leak credentials in fork PR contexts.",
                        detect="At least one step contains a secrets.* reference.",
                        fix="Remove secrets.* from pull_request workflows and run secret-dependent steps only on trusted triggers.",
                        verify="Re-run the scanner and ensure L1-04 passes with no step secret references.",
                        difficulty="Easy",
                    ),
                    metadata={"job": job.job_id},
                ))
                continue

            findings.append(Finding(
                control_id=self.control_id,
                status="PASS",
                severity="None",
                rule_id="L1-04.PASS",
                message="No secret usage detected in pull_request workflow job.",
                file_path=wf.file_path,
                start_line=loc_line,
                end_line=None,
                explain=explain_pack(
                    why="Keeping PR workflows secret-free prevents credential exfiltration from untrusted code paths.",
                    detect="No secret references and no environment bindings were detected.",
                    fix="No change required.",
                    verify="Keep PR workflows free of secrets as they evolve.",
                    difficulty="Easy",
                ),
                metadata={"job": job.job_id},
            ))

        return findings
