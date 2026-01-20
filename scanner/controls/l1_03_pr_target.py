from __future__ import annotations

from typing import Dict, Any, List

from .base import Control
from ..findings import Finding
from ..ir.models import WorkflowIR
from ..utils.explain import explain_pack
from ..utils.locator import find_trigger_line, find_on_line


class L103PullRequestTarget(Control):
    control_id = "L1-03"

    def evaluate(self, wf: WorkflowIR, policy: Dict[str, Any]) -> List[Finding]:
        trigger_line = find_trigger_line(getattr(wf, 'source_text', None), 'pull_request_target')
        on_line = find_on_line(getattr(wf, 'source_text', None))
        loc_line = trigger_line or on_line
        if "pull_request_target" not in wf.triggers.events:
            return [Finding(
                control_id=self.control_id,
                status="SKIP",
                severity="None",
                rule_id="L1-03.R0",
                message="Workflow is not triggered by pull_request_target.",
                file_path=wf.file_path,
                start_line=loc_line,
                end_line=None,
                explain=explain_pack(
                    why="pull_request_target is a special high-risk trigger. If unused, this control does not apply.",
                    detect="No `pull_request_target` trigger found.",
                    fix="No change required.",
                    verify="N/A",
                    difficulty="Easy",
                ),
            )]

        findings: List[Finding] = []

        for job in wf.jobs:
            if job.derived.uses_secrets:
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="Critical",
                    rule_id="L1-03.R3",
                    message="Secrets must not be accessed in pull_request_target workflows.",
                    file_path=wf.file_path,
                    start_line=loc_line,
                    end_line=None,
                    explain=explain_pack(
                        why="pull_request_target runs with target-branch context, which can expose secrets to attacker-controlled PR data.",
                        detect="Job appears to reference secrets (derived uses_secrets=true).",
                        fix="Split workflows by trust boundary. Use pull_request for code execution and reserve pull_request_target for metadata-only tasks without secrets.",
                        verify="Re-run the scanner and ensure L1-03 passes; confirm no secrets are used under pull_request_target.",
                        difficulty="Medium",
                    ),
                    metadata={"job": job.job_id},
                ))
                continue

            has_run = any(s.kind == "run" for s in job.steps)
            if has_run:
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="Critical",
                    rule_id="L1-03.R2",
                    message="Executing shell commands under pull_request_target may execute untrusted code.",
                    file_path=wf.file_path,
                    start_line=loc_line,
                    end_line=None,
                    explain=explain_pack(
                        why="A malicious PR can influence checked-out content or scripts that run under trusted context.",
                        detect="At least one `run:` step exists in a pull_request_target job.",
                        fix="Move code execution to a pull_request workflow without secrets. Keep pull_request_target jobs metadata-only (label/comment).",
                        verify="Re-run the scanner and ensure pull_request_target jobs have no run steps.",
                        difficulty="Medium",
                    ),
                    metadata={"job": job.job_id},
                ))
                continue

            has_checkout = any(
                s.kind == "uses" and s.uses is not None and (s.uses.owner_repo or "").lower() == "actions/checkout"
                for s in job.steps
            )
            if has_checkout:
                findings.append(Finding(
                    control_id=self.control_id,
                    status="FAIL",
                    severity="Critical",
                    rule_id="L1-03.R1",
                    message="Checking out pull request code under pull_request_target is unsafe.",
                    file_path=wf.file_path,
                    start_line=loc_line,
                    end_line=None,
                    explain=explain_pack(
                        why="Checking out attacker-controlled PR code under a trusted context enables secret exfiltration and repo compromise.",
                        detect="actions/checkout detected in a pull_request_target job.",
                        fix="Avoid checkout in pull_request_target. If you need PR files, use pull_request (untrusted) and never expose secrets.",
                        verify="Re-run the scanner and ensure no checkout occurs under pull_request_target.",
                        difficulty="Medium",
                    ),
                    metadata={"job": job.job_id},
                ))
                continue

            findings.append(Finding(
                control_id=self.control_id,
                status="PASS",
                severity="None",
                rule_id="L1-03.PASS",
                message="pull_request_target usage appears metadata-only (no run steps, no secrets, no checkout).",
                file_path=wf.file_path,
                start_line=loc_line,
                end_line=None,
                explain=explain_pack(
                    why="Metadata-only pull_request_target workflows can be safe when no untrusted code runs and no secrets are used.",
                    detect="No run steps, no checkout, and no secret references were detected.",
                    fix="No change required.",
                    verify="Keep pull_request_target jobs metadata-only as workflows evolve.",
                    difficulty="Easy",
                ),
                metadata={"job": job.job_id},
            ))

        return findings
