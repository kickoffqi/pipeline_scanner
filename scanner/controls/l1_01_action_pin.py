from __future__ import annotations

from typing import Dict, Any, List

from .base import Control
from ..findings import Finding
from ..ir.models import WorkflowIR
from ..utils.explain import explain_pack


class L101ActionPin(Control):
    control_id = "L1-01"

    def evaluate(self, wf: WorkflowIR, policy: Dict[str, Any]) -> List[Finding]:
        allow_semver_tags = bool(policy.get("allow_semver_tags", False))
        findings: List[Finding] = []

        for job in wf.jobs:
            for step in job.steps:
                if step.kind != "uses" or step.uses is None:
                    continue

                ref_type = step.uses.ref_type
                loc = step.location
                file_path = wf.file_path
                uses_str = step.uses.full

                if ref_type == "sha":
                    findings.append(Finding(
                        control_id=self.control_id,
                        status="PASS",
                        severity="None",
                        rule_id="L1-01.R3",
                        message="Action is pinned to an immutable commit SHA.",
                        file_path=file_path,
                        start_line=loc.start_line if loc else None,
                        end_line=loc.end_line if loc else None,
                        explain=explain_pack(
                            why="Pinned SHAs prevent upstream action changes from silently altering your pipeline.",
                            detect=f"`uses: {uses_str}` is pinned to a 40-hex commit SHA.",
                            fix="No change required.",
                            verify="Confirm `uses:` references are 40-hex SHAs across all steps.",
                            difficulty="Easy",
                        ),
                        metadata={"job": job.job_id, "uses": uses_str, "ref_type": ref_type},
                    ))
                elif ref_type == "branch":
                    findings.append(Finding(
                        control_id=self.control_id,
                        status="FAIL",
                        severity="High",
                        rule_id="L1-01.R1",
                        message="Action references a mutable branch. Pin to a commit SHA.",
                        file_path=file_path,
                        start_line=loc.start_line if loc else None,
                        end_line=loc.end_line if loc else None,
                        explain=explain_pack(
                            why="Branches can move. If the upstream action is compromised, your workflow may run malicious code without changing YAML.",
                            detect=f"`uses: {uses_str}` references a branch-like ref.",
                            fix="Replace the ref with the action's commit SHA (40-hex). Consider allowing tags only at higher security levels.",
                            verify="Re-run the scanner and ensure the step is PASS with ref_type=sha.",
                            difficulty="Medium",
                        ),
                        metadata={"job": job.job_id, "uses": uses_str, "ref_type": ref_type},
                    ))
                elif ref_type == "tag":
                    if allow_semver_tags:
                        findings.append(Finding(
                            control_id=self.control_id,
                            status="WARN",
                            severity="Medium",
                            rule_id="L1-01.R2",
                            message="Action uses a tag. Commit SHA pinning is recommended.",
                            file_path=file_path,
                            start_line=loc.start_line if loc else None,
                            end_line=loc.end_line if loc else None,
                            explain=explain_pack(
                                why="Tags can be retargeted. SHA pinning provides the strongest supply-chain protection.",
                                detect=f"`uses: {uses_str}` references a tag.",
                                fix="Pin to a commit SHA if possible. If you must use tags, restrict to trusted owners and monitor upstream.",
                                verify="Re-run the scanner; PASS requires ref_type=sha unless policy allows tags.",
                                difficulty="Medium",
                            ),
                            metadata={"job": job.job_id, "uses": uses_str, "ref_type": ref_type},
                        ))
                    else:
                        findings.append(Finding(
                            control_id=self.control_id,
                            status="FAIL",
                            severity="High",
                            rule_id="L1-01.R2",
                            message="Action references a mutable tag. Pin to a commit SHA.",
                            file_path=file_path,
                            start_line=loc.start_line if loc else None,
                            end_line=loc.end_line if loc else None,
                            explain=explain_pack(
                                why="Tags can be retargeted. If the upstream action is compromised, tag-based pinning can run attacker code.",
                                detect=f"`uses: {uses_str}` references a tag while SHA-only policy is enabled.",
                                fix="Replace the tag with the resolved commit SHA (40-hex).",
                                verify="Re-run the scanner and ensure the step is PASS with ref_type=sha.",
                                difficulty="Medium",
                            ),
                            metadata={"job": job.job_id, "uses": uses_str, "ref_type": ref_type},
                        ))
                else:
                    findings.append(Finding(
                        control_id=self.control_id,
                        status="WARN",
                        severity="Medium",
                        rule_id="L1-01.R4",
                        message="Unable to determine reference immutability. Review manually.",
                        file_path=file_path,
                        start_line=loc.start_line if loc else None,
                        end_line=loc.end_line if loc else None,
                        explain=explain_pack(
                            why="If the reference is not clearly immutable, the action may still change over time.",
                            detect=f"`uses: {uses_str}` reference type could not be determined.",
                            fix="Prefer pinning to a commit SHA (40-hex).",
                            verify="Re-run the scanner and confirm the step is PASS with ref_type=sha.",
                            difficulty="Easy",
                        ),
                        metadata={"job": job.job_id, "uses": uses_str, "ref_type": ref_type},
                    ))

        return findings
