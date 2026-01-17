from __future__ import annotations

from typing import Dict, Any, List

from .base import Control
from ..findings import Finding
from ..ir.models import WorkflowIR


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

                if ref_type == "sha":
                    findings.append(Finding(
                        control_id=self.control_id,
                        status="PASS",
                        severity="None",
                        message="Action is pinned to an immutable commit SHA.",
                        file_path=file_path,
                        start_line=loc.start_line if loc else None,
                        end_line=loc.end_line if loc else None,
                        metadata={"uses": step.uses.full, "ref_type": ref_type},
                    ))
                elif ref_type == "branch":
                    findings.append(Finding(
                        control_id=self.control_id,
                        status="FAIL",
                        severity="High",
                        message="Action references a mutable branch. Pin to a commit SHA.",
                        file_path=file_path,
                        start_line=loc.start_line if loc else None,
                        end_line=loc.end_line if loc else None,
                        metadata={"uses": step.uses.full, "ref_type": ref_type},
                    ))
                elif ref_type == "tag":
                    if allow_semver_tags:
                        findings.append(Finding(
                            control_id=self.control_id,
                            status="WARN",
                            severity="Medium",
                            message="Action uses a tag. Commit SHA pinning is recommended.",
                            file_path=file_path,
                            start_line=loc.start_line if loc else None,
                            end_line=loc.end_line if loc else None,
                            metadata={"uses": step.uses.full, "ref_type": ref_type},
                        ))
                    else:
                        findings.append(Finding(
                            control_id=self.control_id,
                            status="FAIL",
                            severity="High",
                            message="Action references a mutable tag. Pin to a commit SHA.",
                            file_path=file_path,
                            start_line=loc.start_line if loc else None,
                            end_line=loc.end_line if loc else None,
                            metadata={"uses": step.uses.full, "ref_type": ref_type},
                        ))
                else:
                    findings.append(Finding(
                        control_id=self.control_id,
                        status="WARN",
                        severity="Medium",
                        message="Unable to determine reference immutability. Review manually.",
                        file_path=file_path,
                        start_line=loc.start_line if loc else None,
                        end_line=loc.end_line if loc else None,
                        metadata={"uses": step.uses.full, "ref_type": ref_type},
                    ))

        return findings
