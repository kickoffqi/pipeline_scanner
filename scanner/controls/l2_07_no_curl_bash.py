from __future__ import annotations

from typing import Dict, Any, List, Tuple
import re

from .base import Control
from ..findings import Finding
from ..ir.models import WorkflowIR
from ..utils.explain import explain_pack
from ..utils.locator import find_first_regex_line


class L207NoCurlBash(Control):
    """L2-07: Prevent remote script execution via curl|bash / wget|sh / iwr|iex."""

    control_id = "L2-07"

    # Common patterns
    _PIPE_SHELL_PAT = r"\b(curl|wget)\b[^\n\r]*\|\s*(bash|sh)\b"
    _CURL_BASH_SUBSHELL_PAT = r"\b(bash|sh)\s+-c\s+\"\$\(\s*(curl|wget)\b"
    _POWERSHELL_IEX_PAT = r"\b(iwr|Invoke-WebRequest)\b[^\n\r]*\|\s*(iex|Invoke-Expression)\b"

    def evaluate(self, wf: WorkflowIR, policy: Dict[str, Any]) -> List[Finding]:
        forbid_pipe_to_shell = bool(policy.get("forbid_pipe_to_shell", True))
        findings: List[Finding] = []

        src = getattr(wf, "source_text", None)

        any_applicable = False
        hit = False

        for job in wf.jobs:
            for step in job.steps:
                if step.kind != "run" or step.run is None:
                    continue
                any_applicable = True
                cmd = step.run.command or ""

                # Detect
                if re.search(self._PIPE_SHELL_PAT, cmd, flags=re.IGNORECASE | re.MULTILINE) or                    re.search(self._CURL_BASH_SUBSHELL_PAT, cmd, flags=re.IGNORECASE | re.MULTILINE) or                    re.search(self._POWERSHELL_IEX_PAT, cmd, flags=re.IGNORECASE | re.MULTILINE):
                    hit = True
                    status = "FAIL" if forbid_pipe_to_shell else "WARN"
                    severity = "High" if status == "FAIL" else "Medium"
                    rule_id = "L2-07.R1"
                    message = "Remote script execution detected (curl|bash / wget|sh / iwr|iex)."

                    why = "Piping remote content directly into a shell executes unverified code and is a high-risk supply-chain entry point."
                    detect = "A run step contains a pipe-to-shell pattern such as `curl ... | bash`, `wget ... | sh`, or PowerShell `iwr ... | iex`."
                    fix = "Download a fixed version, verify checksum/signature (SHA256/GPG/Sigstore), and then execute. Prefer official actions or package managers."
                    verify = "Re-run the scanner; ensure no pipe-to-shell patterns remain. Confirm downloads are pinned and verified."
                    difficulty = "Medium"

                    line = (
                        find_first_regex_line(src, self._PIPE_SHELL_PAT)
                        or find_first_regex_line(src, self._POWERSHELL_IEX_PAT)
                        or find_first_regex_line(src, self._CURL_BASH_SUBSHELL_PAT)
                    )

                    findings.append(Finding(
                        control_id=self.control_id,
                        status=status,
                        severity=severity,
                        rule_id=rule_id,
                        message=message,
                        file_path=wf.file_path,
                        start_line=line,
                        end_line=None,
                        explain=explain_pack(
                            why=why,
                            detect=detect,
                            fix=fix,
                            verify=verify,
                            difficulty=difficulty,
                        ),
                        metadata={
                            "job": job.job_id,
                            "step": step.name or f"step[{step.index}]"
                        },
                    ))

        if not any_applicable:
            findings.append(Finding(
                control_id=self.control_id,
                status="SKIP",
                severity="None",
                rule_id="L2-07.R0",
                message="Workflow contains no run steps.",
                file_path=wf.file_path,
                start_line=None,
                end_line=None,
                explain=explain_pack(
                    why="Remote script execution checks apply to shell/script steps.",
                    detect="No `run:` steps were found.",
                    fix="No change required.",
                    verify="N/A",
                    difficulty="Easy",
                ),
                metadata={},
            ))
        elif not hit:
            findings.append(Finding(
                control_id=self.control_id,
                status="PASS",
                severity="None",
                rule_id="L2-07.PASS",
                message="No pipe-to-shell remote execution patterns were detected.",
                file_path=wf.file_path,
                start_line=None,
                end_line=None,
                explain=explain_pack(
                    why="Avoiding unverified remote scripts reduces supply-chain risk.",
                    detect="No `curl|bash`/`wget|sh`/`iwr|iex` patterns were found.",
                    fix="No change required.",
                    verify="Keep workflows free of pipe-to-shell patterns. Use pinned + verified installers.",
                    difficulty="Easy",
                ),
                metadata={},
            ))

        return findings
