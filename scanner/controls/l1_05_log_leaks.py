from __future__ import annotations

from typing import Dict, Any, List, Tuple
import re

from .base import Control
from ..findings import Finding
from ..ir.models import WorkflowIR
from ..utils.explain import explain_pack
from ..utils.locator import find_first_regex_line


class L105LogLeaks(Control):
    """L1-05: Prevent leaking sensitive information to logs."""

    control_id = "L1-05"

    # Basic heuristics (language-agnostic-ish)
    _SET_X_PAT = r"(^|\s)set\s+-x(\s|$)|xtrace"
    _PRINTENV_PAT = r"(^|\s)(printenv|env)(\s|$)"
    _PS_ENV_DUMP_PAT = r"Get-ChildItem\s+Env:|gci\s+Env:|dir\s+Env:"
    _SECRET_EXPR_PAT = r"\$\{\{\s*secrets\.[^\s\}]+\s*\}\}"
    _ECHO_LIKE_PAT = r"(^|\s)(echo|printf|Write-Output|Write-Host)\s+"

    def _scan_run(self, run_text: str) -> List[Tuple[str, str]]:
        """Return list of (rule_id, kind) matches."""
        matches: List[Tuple[str, str]] = []
        rt = run_text or ""

        if re.search(self._SET_X_PAT, rt, flags=re.IGNORECASE | re.MULTILINE):
            matches.append(("L1-05.R1", "set_x"))

        if re.search(self._PRINTENV_PAT, rt, flags=re.IGNORECASE | re.MULTILINE) or re.search(self._PS_ENV_DUMP_PAT, rt, flags=re.IGNORECASE | re.MULTILINE):
            matches.append(("L1-05.R2", "env_dump"))

        # High risk: printing secrets into logs
        if re.search(self._SECRET_EXPR_PAT, rt) and re.search(self._ECHO_LIKE_PAT, rt, flags=re.IGNORECASE | re.MULTILINE):
            matches.append(("L1-05.R3", "echo_secrets"))

        return matches

    def evaluate(self, wf: WorkflowIR, policy: Dict[str, Any]) -> List[Finding]:
        # Policy knobs
        forbid_set_x = bool(policy.get("forbid_set_x", False))
        forbid_env_dump = bool(policy.get("forbid_env_dump", False))
        forbid_secret_echo = bool(policy.get("forbid_secret_echo", True))

        findings: List[Finding] = []

        src = getattr(wf, "source_text", None)

        any_applicable = False
        for job in wf.jobs:
            for step in job.steps:
                if step.kind != "run" or step.run is None:
                    continue
                any_applicable = True
                run_cmd = step.run.command or ""
                matches = self._scan_run(run_cmd)
                if not matches:
                    continue

                # Determine the most severe match for this step
                # Priority: echo_secrets > env_dump > set_x
                kinds = [k for _, k in matches]
                if "echo_secrets" in kinds:
                    rule_id = "L1-05.R3"
                    status = "FAIL" if forbid_secret_echo else "WARN"
                    severity = "High" if status == "FAIL" else "Medium"
                    message = "Potential secret leakage: secrets are printed to logs."
                    why = "Secrets printed to logs can be harvested from workflow logs or artifacts."
                    detect = "A run step contains `${{ secrets.* }}` and a print/echo command."
                    fix = "Remove secret printing. Use safe debug patterns and mask values if absolutely necessary (e.g., `::add-mask::`)."
                    verify = "Re-run the scanner and confirm no steps print secrets. Review workflow logs to ensure secrets are not exposed."
                    difficulty = "Easy"
                    line = find_first_regex_line(src, self._SECRET_EXPR_PAT) or find_first_regex_line(src, self._ECHO_LIKE_PAT)

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
                    continue

                if "env_dump" in kinds:
                    rule_id = "L1-05.R2"
                    status = "FAIL" if forbid_env_dump else "WARN"
                    severity = "Medium" if status == "WARN" else "High"
                    message = "Environment dump detected. This may leak sensitive values into logs."
                    why = "Dumping environment variables can accidentally expose credentials, tokens, or internal endpoints."
                    detect = "A run step uses `printenv`/`env` (or PowerShell Env: listing)."
                    fix = "Avoid full environment dumps. If debugging, print only specific non-sensitive variables, and mask sensitive values."
                    verify = "Re-run the scanner; ensure no `printenv`/`env`/Env: dump remains in workflows."
                    difficulty = "Easy"
                    line = find_first_regex_line(src, self._PRINTENV_PAT) or find_first_regex_line(src, self._PS_ENV_DUMP_PAT)

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
                    continue

                if "set_x" in kinds:
                    rule_id = "L1-05.R1"
                    status = "FAIL" if forbid_set_x else "WARN"
                    severity = "Medium" if status == "WARN" else "High"
                    message = "Shell xtrace detected (`set -x`). Commands and expansions may leak secrets into logs."
                    why = "`set -x` prints commands and expansions; if secrets are present in env/args, they can be logged."
                    detect = "A run step enables xtrace (`set -x` or `set -o xtrace`)."
                    fix = "Remove `set -x` or scope it carefully. Prefer safe debug templates and mask sensitive values."
                    verify = "Re-run the scanner; ensure `set -x` is not enabled in workflows."
                    difficulty = "Easy"
                    line = find_first_regex_line(src, self._SET_X_PAT)

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
                    continue

        if not any_applicable:
            # No run steps at all
            findings.append(Finding(
                control_id=self.control_id,
                status="SKIP",
                severity="None",
                rule_id="L1-05.R0",
                message="Workflow contains no run steps.",
                file_path=wf.file_path,
                start_line=None,
                end_line=None,
                explain=explain_pack(
                    why="Log leakage checks apply to shell/script steps.",
                    detect="No `run:` steps were found.",
                    fix="No change required.",
                    verify="N/A",
                    difficulty="Easy",
                ),
                metadata={},
            ))
        elif not any(f.control_id == self.control_id and f.status in ("FAIL", "WARN") for f in findings):
            # Applicable but clean
            findings.append(Finding(
                control_id=self.control_id,
                status="PASS",
                severity="None",
                rule_id="L1-05.PASS",
                message="No obvious log-leak patterns were detected in run steps.",
                file_path=wf.file_path,
                start_line=None,
                end_line=None,
                explain=explain_pack(
                    why="Preventing secret leakage via logs reduces accidental credential exposure.",
                    detect="No xtrace/env-dump/secret-print patterns were found.",
                    fix="No change required.",
                    verify="Keep workflows free of debug patterns that can leak sensitive data.",
                    difficulty="Easy",
                ),
                metadata={},
            ))

        return findings
