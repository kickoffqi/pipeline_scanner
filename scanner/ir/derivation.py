from __future__ import annotations

import re
from typing import Dict, Tuple, Iterable
from .models import WorkflowIR, PermissionsIR

_SECRETS_RE = re.compile(r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}")
_SET_X_RE = re.compile(r"(^|\n)\s*set\s+-x\b")
_CURL_PIPE_RE = re.compile(r"(curl\s+[^\n\r]*\|\s*(bash|sh))|(wget\s+[^\n\r]*\|\s*(bash|sh))", re.IGNORECASE)

AZURE_ENV_KEYS = {"AZURE_CREDENTIALS", "AZURE_CLIENT_SECRET", "AZURE_SECRET"}


def merge_permissions(workflow_perm: PermissionsIR, job_perm: PermissionsIR) -> Tuple[Dict[str, str], str]:
    # Returns: (effective_entries, effective_mode)
    # - workflow implicit: base is implicit (unknown defaults)
    # - job explicit overrides workflow; __all__ at job means full replace
    if workflow_perm.mode == "implicit":
        base_mode = "implicit"
        base_entries: Dict[str, str] = {}
    else:
        base_mode = "explicit"
        base_entries = dict(workflow_perm.entries)

    if job_perm.mode == "implicit":
        return base_entries, base_mode

    # job explicit
    job_entries = dict(job_perm.entries)
    if "__all__" in job_entries:
        return job_entries, "explicit"

    merged = dict(base_entries)
    merged.update(job_entries)
    return merged, "explicit"


def derive_workflow(wf: WorkflowIR) -> WorkflowIR:
    # workflow derived flags
    wf.derived.has_pull_request_target = "pull_request_target" in wf.triggers.events
    wf.derived.has_pull_request = "pull_request" in wf.triggers.events
    wf.derived.has_fork_risk_surface = wf.derived.has_pull_request_target or wf.derived.has_pull_request
    wf.derived.effective_permissions_mode = wf.permissions.mode

    # per-job derivation
    for job in wf.jobs:
        eff, eff_mode = merge_permissions(wf.permissions, job.permissions)
        job.derived.effective_permissions = eff
        job.derived.effective_permissions_mode = eff_mode

        # runner classification
        job.derived.uses_self_hosted = any(x == "self-hosted" for x in job.runs_on)

        # step-level analysis
        uses_secrets = False
        dangerous = set()
        uses_azure_login = False
        azure_env_injected = False

        for step in job.steps:
            if step.kind == "run" and step.run is not None:
                cmd = step.run.command or ""
                if _SECRETS_RE.search(cmd):
                    uses_secrets = True
                    step.derived.references_secrets = True
                if _SET_X_RE.search(cmd):
                    dangerous.add("set_x")
                    step.derived.has_set_x = True
                if _CURL_PIPE_RE.search(cmd):
                    dangerous.add("curl_pipe_shell")
                    step.derived.has_curl_pipe_shell = True

            if step.kind == "uses" and step.uses is not None:
                # azure login detection
                if step.uses.owner_repo and step.uses.owner_repo.lower() == "azure/login":
                    uses_azure_login = True

            # env keys hints
            if step.env_keys & AZURE_ENV_KEYS:
                azure_env_injected = True

        # job-level secrets heuristic
        # v1: secrets in run commands or presence of common Azure credential env keys
        job.derived.uses_secrets = uses_secrets or azure_env_injected
        job.derived.dangerous_patterns = dangerous

        # OIDC heuristic (v1):
        # if azure/login is used and effective permissions include id-token: write, assume OIDC intent
        job.derived.uses_oidc = uses_azure_login and (job.derived.effective_permissions.get("id-token") == "write")

    return wf
