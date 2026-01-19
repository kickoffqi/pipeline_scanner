from __future__ import annotations

from typing import Any
import re
import yaml

from .models import (
    WorkflowIR, TriggerIR, PermissionsIR, JobIR, StepIR, UsesRefIR, RunIR
)
from ..utils.text import classify_ref_type


def _parse_permissions(node: Any) -> PermissionsIR:
    # GitHub Actions supports:
    # permissions: read-all | write-all
    # permissions: { contents: read, id-token: write }
    if node is None:
        return PermissionsIR(mode="implicit", entries={})

    if isinstance(node, str):
        val = node.strip().lower()
        if val == "read-all":
            return PermissionsIR(mode="explicit", entries={"__all__": "read"})
        if val == "write-all":
            return PermissionsIR(mode="explicit", entries={"__all__": "write"})
        return PermissionsIR(mode="explicit", entries={"__raw__": val})

    if isinstance(node, dict):
        entries = {}
        for k, v in node.items():
            if not isinstance(k, str):
                continue
            if isinstance(v, str):
                entries[k.strip()] = v.strip().lower()
            else:
                entries[k.strip()] = str(v).strip().lower()
        return PermissionsIR(mode="explicit", entries=entries)

    return PermissionsIR(mode="explicit", entries={"__raw__": str(node)})


def _parse_triggers(on_node: Any) -> TriggerIR:
    trig = TriggerIR()
    trig.raw = on_node if isinstance(on_node, dict) else {"__raw__": on_node}

    if on_node is None:
        return trig

    if isinstance(on_node, str):
        trig.events.add(on_node)
        return trig

    if isinstance(on_node, list):
        for it in on_node:
            if isinstance(it, str):
                trig.events.add(it)
        return trig

    if isinstance(on_node, dict):
        for k in on_node.keys():
            if isinstance(k, str):
                trig.events.add(k)
        return trig

    return trig


_USES_RE = re.compile(r"^([^@\s]+)@([^\s]+)$")


def _parse_uses(value: str) -> UsesRefIR:
    full = value.strip()
    m = _USES_RE.match(full)
    if not m:
        return UsesRefIR(full=full, owner_repo=None, ref=None, ref_type="unknown")
    owner_repo, ref = m.group(1), m.group(2)
    ref_type = classify_ref_type(ref)
    return UsesRefIR(full=full, owner_repo=owner_repo, ref=ref, ref_type=ref_type)


def parse_workflow_yaml(file_path: str, text: str) -> WorkflowIR:
    data = yaml.safe_load(text) or {}
    wf = WorkflowIR(file_path=file_path, name=(data.get("name") if isinstance(data, dict) else None))
    wf.source_text = text

    if not isinstance(data, dict):
        return wf

    wf.triggers = _parse_triggers(data.get("on"))
    wf.permissions = _parse_permissions(data.get("permissions"))

    jobs_node = data.get("jobs", {})
    if not isinstance(jobs_node, dict):
        return wf

    for job_id, job_node in jobs_node.items():
        if not isinstance(job_id, str) or not isinstance(job_node, dict):
            continue

        job = JobIR(job_id=job_id, name=job_node.get("name") if isinstance(job_node.get("name"), str) else None)

        runs_on = job_node.get("runs-on")
        if isinstance(runs_on, str):
            job.runs_on = [runs_on]
        elif isinstance(runs_on, list):
            job.runs_on = [str(x) for x in runs_on]
        else:
            job.runs_on = []

        job.permissions = _parse_permissions(job_node.get("permissions"))

        env = job_node.get("environment")
        if isinstance(env, str):
            job.environment = env
        elif isinstance(env, dict) and isinstance(env.get("name"), str):
            job.environment = env.get("name")

        steps_node = job_node.get("steps", [])
        if isinstance(steps_node, list):
            for idx, st in enumerate(steps_node):
                step = StepIR(index=idx)

                if isinstance(st, dict):
                    if isinstance(st.get("name"), str):
                        step.name = st.get("name")

                    if isinstance(st.get("uses"), str):
                        step.kind = "uses"
                        step.uses = _parse_uses(st["uses"])
                    elif isinstance(st.get("run"), str):
                        step.kind = "run"
                        step.run = RunIR(
                            shell=st.get("shell") if isinstance(st.get("shell"), str) else None,
                            command=st["run"],
                        )
                    else:
                        step.kind = "other"

                    with_node = st.get("with")
                    if isinstance(with_node, dict):
                        for k in with_node.keys():
                            if isinstance(k, str):
                                step.with_keys.add(k)

                    env_node = st.get("env")
                    if isinstance(env_node, dict):
                        for k in env_node.keys():
                            if isinstance(k, str):
                                step.env_keys.add(k)

                job.steps.append(step)

        wf.jobs.append(job)

    return wf
