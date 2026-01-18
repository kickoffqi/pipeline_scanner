from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Literal


RefType = Literal["sha", "tag", "branch", "unknown"]
StepKind = Literal["uses", "run", "other"]


@dataclass(frozen=True)
class LocationIR:
    file_path: str
    start_line: Optional[int] = None
    end_line: Optional[int] = None


@dataclass
class PermissionsIR:
    mode: Literal["implicit", "explicit"] = "implicit"
    entries: Dict[str, str] = field(default_factory=dict)  # e.g. {"contents": "read", "id-token": "write"}


@dataclass
class TriggerIR:
    events: Set[str] = field(default_factory=set)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UsesRefIR:
    full: str
    owner_repo: Optional[str] = None   # e.g. "actions/checkout"
    ref: Optional[str] = None          # e.g. "v4", "main", "<sha>"
    ref_type: RefType = "unknown"      # sha|tag|branch|unknown


@dataclass
class RunIR:
    shell: Optional[str] = None
    command: str = ""


@dataclass
class StepDerivedIR:
    references_secrets: bool = False
    has_set_x: bool = False
    has_curl_pipe_shell: bool = False


@dataclass
class StepIR:
    index: int
    name: Optional[str] = None
    kind: StepKind = "other"
    uses: Optional[UsesRefIR] = None
    run: Optional[RunIR] = None
    env_keys: Set[str] = field(default_factory=set)
    with_keys: Set[str] = field(default_factory=set)
    derived: StepDerivedIR = field(default_factory=StepDerivedIR)
    location: Optional[LocationIR] = None


@dataclass
class JobDerivedIR:
    uses_secrets: bool = False
    uses_oidc: bool = False
    uses_self_hosted: bool = False
    dangerous_patterns: Set[str] = field(default_factory=set)

    effective_permissions: Dict[str, str] = field(default_factory=dict)
    effective_permissions_mode: Literal["implicit", "explicit"] = "implicit"


@dataclass
class JobIR:
    job_id: str
    name: Optional[str] = None
    runs_on: List[str] = field(default_factory=list)
    permissions: PermissionsIR = field(default_factory=PermissionsIR)
    environment: Optional[str] = None
    steps: List[StepIR] = field(default_factory=list)
    derived: JobDerivedIR = field(default_factory=JobDerivedIR)
    location: Optional[LocationIR] = None


@dataclass
class WorkflowDerivedIR:
    has_pull_request_target: bool = False
    has_pull_request: bool = False
    has_fork_risk_surface: bool = False
    effective_permissions_mode: Literal["implicit", "explicit"] = "implicit"


@dataclass
class WorkflowIR:
    file_path: str
    name: Optional[str] = None
    triggers: TriggerIR = field(default_factory=TriggerIR)
    permissions: PermissionsIR = field(default_factory=PermissionsIR)
    jobs: List[JobIR] = field(default_factory=list)
    derived: WorkflowDerivedIR = field(default_factory=WorkflowDerivedIR)
