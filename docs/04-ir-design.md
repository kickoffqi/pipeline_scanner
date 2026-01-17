# IR Design (v1) - GitHub Actions

## 1. Purpose
IR（Intermediate Representation）用于把 GitHub Actions 的 YAML 表达，转换为本系统稳定、统一、易分析的结构。
Rules/Controls 只依赖 IR，不直接依赖 YAML。

## 2. Non-goals (v1)
- 不完整支持所有 GitHub Actions 语法（例如：复杂表达式求值、全部 matrix 展开、所有可重用 workflow 细节）。
- 不做运行时日志推断（v1 只做静态分析）。
- 不解析 step 内脚本语义（仅做关键模式匹配，如 set -x / curl|bash / secrets 引用）。

## 3. Design Principles
- 最小字段集支持最大控制项覆盖（优先服务 L1/L2）。
- 保留“证据定位”能力：文件路径 + 行号范围（方便 PR comment）。
- 派生字段（derived fields）优先：例如 uses_secrets / has_pull_request_target，避免规则重复计算。
- 可扩展：允许以后加入 matrix / reusable workflow / GitHub org settings 等。

## 4. IR Schema (v1)

### 4.1 Core Types

#### WorkflowIR
- id: str (internal)
- file_path: str
- name: str | None
- triggers: TriggerIR
- permissions: PermissionsIR (workflow-level)
- jobs: list[JobIR]
- derived: WorkflowDerivedIR

#### TriggerIR
- events: set[str]               # e.g. {"push", "pull_request", "pull_request_target", "workflow_dispatch"}
- raw: dict                      # 原始 on: 的结构（可选保留，便于未来扩展）

#### PermissionsIR
- mode: str                      # "implicit" | "explicit"
- entries: dict[str, str]        # e.g. {"contents": "read", "id-token": "write"}
    key: scope                   # contents, id-token, pull-requests, __all__
    value: none|read|write

#### JobIR
- job_id: str                    # YAML 里的 job key
- name: str | None
- runs_on: list[str]             # e.g. ["ubuntu-latest"] or ["self-hosted","linux","x64"]
- permissions: PermissionsIR (job-level, may override)
- environment: str | None        # environment name, if used
- steps: list[StepIR]
- derived: JobDerivedIR
- location: LocationIR

#### StepIR
- index: int
- name: str | None
- kind: str                      # "uses" | "run" | "other"
- uses: UsesRefIR | None
- run: RunIR | None
- env_keys: set[str]             # 仅记录 env key（默认不记录值，避免敏感泄露）
- derived: StepDerivedIR
- location: LocationIR

#### UsesRefIR
- full: str                      # 原始 uses 字符串，例如 "actions/checkout@v4"
- owner_repo: str | None         # "actions/checkout"
- ref: str | None                # "v4" or "main" or SHA
- ref_type: str | None           # "sha" | "tag" | "branch" | "unknown"
- is_third_party: bool | None    # 是否非 GitHub 官方/组织 allowlist（v1 可粗略）

#### RunIR
- shell: str | None
- command: str                   # 原始 run 内容（v1 保留全文，后续可做脱敏/摘要）

#### LocationIR
- file_path: str
- start_line: int | None
- end_line: int | None

### 4.2 Derived (v1)

#### WorkflowDerivedIR
- has_pull_request_target: bool
- has_pull_request: bool
- has_fork_risk_surface: bool         # 触发器含 pull_request/pull_request_target
- effective_permissions_mode: str     # "implicit"|"explicit"

#### JobDerivedIR
- uses_secrets: bool                 # 检测到 ${{ secrets.* }} / env 引用等
- uses_oidc: bool                    # 检测到 azure/login 且使用 id-token 或 oidc-like 参数（粗略）
- uses_self_hosted: bool
- dangerous_patterns: set[str]        # e.g. {"curl_pipe_bash","set_x","docker_sock","privileged"}
- effective_permissions: dict[str,str]
- effective_permissions_mode: "implicit"|"explicit"

#### StepDerivedIR
- references_secrets: bool
- has_set_x: bool
- has_curl_pipe_shell: bool

## 5. Permissions Resolution Rules
- effective = merge_permissions(workflow_perm, job_perm)


## 6. Mapping Rules (YAML -> IR)
- Workflow triggers:
  - on: push/pull_request/pull_request_target/workflow_dispatch -> TriggerIR.events
- Permissions:
  - permissions 缺失 => PermissionsIR.mode="implicit"
  - permissions 存在 => mode="explicit" + entries
- Jobs:
  - jobs.<job_id>.runs-on -> JobIR.runs_on
  - jobs.<job_id>.permissions -> JobIR.permissions
  - jobs.<job_id>.environment -> JobIR.environment
- Steps:
  - steps[].uses -> StepIR.kind="uses" + UsesRefIR
  - steps[].run -> StepIR.kind="run" + RunIR
  - steps[].env -> StepIR.env_keys 仅记录 key
- Derived:
  - 搜索 secrets 引用模式：${{ secrets.XXX }} / secrets["XXX"] / needs.*.outputs?（v1 先只做 secrets.*）
  - 搜索危险模式：set -x, curl|bash, wget|sh, docker.sock, --privileged

## 7. Why these fields (v1)
- L1-01 Action pin 需要 UsesRefIR.ref/ref_type
- L1-02 permissions 需要 PermissionsIR.mode/entries + job override
- L1-03 pull_request_target 需要 TriggerIR.events + job uses_secrets
- L1-04 fork secrets 需要 has_fork_risk_surface + uses_secrets
- L2-09 Azure OIDC 需要检测 azure/login + id-token 权限 + secrets 使用情况（粗略）

## 8. Example
Example01:
    name: CI
    on:
    pull_request:
        branches: [ "main" ]

    permissions: write-all

    jobs:
    build:
        runs-on: ubuntu-latest
        steps:
        - uses: actions/checkout@v4
        - run: |
            set -x
            echo "${{ secrets.MY_TOKEN }}"

IR:
    •	triggers.events = {“pull_request”}
	•	permissions.mode=“explicit”, entries={”all”:“write”}（或你实现成 write-all 特殊标记）
	•	job build:
	•	runs_on=[“ubuntu-latest”]
	•	derived.uses_secrets=True（因为出现 secrets.MY_TOKEN）
	•	derived.dangerous_patterns={“set_x”}
	•	step 0 uses:
	•	owner_repo=“actions/checkout”, ref=“v4”, ref_type=“tag”
	•	step 1 run:
	•	command 包含 set -x、secrets 引用

Example02: workflow implicit，job 不写
    on: push
    jobs:
    build:
        runs-on: ubuntu-latest
IR:
	•	workflow.permissions.mode = implicit
	•	job.permissions.mode = implicit
	•	effective = implicit（未知默认）

Example03: 
    permissions: workflow 最小化，job 不写
        contents: read
    jobs:
    build:
        runs-on: ubuntu-latest

IR:
    •	base = contents: read
	•	effective = contents: read

Example04: workflow 最小化，job 局部提升（OIDC）
    permissions:
    contents: read
    jobs:
    deploy:
        permissions:
        id-token: write
        steps: ...
IR:
    •	base = contents: read
	•	effective = contents: read, id-token: write

Example05: workflow 最小化，但 job write-all（危险）
    permissions:
    contents: read
    jobs:
    release:
        permissions: write-all
IR:
    •	base = contents: read
	•	effective = __all__: write