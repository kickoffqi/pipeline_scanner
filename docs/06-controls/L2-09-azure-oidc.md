# L2-09 — Azure Authentication via OIDC (Workload Identity)

## Control ID
L2-09

## Title
Azure authentication in GitHub Actions must use OIDC (workload identity) and forbid long-lived secrets

---

## 1. Purpose (Why)

Using long-lived Azure credentials (client secrets, JSON credentials, service principal passwords) in CI/CD introduces high-impact risk:
- Secrets can be exfiltrated via logs, artifacts, or malicious PR code.
- Leaked credentials can be abused long after the workflow run completes.
- Rotation and auditing are difficult at scale.

GitHub Actions supports OpenID Connect (OIDC) to obtain short-lived tokens for Azure (workload identity / federated credentials). OIDC enables:
- No stored long-lived cloud secrets in GitHub
- Tight scoping by repository, environment, and branch
- Improved auditing and reduced blast radius

This control enforces OIDC-based Azure authentication and blocks secret-based Azure login patterns.

---

## 2. Scope

This control applies to:
- Workflows that authenticate to Azure from GitHub Actions
- Azure login steps (e.g., `azure/login`) and downstream Azure CLI/SDK usage

This control does not:
- Validate Azure role assignments (handled by separate controls/policies)
- Guarantee runtime token usage correctness beyond static analysis
- Cover non-Azure clouds

---

## 3. Inputs (from IR)

This control consumes the following IR fields:

- `workflow.triggers.events`
- `workflow.permissions`
- `job.permissions`
- `job.derived.effective_permissions`
- `job.derived.effective_permissions_mode`
- `job.derived.uses_secrets`
- `job.derived.uses_oidc` (derived)
- `job.environment`
- `steps[].kind`
- `steps[].uses.owner_repo`
- `steps[].uses.ref`
- `steps[].run.command`
- `steps[].env_keys`
- `step.location`

> Controls MUST rely on derived IR fields (e.g., `effective_permissions`, `uses_oidc`) and MUST NOT inspect secret values.

---

## 4. Policy Configuration

Recommended policy defaults for **L2**:

```yaml
require_azure_oidc: true
forbid_azure_credentials_secret: true
require_id_token_write: true

azure_login_actions_allowlist:
  - azure/login
```

Optional stricter settings:

```yaml
forbid_azure_client_secret_inputs: true
forbid_oidc_on_untrusted_triggers: true
trusted_triggers_for_oidc:
  - push
  - workflow_dispatch
  - schedule
```

---

## 5. Threat Model

Primary attacker paths:
- Malicious pull request code reads environment variables and prints them to logs.
- Compromised third-party action exfiltrates injected secrets.
- Shared/self-hosted runners leak secrets via filesystem or process inspection.

Long-lived Azure secrets enable persistent compromise. OIDC reduces risk by using short-lived tokens bound to a specific workflow identity and conditions (repo/ref/environment), with no reusable secret stored in GitHub.

---

## 6. Evaluation Rules

### Rule 0 — Applicability
This control evaluates a job if **any** of the following is detected:
- A `uses:` step with `owner_repo` matching an allowlisted Azure login action (e.g., `azure/login`), OR
- A `run:` step containing Azure CLI usage patterns (e.g., `az login`, `az account`, `az deployment`, `az keyvault`)

If none are detected, **SKIP**.

---

### Rule 1 — Secret-Based Azure Credentials Are Forbidden (L2)
**FAIL** if any of the following are detected in the job:
- `job.derived.uses_secrets == true` **and** the Azure login step is present (conservative)
- Environment keys suggest secret injection for Azure credentials (case-insensitive match), e.g.:
  - `AZURE_CREDENTIALS`
  - `AZURE_CLIENT_SECRET`
  - `AZURE_SECRET`
- Azure login step inputs imply secret-based login patterns (when available in IR), such as:
  - `client-secret` present
  - `creds` present

Message:
```
Azure authentication must use OIDC. Long-lived Azure credentials (client secrets / creds) are forbidden.
```

---

### Rule 2 — OIDC Requires `id-token: write`
**FAIL** if:
- Azure authentication is detected, AND
- Policy requires OIDC (`require_azure_oidc: true`), AND
- Effective permissions do not include `id-token: write`

Message:
```
OIDC requires `permissions: id-token: write`. Add minimal id-token permission to the Azure job.
```

---

### Rule 3 — Prefer Least Privilege Permissions for Azure Jobs
**WARN** if the Azure job contains unnecessary write permissions (example checks):
- `__all__: write`
- `contents: write` (often not needed for deploy)

Message:
```
Azure deploy jobs should use least-privilege permissions. Review write scopes in this job.
```

---

### Rule 4 — Untrusted Triggers (Optional Hardening)
If `forbid_oidc_on_untrusted_triggers: true`, then **FAIL** if:
- Workflow trigger includes `pull_request` (especially forks), AND
- Azure authentication is present in the same workflow/job

Message:
```
OIDC/Azure authentication must not run on untrusted PR triggers. Split workflows by trust boundary.
```

---

## 7. Severity Guidance

| Condition | Severity |
|---------|----------|
| Secret-based Azure credentials detected | Critical |
| Missing `id-token: write` while requiring OIDC | High |
| Excessive repo write permissions in Azure job | Medium (Warn) |
| Azure auth on untrusted PR triggers (if enforced) | Critical/High |

---

## 8. Auto-Fix Guidance (Optional)

### Auto-Fix A — Add Minimal OIDC Permissions
Add to workflow or job:

```yaml
permissions:
  contents: read
  id-token: write
```

### Auto-Fix B — Replace Secret-Based Azure Login with OIDC Pattern
Recommended approach:
- Use `azure/login` with OIDC parameters (tenant, subscription, client-id)
- Configure Federated Credentials in Microsoft Entra ID for the GitHub OIDC subject

### Auto-Fix C — Split Workflows by Trust Boundary
- `pull_request`: build/test without cloud access
- `push` to protected branches / `workflow_dispatch`: deploy with OIDC

> Auto-fix should generate a patch (diff) and a migration checklist, not silently change deployment semantics.

---

## 9. Verification

This control is considered **passed** when:
- Azure authentication is performed via OIDC (no long-lived secrets used)
- Effective permissions include `id-token: write` and are least-privilege

Recommended evidence to include in reports:
- Detected Azure login method (OIDC vs secret-based)
- Job effective permissions summary
- File/line locations of relevant steps

Optional runtime verification (future enhancement):
- Confirm `azure/login` reports OIDC usage in job logs
- Confirm Azure sign-in logs show federated workload identity (Entra ID)

---

## 10. Notes and Limitations

- Static analysis cannot always conclusively prove OIDC is used; conservative heuristics are applied.
- Organizations may choose to allow semver-pinned `azure/login` in L2, but SHA pinning is recommended.
- Azure role scoping and least-privilege RBAC are out of scope for this control and should be enforced separately.

---

## 11. Related Controls

- L1-02 — Explicit and Least-Privilege Permissions
- L1-03 — Unsafe pull_request_target Usage
- L1-04 — Secrets Exposure in Fork Pull Requests
