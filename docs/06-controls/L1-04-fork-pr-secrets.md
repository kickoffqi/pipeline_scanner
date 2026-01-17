# L1-04 — Secrets Exposure in Fork Pull Requests

## Control ID
L1-04

## Title
Secrets must not be exposed to fork-based pull request workflows

---

## 1. Purpose (Why)

Fork-based pull requests are untrusted and must not have access to secrets.

---

## 2. Scope

This control applies to workflows triggered by `pull_request` from forks.

---

## 3. Inputs (from IR)

- `workflow.triggers.events`
- `job.derived.uses_secrets`
- `job.environment`

---

## 4. Policy Configuration

```yaml
forbid_secrets_in_fork_pr: true
```

---

## 5. Threat Model

Attackers can exfiltrate secrets via fork-based pull requests.

---

## 6. Evaluation Rules

- If secrets are accessed in fork PR workflows, FAIL.

---

## 7. Severity Guidance

| Condition | Severity |
|---------|----------|
| Secrets exposure | Critical |

---

## 8. Auto-Fix Guidance (Optional)

Split workflows by trust boundary.

---

## 9. Verification

Fork PR jobs do not access secrets.

---

## 10. Notes and Limitations

Fork detection relies on GitHub event context.

---

## 11. Related Controls

- L1-03 — Unsafe pull_request_target Usage
