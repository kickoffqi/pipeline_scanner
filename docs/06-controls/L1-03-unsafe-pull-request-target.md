# L1-03 — Unsafe pull_request_target Usage

## Control ID
L1-03

## Title
Unsafe usage of pull_request_target must be prevented

---

## 1. Purpose (Why)

The `pull_request_target` event executes workflows with trusted context while being triggered by untrusted pull requests.

---

## 2. Scope

This control applies to workflows triggered by `pull_request_target`.

---

## 3. Inputs (from IR)

- `workflow.triggers.events`
- `job.derived.uses_secrets`
- `step.kind`

---

## 4. Policy Configuration

```yaml
forbid_pr_target_with_code_execution: true
```

---

## 5. Threat Model

Attackers can submit malicious pull requests that execute code with elevated privileges.

---

## 6. Evaluation Rules

- If `pull_request_target` is used and code is executed, FAIL.
- If secrets are accessed, FAIL.

---

## 7. Severity Guidance

| Condition | Severity |
|---------|----------|
| Code execution | Critical |
| Secrets access | Critical |

---

## 8. Auto-Fix Guidance (Optional)

Use `pull_request` instead of `pull_request_target` when executing code.

---

## 9. Verification

No code execution or secret access under `pull_request_target`.

---

## 10. Notes and Limitations

Static analysis is conservative.

---

## 11. Related Controls

- L1-04 — Secrets Exposure in Fork Pull Requests
