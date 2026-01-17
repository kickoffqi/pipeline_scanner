# L1-02 — Explicit and Least-Privilege Permissions

## Control ID
L1-02

## Title
Workflows and jobs must declare explicit and minimal permissions

---

## 1. Purpose (Why)

Implicit permissions depend on repository or organization defaults and are not auditable.
Overly broad permissions significantly increase the blast radius of compromised workflows.

---

## 2. Scope

This control applies to:
- Workflow-level permissions
- Job-level permissions
- Effective permissions after merging

---

## 3. Inputs (from IR)

- `workflow.permissions`
- `job.permissions`
- `job.derived.effective_permissions`
- `job.derived.effective_permissions_mode`

---

## 4. Policy Configuration

```yaml
require_explicit_permissions: true
forbid_write_all: true
```

---

## 5. Threat Model

Excessive or implicit permissions enable attackers to modify code, releases, or pull requests using compromised tokens.

---

## 6. Evaluation Rules

- If permissions are implicit, FAIL.
- If `write-all` is present, FAIL.
- CI jobs must not require write permissions.

---

## 7. Severity Guidance

| Condition | Severity |
|---------|----------|
| Implicit permissions | High |
| write-all | Critical |

---

## 8. Auto-Fix Guidance (Optional)

Insert minimal explicit permissions:

```yaml
permissions:
  contents: read
```

---

## 9. Verification

Permissions are explicit and follow least-privilege principles.

---

## 10. Notes and Limitations

Organization-level defaults are not evaluated.

---

## 11. Related Controls

- L1-01 — Immutable Action References
