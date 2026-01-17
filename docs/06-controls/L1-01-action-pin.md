# L1-01 — Immutable Action References

## Control ID
L1-01

## Title
GitHub Actions must be pinned to immutable references (commit SHA)

---

## 1. Purpose (Why)

GitHub Actions referenced via `uses:` execute third-party code as part of the CI/CD pipeline.

If actions are referenced using mutable identifiers such as branches or tags, the executed code may change over time without any modification to the workflow file, introducing significant supply-chain risk.

This control enforces the use of immutable references to ensure deterministic, reproducible, and auditable pipelines.

---

## 2. Scope

This control applies to:
- All `uses:` steps in GitHub Actions workflows
- Both first-party and third-party actions

This control does not:
- Validate the security of the referenced action source code
- Enforce allowlists of trusted action owners

---

## 3. Inputs (from IR)

- `step.kind`
- `step.uses.owner_repo`
- `step.uses.ref`
- `step.uses.ref_type` (`sha | tag | branch | unknown`)
- `step.location`

---

## 4. Policy Configuration

```yaml
require_immutable_actions: true
allow_semver_tags: false
```

---

## 5. Threat Model

Attackers may compromise an action repository or retarget a branch or tag to execute malicious code in downstream pipelines.

Mutable references enable:
- Silent code substitution
- Non-reproducible builds
- Widespread supply-chain compromise

---

## 6. Evaluation Rules

**Rule 0 — Applicability**  
If `step.kind != "uses"`, skip evaluation.

**Rule 1 — Branch References**  
If `step.uses.ref_type == "branch"`, FAIL.

**Rule 2 — Tag References**  
If `step.uses.ref_type == "tag"` and `allow_semver_tags == false`, FAIL.

**Rule 3 — Commit SHA**  
If `step.uses.ref_type == "sha"`, PASS.

**Rule 4 — Unknown Reference**  
If `step.uses.ref_type == "unknown"`, WARN.

---

## 7. Severity Guidance

| Condition | Severity |
|---------|----------|
| Branch reference | High |
| Tag reference | High |
| Unknown reference | Medium |
| Commit SHA | None |

---

## 8. Auto-Fix Guidance (Optional)

Replace branch or tag references with resolved commit SHAs where possible.

---

## 9. Verification

All `uses:` steps reference immutable commit SHAs.

---

## 10. Notes and Limitations

- Tags in GitHub Actions are mutable.
- Official actions are not exempt from this control.

---

## 11. Related Controls

- L1-02 — Explicit and Least-Privilege Permissions
