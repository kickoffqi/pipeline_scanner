# L1-05 — Prevent Sensitive Data Leakage in Logs

## 1. Summary
This control detects common workflow patterns that can leak secrets or sensitive values into GitHub Actions logs, such as `set -x`, dumping environment variables, or directly printing `${{ secrets.* }}`.

## 2. Why it matters
Workflow logs are often retained, exported, or shared. If secrets appear in logs, they can be harvested by anyone with access to the workflow run logs or artifacts.

## 3. Inputs (from IR)
- `step.kind`
- `step.run.command`
- `wf.source_text` (best-effort line hints)

## 4. Policy Configuration
```yaml
# L1-05
forbid_secret_echo: true   # default true
forbid_set_x: false        # default false (WARN at L1)
forbid_env_dump: false     # default false (WARN at L1)
```

## 5. Threat Model
Attackers and accidental misconfigurations can exfiltrate secrets via logs. Once printed, secrets may be accessible in CI logs, artifacts, or external log aggregators.

## 6. Evaluation Rules
- **R1 (set -x / xtrace)**: Detect `set -x` / `set -o xtrace` / `xtrace`.
- **R2 (env dump)**: Detect `printenv`, `env`, or PowerShell `Env:` dumping patterns.
- **R3 (echo secrets)**: Detect `${{ secrets.* }}` used together with a print/echo-like command.

## 7. Severity Guidance
- **R3**: High (FAIL by default)
- **R2**: Medium (WARN by default; may be FAIL if policy forbids env dumps)
- **R1**: Medium (WARN by default; may be FAIL if policy forbids xtrace)

## 8. Auto-Fix Guidance (Optional)
Automatic fixes are not always safe, but recommended remediation includes:
- Remove secret printing entirely.
- Avoid `set -x`, or scope it to non-sensitive commands.
- Avoid full environment dumps; print specific non-sensitive variables only.
- Use masking if absolutely necessary: `echo "::add-mask::$VALUE"`.

## 9. Verification
- Re-run the scanner and confirm L1-05 reports PASS (or only expected WARNs).
- Manually review workflow logs to ensure sensitive values are not printed.

## 10. Notes and Limitations
- This is heuristic-based detection. It may miss obfuscated patterns or flag benign usage.
- Precise line mapping is best-effort unless YAML parsing preserves line/column metadata.

## 11. Related Controls
- L1-04 (Fork PR secrets)
- L2-07 (curl|bash remote execution)
