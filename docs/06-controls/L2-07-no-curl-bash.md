# L2-07 — No Remote Script Execution via curl|bash (pipe-to-shell)

## 1. Summary
Detect and block high-risk patterns that execute remote content directly in a shell, such as `curl ... | bash`, `wget ... | sh`, or PowerShell `iwr ... | iex`.

## 2. Why it matters
Pipe-to-shell patterns execute unverified code. If the remote source is compromised (or traffic is intercepted), CI runners will execute attacker-controlled scripts, leading to supply-chain compromise.

## 3. Inputs (from IR)
- `step.kind`
- `step.run.command`
- `wf.source_text` (best-effort line hints)

## 4. Policy Configuration
```yaml
# L2-07
forbid_pipe_to_shell: true  # default true
```

## 5. Threat Model
Attackers compromise a download endpoint (or redirect traffic) and deliver malicious install scripts. Pipe-to-shell executes the script immediately, often with elevated permissions or access to secrets.

## 6. Evaluation Rules
- **R1**: Flag `curl|bash`, `wget|sh`, and PowerShell `Invoke-WebRequest|Invoke-Expression` patterns (including subshell variants).

## 7. Severity Guidance
- Default is **FAIL (High)** when `forbid_pipe_to_shell: true`.
- If policy relaxes the rule, report **WARN (Medium)**.

## 8. Auto-Fix Guidance (Optional)
Automatic fixes are not always safe, but recommended remediation includes:
- Download a fixed version to disk
- Verify checksum/signature (`sha256sum`, GPG, Sigstore)
- Execute the verified file
- Prefer official actions or package managers

## 9. Verification
- Re-run the scanner; ensure no pipe-to-shell patterns remain.
- Confirm downloads are pinned to fixed versions and verified.

## 10. Notes and Limitations
- Heuristic matching may miss obfuscated or dynamically generated commands.
- Line hints are best-effort unless YAML parsing preserves line/column metadata.

## 11. Related Controls
- L1-01 (Action pinning)
- L1-05 (Log leaks)
