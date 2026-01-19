# Policy Configuration Reference

This document describes all supported policy options for the GitHub Actions Security Scanner.

Policies are validated against a strict schema. Unknown keys will cause validation errors.

---

## L1-01 Action Pinning

### `allow_semver_tags` (boolean)
- **Description**: Allow semver tags for GitHub Actions instead of requiring commit SHA pinning.
- **Default**:
  - L1: `true`
  - L2/L3: `false`
- **Recommendation**: Use `false` for higher security environments.

---

## L1-02 Permissions

### `require_explicit_permissions` (boolean)
- **Description**: Require an explicit `permissions:` block for `GITHUB_TOKEN`.
- **Default**: `true`
- **Recommendation**: Always enabled.

### `forbid_write_all` (boolean)
- **Description**: Forbid `write-all` permissions.
- **Default**: `true`
- **Recommendation**: Always enabled.

---

## L2-09 Azure OIDC

### `require_azure_oidc` (boolean)
- **Description**: Require Azure authentication to use OIDC instead of secrets.
- **Default**: `true`

### `forbid_azure_credentials_secret` (boolean)
- **Description**: Forbid long-lived Azure credentials (client secrets / creds).
- **Default**: `true`

### `require_id_token_write` (boolean)
- **Description**: Require `permissions: id-token: write` for OIDC.
- **Default**: `true`

### `forbid_oidc_on_untrusted_triggers` (boolean)
- **Description**: Forbid Azure OIDC authentication on `pull_request` and `pull_request_target` triggers.
- **Default**:
  - L1: `false`
  - L2/L3: `true`

### `trusted_triggers_for_oidc` (list[string])
- **Description**: List of trusted triggers allowed for Azure OIDC authentication.
- **Default**: `["push", "workflow_dispatch", "schedule"]`

---

## Example Policy

```yaml
allow_semver_tags: false
require_explicit_permissions: true
forbid_write_all: true
require_azure_oidc: true
forbid_azure_credentials_secret: true
require_id_token_write: true
forbid_oidc_on_untrusted_triggers: true
```
