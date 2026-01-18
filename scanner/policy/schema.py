from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


class PolicySchema(BaseModel):
    # L1-01
    allow_semver_tags: Optional[bool] = Field(
        None,
        description="Allow semver tags for GitHub Actions. If false, require commit SHA pinning."
    )

    # L1-02
    require_explicit_permissions: Optional[bool] = Field(
        None,
        description="Require explicit permissions block for GITHUB_TOKEN."
    )
    forbid_write_all: Optional[bool] = Field(
        None,
        description="Forbid write-all permissions."
    )

    # L2-09 Azure OIDC
    require_azure_oidc: Optional[bool] = Field(
        None,
        description="Require Azure authentication to use OIDC instead of secrets."
    )
    forbid_azure_credentials_secret: Optional[bool] = Field(
        None,
        description="Forbid long-lived Azure credentials (client secrets / creds)."
    )
    require_id_token_write: Optional[bool] = Field(
        None,
        description="Require permissions.id-token: write for OIDC."
    )
    forbid_oidc_on_untrusted_triggers: Optional[bool] = Field(
        None,
        description="Forbid Azure OIDC authentication on pull_request / pull_request_target triggers."
    )
    trusted_triggers_for_oidc: Optional[List[str]] = Field(
        None,
        description="List of trusted triggers allowed for Azure OIDC authentication."
    )

    class Config:
        extra = "forbid"
