from __future__ import annotations

import re
from typing import Literal

RefType = Literal["sha", "tag", "branch", "unknown"]

_SHA40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SEMVER_TAG_RE = re.compile(r"^v?\d+(?:\.\d+){0,2}(?:[-+][0-9A-Za-z.-]+)?$")

_BRANCH_LIKELY = {"main", "master", "develop", "dev", "trunk", "head", "latest"}


def classify_ref_type(ref: str) -> RefType:
    r = ref.strip()
    if _SHA40_RE.match(r):
        return "sha"
    # very common moving references
    if r in _BRANCH_LIKELY:
        return "branch"
    # treat other non-semver strings with slashes as branches, conservatively
    if "/" in r and not _SEMVER_TAG_RE.match(r):
        return "branch"
    # semver-like tags and vN tags
    if _SEMVER_TAG_RE.match(r) or re.match(r"^v\d+$", r):
        return "tag"
    # Unknown: could be a tag or branch; treat as unknown for now
    return "unknown"
