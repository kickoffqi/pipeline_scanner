from __future__ import annotations

from typing import Dict, Any


def explain_pack(*, why: str, detect: str, fix: str, verify: str, difficulty: str) -> Dict[str, Any]:
    """Standard explanation payload to help junior engineers understand findings."""
    return {
        "why": why,
        "detect": detect,
        "fix": fix,
        "verify": verify,
        "difficulty": difficulty,
    }
