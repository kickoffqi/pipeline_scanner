from __future__ import annotations

from typing import Any, Dict


# Policy presets are intentionally small, opinionated override bundles.
# They are merged on top of the per-level defaults.


PRESETS_BY_LEVEL: Dict[str, Dict[str, Dict[str, Any]]] = {
    "L1": {
        # Use code defaults as-is.
        "default": {},

        # Stronger guardrails for teams that want fewer WARNs and more FAILs.
        "strict": {
            "forbid_secret_echo": True,
            "forbid_set_x": True,
            "forbid_env_dump": True,
        },

        # Education mode: keep the high-signal items, avoid noisy failures.
        "relaxed": {
            "forbid_secret_echo": True,
            "forbid_set_x": False,
            "forbid_env_dump": False,
        },
    },
    "L2": {
        "default": {},
        "strict": {
            "forbid_secret_echo": True,
            "forbid_set_x": True,
            "forbid_env_dump": True,
        },
        "relaxed": {
            "forbid_secret_echo": True,
            "forbid_set_x": False,
            "forbid_env_dump": False,
        },
    },
    "L3": {
        "default": {},
        "strict": {
            "forbid_secret_echo": True,
            "forbid_set_x": True,
            "forbid_env_dump": True,
        },
        "relaxed": {
            "forbid_secret_echo": True,
            "forbid_set_x": False,
            "forbid_env_dump": False,
        },
    },
}


PRESET_NAMES = ["default", "strict", "relaxed"]


def get_preset_policy(level: str, preset: str) -> Dict[str, Any]:
    lvl = (level or "L1").strip().upper()
    name = (preset or "default").strip().lower()
    return dict(PRESETS_BY_LEVEL.get(lvl, {}).get(name, {}))
