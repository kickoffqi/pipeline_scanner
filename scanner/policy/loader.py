from __future__ import annotations

from typing import Dict, Any
from pydantic import ValidationError

from .schema import PolicySchema


class PolicyValidationError(Exception):
    pass


def validate_policy(raw: Dict[str, Any]) -> Dict[str, Any]:
    try:
        model = PolicySchema(**raw)
    except ValidationError as e:
        raise PolicyValidationError(str(e)) from e
    # return only explicitly set values
    return model.model_dump(exclude_unset=True)
