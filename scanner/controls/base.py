from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, Any, List

from ..ir.models import WorkflowIR
from ..findings import Finding


class Control(ABC):
    control_id: str

    @abstractmethod
    def evaluate(self, wf: WorkflowIR, policy: Dict[str, Any]) -> List[Finding]:
        raise NotImplementedError
