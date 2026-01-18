from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Dict, Any, Literal

Status = Literal["PASS", "WARN", "FAIL", "SKIP"]
Severity = Literal["None", "Low", "Medium", "High", "Critical"]


@dataclass
class Finding:
    control_id: str
    status: Status
    severity: Severity
    message: str
    file_path: str
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    rule_id: Optional[str] = None
    explain: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        out = {
            "control_id": self.control_id,
            "status": self.status,
            "severity": self.severity,
            "message": self.message,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "rule_id": self.rule_id,
            "explain": self.explain or {},
            "metadata": self.metadata or {},
        }
        return out
