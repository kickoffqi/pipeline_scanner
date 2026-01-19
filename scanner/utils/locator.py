from __future__ import annotations

from typing import Optional
import re


def find_first_uses_line(text: str | None, uses_value: str) -> Optional[int]:
    if not text:
        return None
    pattern = re.compile(r"^\s*-\s*uses:\s*%s\s*$" % re.escape(uses_value))
    for i, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            return i
    return None


def find_permissions_line(text: str | None) -> Optional[int]:
    if not text:
        return None
    pattern = re.compile(r"^\s*permissions:\s*$")
    for i, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            return i
    return None
