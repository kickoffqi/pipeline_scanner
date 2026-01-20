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

def find_on_line(text: str | None) -> Optional[int]:
    """Best-effort 1-based line number for the top-level `on:` key."""
    if not text:
        return None
    pattern = re.compile(r"^\s*on:\s*.*$")
    for i, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            return i
    return None


def find_trigger_line(text: str | None, event: str) -> Optional[int]:
    """Best-effort 1-based line number for a trigger inside `on:`.

    Handles common forms:
      - on: { pull_request: {...} }
      - on:
          pull_request:
          push:
      - on: [push, pull_request]
    """
    if not text:
        return None

    event = event.strip()
    # mapping style: line begins with the event key, typically indented under `on:`
    pattern_key = re.compile(r"^\s*%s\s*:\s*(#.*)?$" % re.escape(event))

    # list style: on: [push, pull_request]
    pattern_list = re.compile(r"^\s*on:\s*\[(.*?)\]\s*(#.*)?$")

    for i, line in enumerate(text.splitlines(), start=1):
        if pattern_key.search(line):
            return i
        m = pattern_list.search(line)
        if m:
            inside = m.group(1)
            # naive contains check with token boundaries
            tokens = [t.strip().strip("'\"") for t in inside.split(",")]
            if event in tokens:
                return i  # best effort: same line as `on: [...]`
    return None
