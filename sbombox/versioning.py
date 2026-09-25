from __future__ import annotations

import re
from typing import Any, Iterable, Optional


def version_key(version: str) -> tuple:
    """Loose numeric key for comparing common PyPI versions (PEP 440 subset)."""
    text = (version or "").strip().lstrip("vV")
    if not text or text == "0":
        return (0,)
    text = text.split("+", 1)[0]
    if "!" in text:
        text = text.split("!", 1)[1]
    parts: list[Any] = []
    for chunk in re.split(r"[.\-_]", text):
        if not chunk:
            continue
        m = re.match(r"^(\d+)(.*)$", chunk)
        if m:
            parts.append(int(m.group(1)))
            rest = m.group(2)
            if rest:
                parts.append(0)
                parts.append(rest)
        else:
            parts.append(0)
            parts.append(chunk)
    return tuple(parts) if parts else (0,)


def version_cmp(a: str, b: str) -> int:
    ka, kb = version_key(a), version_key(b)
    if ka < kb:
        return -1
    if ka > kb:
        return 1
    return 0


def pick_fixed_version(current: str, candidates: Iterable[str]) -> Optional[str]:
    """Prefer same major.minor line, else same major, else earliest version above current.

    Never suggest a downgrade (fixed < current).
    """
    newer = sorted(
        {c.strip() for c in candidates if c and c.strip() and version_cmp(c, current) > 0},
        key=version_key,
    )
    if not newer:
        return None

    cur = version_key(current)
    if len(cur) >= 2:
        same_line = [
            c
            for c in newer
            if len(version_key(c)) >= 2
            and version_key(c)[0] == cur[0]
            and version_key(c)[1] == cur[1]
        ]
        if same_line:
            return same_line[0]

    if cur:
        same_major = [c for c in newer if version_key(c) and version_key(c)[0] == cur[0]]
        if same_major:
            return same_major[0]

    return newer[0]


def better_fixed_in(current: str, a: Optional[str], b: Optional[str]) -> Optional[str]:
    """Choose the better upgrade target between two fixed-in suggestions."""
    return pick_fixed_version(current, [x for x in (a, b) if x])
