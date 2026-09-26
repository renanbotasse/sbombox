from __future__ import annotations

import re
from typing import Any, Iterable, Optional


def version_key(version: str) -> tuple:
    """Loose numeric key for comparing common PyPI versions (PEP 440 subset).

    Every element is a ``(tag, value)`` pair — tag 0 for numeric chunks,
    tag 1 for letter suffixes — so tuple comparison never mixes ``int`` and
    ``str`` at the same position. The naive flat list crashed with
    ``TypeError: '<' not supported between instances of 'str' and 'int'``
    whenever a dot-separated numeric chunk met a letter-suffixed chunk
    (e.g. ``2.0rc1`` vs ``2.0.0rc1``, which OSV fixed-version lists commonly
    produce).
    """
    text = (version or "").strip().lstrip("vV")
    if not text or text == "0":
        return ((0, 0),)
    text = text.split("+", 1)[0]
    if "!" in text:
        text = text.split("!", 1)[1]
    parts: list[tuple[int, Any]] = []
    for chunk in re.split(r"[.\-_]", text):
        if not chunk:
            continue
        m = re.match(r"^(\d+)(.*)$", chunk)
        if m:
            parts.append((0, int(m.group(1))))
            rest = m.group(2)
            if rest:
                # Negative pad: a letter-suffixed chunk (a1/b2/rc1...) is a
                # prerelease, so "1.26rc1" must sort BELOW "1.26.0" — the
                # exact pairing OSV fixed-version lists produce (current is a
                # prerelease, fix is the release). A plain 0 pad sorted it
                # above the whole numeric line.
                parts.append((0, -1))
                parts.append((1, rest))
        else:
            parts.append((0, 0))
            parts.append((1, chunk))
    return tuple(parts) if parts else ((0, 0),)


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
