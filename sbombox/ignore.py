from __future__ import annotations

import re
from pathlib import Path

from typing import Optional

from sbombox.models import Finding
from sbombox.util import log

# Only advisory IDs are accepted. Package-name ignores are intentionally unsupported:
# silencing a whole package would hide future CRITICAL/MAL findings from the CI gate.
ID_RE = re.compile(r"^(?:CVE|GHSA|PYSEC|MAL)-", re.IGNORECASE)


def _accept_ignore_token(token: str) -> Optional[str]:
    token = token.strip()
    if not token:
        return None
    if not ID_RE.match(token):
        log(
            f"warning: ignore token ignored (advisory ID required, "
            f"not package name): {token}"
        )
        return None
    return token.upper()


def load_ignore_file(path: Path) -> set[str]:
    ids: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ids
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0].strip()
        accepted = _accept_ignore_token(token)
        if accepted:
            ids.add(accepted)
    return ids


def resolve_ignores(cli_ignores: list[str], vulnignore: Path, target: Path) -> set[str]:
    ignores: set[str] = set()
    for token in cli_ignores:
        accepted = _accept_ignore_token(token)
        if accepted:
            ignores.add(accepted)

    paths: list[Path] = []
    if vulnignore.is_file():
        paths.append(vulnignore)
    alt = (target / ".vulnignore") if target.is_dir() else (target.parent / ".vulnignore")
    if alt.is_file() and alt.resolve() not in {p.resolve() for p in paths}:
        paths.append(alt)
    for path in paths:
        ignores |= load_ignore_file(path)
    return ignores


def apply_ignores(findings: list[Finding], ignores: set[str]) -> tuple[list[Finding], int]:
    kept = [f for f in findings if not (f.all_ids() & ignores)]
    return kept, len(findings) - len(kept)
