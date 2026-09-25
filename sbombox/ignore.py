from __future__ import annotations

from pathlib import Path

from sbombox.models import Finding


def load_ignore_file(path: Path) -> set[str]:
    ids: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0].strip()
        if token:
            ids.add(token.upper())
    return ids


def resolve_ignores(cli_ignores: list[str], vulnignore: Path, target: Path) -> set[str]:
    ignores = {i.strip().upper() for i in cli_ignores if i.strip()}
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
