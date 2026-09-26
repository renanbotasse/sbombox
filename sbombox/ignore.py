from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from sbombox.models import Finding
from sbombox.util import normalize_name

# Recognize the advisory-ID namespaces the scanner emits; anything else on an
# ignore line is treated as a package name (PEP 503, case-insensitive).
ID_RE = re.compile(r"^(?:CVE|GHSA|PYSEC|MAL)-", re.IGNORECASE)

PackageIgnore = tuple[str, Optional[str]]  # (normalized name, version or None)


def classify_token(token: str) -> tuple[str, PackageIgnore | str]:
    """Return ('id', <ID>) for advisory IDs, else ('package', (name, version))."""
    token = token.strip()
    if ID_RE.match(token):
        return "id", token.upper()
    if "@" in token:
        name, _, version = token.partition("@")
        return "package", (normalize_name(name.strip()), version.strip() or None)
    return "package", (normalize_name(token), None)


def load_ignore_file(path: Path) -> tuple[set[str], set[PackageIgnore]]:
    ids: set[str] = set()
    packages: set[PackageIgnore] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ids, packages
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0].strip()
        if not token:
            continue
        kind, value = classify_token(token)
        if kind == "id":
            ids.add(value)  # type: ignore[arg-type]
        else:
            packages.add(value)  # type: ignore[arg-type]
    return ids, packages


def resolve_ignores(
    cli_ignores: list[str], vulnignore: Path, target: Path
) -> tuple[set[str], set[PackageIgnore]]:
    ids: set[str] = set()
    packages: set[PackageIgnore] = set()
    for token in cli_ignores:
        kind, value = classify_token(token)
        if kind == "id":
            ids.add(value)  # type: ignore[arg-type]
        else:
            packages.add(value)  # type: ignore[arg-type]

    paths: list[Path] = []
    if vulnignore.is_file():
        paths.append(vulnignore)
    alt = (target / ".vulnignore") if target.is_dir() else (target.parent / ".vulnignore")
    if alt.is_file() and alt.resolve() not in {p.resolve() for p in paths}:
        paths.append(alt)
    for path in paths:
        file_ids, file_pkgs = load_ignore_file(path)
        ids |= file_ids
        packages |= file_pkgs
    return ids, packages


def apply_ignores(
    findings: list[Finding],
    ignore_ids: set[str],
    ignore_packages: set[PackageIgnore],
) -> tuple[list[Finding], int]:
    kept: list[Finding] = []
    for f in findings:
        if f.all_ids() & ignore_ids:
            continue
        pkg_norm = normalize_name(f.package)
        if any(
            pkg_norm == name and (version is None or version == f.version)
            for name, version in ignore_packages
        ):
            continue
        kept.append(f)
    return kept, len(findings) - len(kept)