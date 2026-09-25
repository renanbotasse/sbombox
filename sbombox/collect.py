from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable, Iterable, Optional

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

from sbombox.models import Package

REQ_LINE_RE = re.compile(
    r"""^\s*
    (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)
    (?:\[[^\]]*\])?
    \s*
    (?P<op>===|==|!=|<=|>=|~=|<|>)?
    \s*
    (?P<version>[^\s;\\]+)?
    """,
    re.VERBOSE,
)


def collect_packages(target: Path, force_env: bool = False) -> tuple[list[Package], list[str], str]:
    """Return (packages, warnings, source_label)."""
    warnings: list[str] = []

    if force_env or (not target.is_dir() and target.name == "--env"):
        return from_environment(), warnings, "environment"

    if target.is_file():
        return _collect_from_file(target, warnings)

    for name, loader in (
        ("poetry.lock", from_poetry_lock),
        ("uv.lock", from_uv_lock),
        ("Pipfile.lock", from_pipfile_lock),
        ("requirements.txt", from_requirements),
    ):
        path = target / name
        if path.is_file():
            pkgs, warns = loader(path)
            warnings.extend(warns)
            return pkgs, warnings, name

    pkgs = from_environment()
    if not pkgs:
        warnings.append("No lock/requirements found and no installed packages detected.")
    return pkgs, warnings, "environment"


def _collect_from_file(path: Path, warnings: list[str]) -> tuple[list[Package], list[str], str]:
    name = path.name.lower()
    loaders: dict[str, Callable[[Path], tuple[list[Package], list[str]]]] = {
        "poetry.lock": from_poetry_lock,
        "uv.lock": from_uv_lock,
        "pipfile.lock": from_pipfile_lock,
    }
    if name in loaders:
        pkgs, warns = loaders[name](path)
    elif name.endswith(".txt") or "requirements" in name:
        pkgs, warns = from_requirements(path)
    else:
        raise SystemExit(f"Unsupported dependency file: {path}")
    warnings.extend(warns)
    return pkgs, warnings, path.name


def dedupe_packages(packages: Iterable[Package]) -> list[Package]:
    seen: dict[tuple[str, str], Package] = {}
    for pkg in packages:
        key = (pkg.normalized, pkg.version)
        if key not in seen:
            seen[key] = pkg
    return sorted(seen.values(), key=lambda p: (p.normalized, p.version))


def from_requirements(path: Path, seen_files: Optional[set[Path]] = None) -> tuple[list[Package], list[str]]:
    warnings: list[str] = []
    packages: list[Package] = []
    seen_files = seen_files or set()
    resolved = path.resolve()
    if resolved in seen_files:
        return [], warnings
    seen_files.add(resolved)

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        warnings.append(f"Cannot read {path}: {e}")
        return [], warnings

    i = 0
    while i < len(lines):
        raw = lines[i].strip()
        i += 1
        if not raw or raw.startswith("#"):
            continue
        while raw.endswith("\\") and i < len(lines):
            raw = raw[:-1].rstrip() + " " + lines[i].strip()
            i += 1

        if " #" in raw:
            raw = raw.split(" #", 1)[0].strip()

        if raw.startswith("-r ") or raw.startswith("--requirement "):
            inc = raw.split(None, 1)[1].strip()
            nested, warns = from_requirements((path.parent / inc).resolve(), seen_files)
            packages.extend(nested)
            warnings.extend(warns)
            continue

        if raw.startswith("-") or raw.startswith("--"):
            if raw.startswith("-e ") or raw.startswith("--editable "):
                warnings.append(f"Skipping editable install: {raw}")
            continue

        raw = re.sub(r"\s+--hash=\S+", "", raw).strip()
        m = REQ_LINE_RE.match(raw)
        if not m:
            warnings.append(f"Unparseable requirements line: {raw}")
            continue
        name = m.group("name")
        op = m.group("op")
        version = m.group("version")
        if op == "==" and version:
            packages.append(Package(name=name, version=version.strip("\"'"), source=str(path)))
        else:
            warnings.append(f"Unpinned requirement skipped (need ==): {raw}")
    return packages, warnings


def _require_tomllib(kind: str) -> None:
    if tomllib is None:
        raise SystemExit(
            f"Reading {kind} requires Python 3.11+ (tomllib). "
            "Upgrade Python or pass requirements.txt / --env."
        )


def _from_toml_lock(path: Path, kind: str) -> tuple[list[Package], list[str]]:
    _require_tomllib(kind)
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    packages = [
        Package(name=entry["name"], version=entry["version"], source=str(path))
        for entry in data.get("package", []) or []
        if entry.get("name") and entry.get("version")
    ]
    return packages, []


def from_poetry_lock(path: Path) -> tuple[list[Package], list[str]]:
    return _from_toml_lock(path, "poetry.lock")


def from_uv_lock(path: Path) -> tuple[list[Package], list[str]]:
    return _from_toml_lock(path, "uv.lock")


def from_pipfile_lock(path: Path) -> tuple[list[Package], list[str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    packages: list[Package] = []
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            if isinstance(meta, dict):
                version = meta.get("version", "")
                if isinstance(version, str) and version.startswith("=="):
                    packages.append(Package(name=name, version=version[2:], source=str(path)))
    return packages, []


def from_environment() -> list[Package]:
    try:
        from importlib import metadata
    except ImportError:  # pragma: no cover
        return []

    packages: list[Package] = []
    for dist in metadata.distributions():
        name = dist.metadata["Name"] if dist.metadata else None
        version = dist.version
        if name and version:
            packages.append(Package(name=name, version=version, source="environment"))
    return packages
