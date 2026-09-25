#!/usr/bin/env python3
"""SBOMBox — SBOM generation and dependency vulnerability scan for Python packages.

Stdlib only. Requires Python 3.9+. poetry.lock / uv.lock need 3.11+ (tomllib).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
GITHUB_ADVISORIES = "https://api.github.com/advisories"
NVD_CVE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ORG = "https://www.cve.org/CVERecord?id={id}"

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


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    source: str = ""

    @property
    def normalized(self) -> str:
        return normalize_name(self.name)

    @property
    def purl(self) -> str:
        return f"pkg:pypi/{urllib.parse.quote(self.normalized)}@{urllib.parse.quote(self.version)}"


@dataclass
class Finding:
    vuln_id: str
    package: str
    version: str
    severity: str
    summary: str = ""
    fixed_in: Optional[str] = None
    aliases: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    cvss: Optional[float] = None
    nvd_status: Optional[str] = None
    references: list[str] = field(default_factory=list)

    def all_ids(self) -> set[str]:
        return {i.upper() for i in (self.vuln_id, *self.aliases) if i}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def normalize_name(name: str) -> str:
    """PEP 503 normalized name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def severity_rank(s: str) -> int:
    return SEVERITY_ORDER.get((s or "UNKNOWN").upper(), 0)


def max_severity(a: str, b: str) -> str:
    return a if severity_rank(a) >= severity_rank(b) else b


def parse_severity(value: Any) -> str:
    if value is None:
        return "UNKNOWN"
    if isinstance(value, list):
        best = "UNKNOWN"
        for item in value:
            best = max_severity(best, parse_severity(item))
        return best
    if isinstance(value, dict):
        # OSV severity entry: {"type": "CVSS_V3", "score": "..."}
        score = str(value.get("score") or "").upper()
        return score if score in SEVERITY_ORDER else "UNKNOWN"
    text = str(value).strip().upper()
    if text in SEVERITY_ORDER:
        return text
    if text == "MODERATE":  # GitHub
        return "MEDIUM"
    return "UNKNOWN"


def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def is_malware(*ids: str) -> bool:
    return any(i.upper().startswith("MAL-") for i in ids if i)


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def first_cve(ids: Iterable[str]) -> Optional[str]:
    for vid in ids:
        if vid.startswith("CVE-"):
            return vid
    return None


def version_key(version: str) -> tuple:
    """Loose numeric key for comparing common PyPI versions (PEP 440 subset)."""
    text = (version or "").strip().lstrip("vV")
    if not text or text == "0":
        return (0,)
    # Drop local/epoch markers we don't need for ordering tips
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
                # pre-release sorts before final: 5.1.0rc1 < 5.1.0
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


# ---------------------------------------------------------------------------
# HTTP client with retry / backoff
# ---------------------------------------------------------------------------


class HttpClient:
    def __init__(self, timeout: float = 30.0, max_retries: int = 4) -> None:
        self.timeout = timeout
        self.max_retries = max_retries
        self._ctx = ssl.create_default_context()

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        data: Any = None,
        headers: Optional[dict[str, str]] = None,
    ) -> tuple[int, Any]:
        body: Optional[bytes] = None
        hdrs = {"User-Agent": "SBOMBox/1.0", "Accept": "application/json"}
        if headers:
            hdrs.update(headers)
        if data is not None:
            body = json.dumps(data).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")

        last_err: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                    raw = resp.read()
                    status = resp.getcode()
                    if not raw:
                        return status, None
                    try:
                        return status, json.loads(raw.decode("utf-8"))
                    except json.JSONDecodeError:
                        return status, raw.decode("utf-8", errors="replace")
            except urllib.error.HTTPError as e:
                last_err = e
                payload = e.read()
                retryable = e.code == 429 or 500 <= e.code < 600
                if retryable and attempt < self.max_retries:
                    wait = self._backoff(attempt, e.headers.get("Retry-After") if e.headers else None)
                    log(f"HTTP {e.code} for {url}; retry in {wait:.1f}s")
                    time.sleep(wait)
                    continue
                try:
                    return e.code, json.loads(payload.decode("utf-8")) if payload else None
                except Exception:
                    return e.code, None
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last_err = e
                if attempt < self.max_retries:
                    wait = self._backoff(attempt, None)
                    log(f"Network error for {url}: {e}; retry in {wait:.1f}s")
                    time.sleep(wait)
                    continue
        raise RuntimeError(f"Request failed after retries: {url}: {last_err}")

    @staticmethod
    def _backoff(attempt: int, retry_after: Optional[str]) -> float:
        if retry_after:
            try:
                return max(1.0, float(retry_after))
            except ValueError:
                pass
        return min(30.0, (2 ** attempt) + 0.1 * attempt)


# ---------------------------------------------------------------------------
# Dependency collection
# ---------------------------------------------------------------------------


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
            # --hash, -e, --index-url, etc.
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


# ---------------------------------------------------------------------------
# SBOM (CycloneDX 1.5)
# ---------------------------------------------------------------------------


def build_sbom(
    packages: list[Package],
    findings: list[Finding],
    source_label: str,
) -> dict[str, Any]:
    bom_ref_by_pkg: dict[tuple[str, str], str] = {}
    components = []
    for pkg in packages:
        bom_ref_by_pkg[(pkg.normalized, pkg.version)] = pkg.purl
        components.append(
            {
                "type": "library",
                "bom-ref": pkg.purl,
                "name": pkg.normalized,
                "version": pkg.version,
                "purl": pkg.purl,
            }
        )

    vulns: list[dict[str, Any]] = []
    for finding in findings:
        affects_ref = bom_ref_by_pkg.get((normalize_name(finding.package), finding.version))
        if finding.cvss is not None:
            ratings: list[dict[str, Any]] = [
                {
                    "source": {"name": "NVD"},
                    "score": finding.cvss,
                    "severity": finding.severity.lower(),
                    "method": "CVSSv3",
                }
            ]
        else:
            ratings = [{"severity": finding.severity.lower(), "method": "other"}]

        entry: dict[str, Any] = {
            "id": finding.vuln_id,
            "source": {"name": ",".join(sorted(set(finding.sources))) or "osv"},
            "ratings": ratings,
            "description": finding.summary or finding.vuln_id,
            "affects": [
                {
                    "ref": affects_ref
                    or f"pkg:pypi/{normalize_name(finding.package)}@{finding.version}"
                }
            ],
        }
        if finding.aliases:
            entry["references"] = [{"id": a} for a in finding.aliases]
        if finding.fixed_in:
            entry["recommendation"] = f"Upgrade to {finding.fixed_in} or later"
        vulns.append(entry)

    serial = hashlib.sha256(f"{source_label}:{len(packages)}:{utc_now_iso()}".encode()).hexdigest()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": (
            f"urn:uuid:{serial[:8]}-{serial[8:12]}-{serial[12:16]}-"
            f"{serial[16:20]}-{serial[20:32]}"
        ),
        "version": 1,
        "metadata": {
            "timestamp": utc_now_iso(),
            "tools": [{"vendor": "SBOMBox", "name": "sbom_scan", "version": "1.0"}],
            "component": {
                "type": "application",
                "name": source_label,
                "version": "0.0.0",
            },
        },
        "components": components,
        "vulnerabilities": vulns,
    }


# ---------------------------------------------------------------------------
# Vulnerability sources
# ---------------------------------------------------------------------------


def query_osv(client: HttpClient, packages: list[Package]) -> tuple[list[dict[str, Any]], bool]:
    """Return (raw vuln dicts with package context, ok)."""
    if not packages:
        return [], True

    results: list[dict[str, Any]] = []
    ok = False
    total_batches = (len(packages) + 99) // 100
    log(f"OSV: querying {len(packages)} packages ({total_batches} batch(es))...")
    for i in range(0, len(packages), 100):
        chunk = packages[i : i + 100]
        batch_no = i // 100 + 1
        queries = [
            {"package": {"name": p.normalized, "ecosystem": "PyPI"}, "version": p.version}
            for p in chunk
        ]
        try:
            status, data = client.request(OSV_QUERYBATCH, method="POST", data={"queries": queries})
        except RuntimeError as e:
            log(f"OSV querybatch failed: {e}")
            continue
        if status != 200 or not isinstance(data, dict):
            log(f"OSV querybatch HTTP {status}")
            continue
        ok = True

        vuln_ids: list[tuple[Package, str]] = []
        for pkg, res in zip(chunk, data.get("results") or []):
            for v in res.get("vulns") or []:
                vid = v.get("id")
                if vid:
                    vuln_ids.append((pkg, vid))
        log(f"OSV: batch {batch_no}/{total_batches} → {len(vuln_ids)} vuln id(s), fetching details...")

        def fetch_one(item: tuple[Package, str]) -> Optional[dict[str, Any]]:
            pkg, vid = item
            try:
                st, detail = client.request(OSV_VULN.format(id=urllib.parse.quote(vid)))
            except RuntimeError:
                return None
            if st != 200 or not isinstance(detail, dict):
                return None
            detail["_package"] = pkg.normalized
            detail["_version"] = pkg.version
            detail["_source"] = "osv"
            return detail

        done = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for detail in pool.map(fetch_one, vuln_ids):
                done += 1
                if done % 25 == 0 or done == len(vuln_ids):
                    log(f"OSV: details {done}/{len(vuln_ids)}")
                if detail:
                    results.append(detail)
    log(f"OSV: done ({len(results)} raw hit(s))")
    return results, ok


def query_github(client: HttpClient, packages: list[Package], token: str) -> tuple[list[dict[str, Any]], bool]:
    if not token or not packages:
        if not token:
            log("GitHub: skipped (no GITHUB_TOKEN)")
        return [], bool(token)

    results: list[dict[str, Any]] = []
    ok = False
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    log(f"GitHub Advisories: querying {len(packages)} packages...")

    def fetch_pkg(pkg: Package) -> list[dict[str, Any]]:
        q = urllib.parse.urlencode(
            {
                "ecosystem": "pip",
                "affects": f"{pkg.normalized}@{pkg.version}",
                "per_page": "100",
            }
        )
        try:
            status, data = client.request(f"{GITHUB_ADVISORIES}?{q}", headers=headers)
        except RuntimeError as e:
            log(f"GitHub advisories failed for {pkg.normalized}: {e}")
            return []
        if status in (401, 403):
            log(f"GitHub advisories auth error HTTP {status}")
            return []
        if status != 200:
            log(f"GitHub advisories HTTP {status} for {pkg.normalized}")
            return []
        out: list[dict[str, Any]] = []
        if isinstance(data, list):
            for adv in data:
                if not isinstance(adv, dict) or adv.get("withdrawn_at"):
                    continue
                adv = dict(adv)
                adv["_package"] = pkg.normalized
                adv["_version"] = pkg.version
                adv["_source"] = "github"
                out.append(adv)
        return out

    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        for batch in pool.map(fetch_pkg, packages):
            done += 1
            if done % 20 == 0 or done == len(packages):
                log(f"GitHub: {done}/{len(packages)} packages")
            ok = True
            results.extend(batch)
    log(f"GitHub: done ({len(results)} raw hit(s))")
    return results, ok


def _nvd_metrics(cve: dict[str, Any]) -> tuple[Optional[float], Optional[str], Optional[str]]:
    metrics = cve.get("metrics") or {}
    score = None
    severity = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if not arr or not isinstance(arr[0], dict):
            continue
        cvss_data = arr[0].get("cvssData") or {}
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity")
        break

    tag = None
    for w in cve.get("cveTags") or []:
        if isinstance(w, dict) and w.get("tag"):
            tag = w["tag"]
            break
    return score, severity, cve.get("vulnStatus") or tag


def enrich_nvd(
    client: HttpClient,
    findings: list[Finding],
    api_key: Optional[str],
) -> None:
    cve_ids = sorted({cve for f in findings if (cve := first_cve(f.all_ids()))})
    if not cve_ids:
        return

    headers = {"apiKey": api_key} if api_key else {}
    delay = 0.7 if api_key else 6.1
    eta_min = len(cve_ids) * delay / 60
    log(
        f"NVD: enriching {len(cve_ids)} CVE(s) "
        f"({'with API key' if api_key else 'no API key, ~6s each'} ≈ {eta_min:.1f} min)..."
    )
    log("      tip: use --no-nvd for a fast local pass (OSV severity is enough for the gate)")
    cache: dict[str, dict[str, Any]] = {}

    for idx, cve_id in enumerate(cve_ids, 1):
        log(f"NVD: {idx}/{len(cve_ids)} {cve_id}")
        url = f"{NVD_CVE}?{urllib.parse.urlencode({'cveId': cve_id})}"
        try:
            status, data = client.request(url, headers=headers or None)
        except RuntimeError as e:
            log(f"NVD lookup failed for {cve_id}: {e}")
            time.sleep(delay)
            continue
        time.sleep(delay)
        if status != 200 or not isinstance(data, dict):
            continue
        vulns = data.get("vulnerabilities") or []
        if not vulns or not isinstance(vulns[0], dict):
            continue
        cve = vulns[0].get("cve") or {}
        score, severity, vuln_status = _nvd_metrics(cve)
        cache[cve_id] = {"score": score, "severity": severity, "status": vuln_status}
    log("NVD: done")

    for f in findings:
        cve = first_cve(f.all_ids())
        if not cve:
            continue
        link = CVE_ORG.format(id=cve)
        if link not in f.references:
            f.references.append(link)
        if cve not in cache:
            continue
        info = cache[cve]
        if info.get("score") is not None:
            try:
                f.cvss = float(info["score"])
            except (TypeError, ValueError):
                pass
        if f.severity == "UNKNOWN":
            if info.get("severity"):
                f.severity = str(info["severity"]).upper()
            elif f.cvss is not None:
                f.severity = cvss_to_severity(f.cvss)
        f.nvd_status = info.get("status")
        if (f.nvd_status or "").lower() in {"rejected", "deferred"}:
            f.severity = "UNKNOWN"


# ---------------------------------------------------------------------------
# Normalize findings from OSV / GitHub
# ---------------------------------------------------------------------------


def osv_to_finding(raw: dict[str, Any]) -> Optional[Finding]:
    if raw.get("withdrawn"):
        return None
    vuln_id = raw.get("id") or ""
    if not vuln_id:
        return None
    aliases = [a for a in (raw.get("aliases") or []) if a]
    summary = raw.get("summary") or raw.get("details") or ""
    if isinstance(summary, str):
        summary = truncate(summary, 280)
    else:
        summary = ""

    severity = "UNKNOWN"
    db = raw.get("database_specific") or {}
    if isinstance(db, dict) and db.get("severity"):
        severity = parse_severity(db.get("severity"))
    if severity == "UNKNOWN":
        severity = parse_severity(raw.get("severity"))
    if is_malware(vuln_id, *aliases):
        severity = "CRITICAL"

    refs = [
        ref["url"]
        for ref in raw.get("references") or []
        if isinstance(ref, dict) and ref.get("url")
    ]

    return Finding(
        vuln_id=vuln_id,
        package=raw.get("_package") or "",
        version=raw.get("_version") or "",
        severity=severity,
        summary=summary,
        fixed_in=extract_fixed_version_osv(
            raw, raw.get("_package") or "", raw.get("_version") or ""
        ),
        aliases=aliases,
        sources=["osv"],
        references=refs[:5],
    )


def extract_fixed_version_osv(raw: dict[str, Any], package: str, current: str = "") -> Optional[str]:
    """Pick a fixed version suitable for *current*, not the oldest branch fix."""
    pkg_norm = normalize_name(package) if package else ""
    candidates: list[str] = []
    for affected in raw.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package") or {}
        name = normalize_name(pkg.get("name") or "")
        eco = pkg.get("ecosystem") or ""
        if eco and eco != "PyPI":
            continue
        if pkg_norm and name and name != pkg_norm:
            continue
        for r in affected.get("ranges") or []:
            if not isinstance(r, dict):
                continue
            for event in r.get("events") or []:
                if isinstance(event, dict) and event.get("fixed"):
                    candidates.append(str(event["fixed"]))
    if not current:
        # No installed version context — keep deterministic min for stability
        return min(candidates, key=version_key) if candidates else None
    return pick_fixed_version(current, candidates)


def github_to_finding(raw: dict[str, Any]) -> Optional[Finding]:
    if raw.get("withdrawn_at"):
        return None
    vuln_id = raw.get("ghsa_id") or raw.get("cve_id") or ""
    if not vuln_id:
        return None

    aliases = []
    for key in ("cve_id", "ghsa_id"):
        val = raw.get(key)
        if val and val != vuln_id:
            aliases.append(val)

    severity = parse_severity(raw.get("severity"))
    if is_malware(vuln_id):
        severity = "CRITICAL"

    current = raw.get("_version") or ""
    patched = [
        str(vp["first_patched_version"])
        for vp in raw.get("vulnerabilities") or []
        if isinstance(vp, dict) and vp.get("first_patched_version")
    ]
    fixed_in = pick_fixed_version(current, patched) if current else (patched[0] if patched else None)

    refs = [raw["html_url"]] if raw.get("html_url") else []
    return Finding(
        vuln_id=vuln_id,
        package=raw.get("_package") or "",
        version=current,
        severity=severity,
        summary=raw.get("summary") or "",
        fixed_in=fixed_in,
        aliases=aliases,
        sources=["github"],
        references=refs,
    )


def _merge_finding(target: Finding, other: Finding) -> None:
    ids = target.all_ids() | other.all_ids()
    cves = sorted(i for i in ids if i.startswith("CVE-"))
    ghsas = sorted(i for i in ids if i.startswith("GHSA-"))
    primary = cves[0] if cves else (ghsas[0] if ghsas else target.vuln_id)
    target.vuln_id = primary
    target.aliases = sorted(
        {a for a in (*target.aliases, *other.aliases, *ids) if a.upper() != primary.upper()}
    )
    target.severity = max_severity(target.severity, other.severity)
    target.sources = sorted(set(target.sources + other.sources))
    if not target.summary:
        target.summary = other.summary
    target.fixed_in = better_fixed_in(target.version, target.fixed_in, other.fixed_in)
    for ref in other.references:
        if ref not in target.references:
            target.references.append(ref)
    if other.cvss is not None and (target.cvss is None or other.cvss > target.cvss):
        target.cvss = other.cvss


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Merge findings that share CVE / GHSA / PYSEC aliases for the same package@version."""
    groups: list[Finding] = []
    for f in findings:
        merged = False
        for g in groups:
            same_pkg = (
                normalize_name(f.package) == normalize_name(g.package) and f.version == g.version
            )
            if same_pkg and (f.all_ids() & g.all_ids()):
                _merge_finding(g, f)
                merged = True
                break
        if not merged:
            groups.append(f)
    return groups


# ---------------------------------------------------------------------------
# Ignore list
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def write_reports(
    out_dir: Path,
    sbom: dict[str, Any],
    findings: list[Finding],
    meta: dict[str, Any],
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "sbom.cdx.json", sbom)

    flat = [
        {
            "id": f.vuln_id,
            "aliases": f.aliases,
            "package": f.package,
            "version": f.version,
            "severity": f.severity,
            "summary": f.summary,
            "fixed_in": f.fixed_in,
            "cvss": f.cvss,
            "nvd_status": f.nvd_status,
            "sources": f.sources,
            "references": f.references,
        }
        for f in findings
    ]
    write_json(
        out_dir / "vuln-report.json",
        {"generated_at": utc_now_iso(), "meta": meta, "findings": flat},
    )

    md = render_markdown(findings, meta)
    (out_dir / "vuln-report.md").write_text(md, encoding="utf-8")
    print(md)


def render_markdown(findings: list[Finding], meta: dict[str, Any]) -> str:
    lines = [
        "# Dependency vulnerability report",
        "",
        f"- Generated: `{meta.get('generated_at')}`",
        f"- Source: `{meta.get('source')}`",
        f"- Packages scanned: **{meta.get('package_count')}**",
        f"- Findings: **{len(findings)}**",
        f"- Ignored: **{meta.get('ignored_count', 0)}**",
        f"- Fail-on threshold: `{meta.get('fail_on')}`",
        "",
        "## How to read this report",
        "",
        "This scanner does **not** check whether your system has already been breached. "
        "It matches each `package==version` in the inventory against public databases "
        "(OSV, GitHub Advisory Database, and optionally NVD) and lists **known published** "
        "flaws that affect that version.",
        "",
        "| Situation | Meaning |",
        "|---|---|",
        "| **Outdated / vulnerable** | The version you use has a known flaw. "
        "Almost all findings fall here. The **Fixed in** column is the minimum fixed version. |",
        "| **Compromised / malicious (`MAL-*`)** | A package or release published maliciously "
        "(typosquat, compromised maintainer account). Always classified as `CRITICAL`. |",
        "| **CRITICAL / HIGH severity** | High impact of the flaw (e.g. SQL injection, RCE, auth bypass), "
        "per CVSS / OSV / GitHub — **not** proof that someone already exploited your environment. |",
        "| **MEDIUM / LOW** | Lower impact (limited DoS, sandbox issues, etc.). |",
        "| **UNKNOWN** | The source did not assign a severity; triage manually. |",
        "",
        "**What to do with each finding:** upgrade the package to **Fixed in** (or newer), "
        "confirm whether the affected code path is reachable in your app, "
        "or record a temporary exception in `.vulnignore` with reason, owner, and review date.",
        "",
        "The CI gate fails when at least one finding is at or above `--fail-on` "
        "(default: `high`).",
        "",
    ]
    if not findings:
        lines += [
            "## Findings",
            "",
            "No vulnerabilities matched the current dependency set.",
            "",
        ]
        return "\n".join(lines)

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    summary_bits = [f"**{sev}**: {by_sev[sev]}" for sev in order if sev in by_sev]
    lines += [
        "## Severity summary",
        "",
        "- " + " · ".join(summary_bits) if summary_bits else "- (none)",
        "",
        "## Findings",
        "",
        "| Severity | Package | Version | ID | Fixed in | Summary |",
        "|---|---|---|---|---|---|",
    ]
    ordered = sorted(findings, key=lambda f: (-severity_rank(f.severity), f.package, f.vuln_id))
    for f in ordered:
        summary = truncate((f.summary or "").replace("|", "\\|").replace("\n", " "), 80)
        lines.append(
            f"| {f.severity} | `{f.package}` | `{f.version}` | `{f.vuln_id}` | "
            f"`{f.fixed_in or '—'}` | {summary} |"
        )
    lines += [
        "",
        "## Suggested next steps",
        "",
        "1. Fix `CRITICAL` and `HIGH` first, grouped by package (one upgrade often clears many IDs).",
        "2. Run the test suite after meaningful upgrades (Django, cryptography, pyjwt, etc.).",
        "3. Re-run the scan before making the check required on `main`.",
        "4. Exceptions only with a non-reachability / accepted-risk justification in `.vulnignore`.",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="SBOMBox: generate a CycloneDX SBOM and scan Python dependencies for vulnerabilities."
    )
    p.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Project directory, lock/requirements file, or ignored when --env is set",
    )
    p.add_argument("-o", "--output", default="sbom-report", help="Output directory (default: sbom-report)")
    p.add_argument("--env", action="store_true", help="Scan packages installed in the current environment")
    p.add_argument(
        "--sbom-only",
        action="store_true",
        help="Generate SBOM only; do not query vulnerability databases",
    )
    p.add_argument(
        "--fail-on",
        default="high",
        choices=["critical", "high", "medium", "low", "none"],
        help="Minimum severity that fails the scan (default: high)",
    )
    p.add_argument(
        "--ignore",
        action="append",
        default=[],
        help="Vulnerability ID to ignore (repeatable). Also reads .vulnignore",
    )
    p.add_argument(
        "--vulnignore",
        default=".vulnignore",
        help="Path to ignore file (default: .vulnignore in cwd)",
    )
    p.add_argument("--no-nvd", action="store_true", help="Skip NVD enrichment")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    target = Path(args.target)
    if not args.env and not target.exists():
        log(f"Target not found: {target}")
        return 2

    try:
        packages, warnings, source_label = collect_packages(target, force_env=args.env)
    except SystemExit as e:
        log(str(e))
        return 2

    packages = dedupe_packages(packages)
    for w in warnings:
        log(f"warning: {w}")
    log(f"Collected {len(packages)} packages from {source_label}")

    findings: list[Finding] = []
    ignored_count = 0
    sources_ok = {"osv": False, "github": False}
    out = Path(args.output)

    if not args.sbom_only:
        client = HttpClient()
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
        nvd_key = os.environ.get("NVD_API_KEY")

        log("Scanning vulnerability sources (this can take a few minutes)...")
        osv_raw, sources_ok["osv"] = query_osv(client, packages)
        for raw in osv_raw:
            finding = osv_to_finding(raw)
            if finding:
                findings.append(finding)

        gh_raw, gh_ok = query_github(client, packages, token)
        if token:
            sources_ok["github"] = gh_ok
        for raw in gh_raw:
            finding = github_to_finding(raw)
            if finding:
                findings.append(finding)

        if not any(sources_ok.values()):
            log("ERROR: no vulnerability source responded (fail closed)")
            out.mkdir(parents=True, exist_ok=True)
            write_json(out / "sbom.cdx.json", build_sbom(packages, [], source_label))
            return 2

        findings = dedupe_findings(findings)
        log(f"Deduped findings: {len(findings)}")
        if not args.no_nvd:
            enrich_nvd(client, findings, nvd_key)
        else:
            log("NVD: skipped (--no-nvd)")

        findings = [f for f in findings if (f.nvd_status or "").lower() != "rejected"]
        ignores = resolve_ignores(args.ignore, Path(args.vulnignore), target)
        findings, ignored_count = apply_ignores(findings, ignores)
        if ignored_count:
            log(f"Ignored {ignored_count} finding(s) via .vulnignore / --ignore")

    meta = {
        "generated_at": utc_now_iso(),
        "source": source_label,
        "package_count": len(packages),
        "ignored_count": ignored_count,
        "fail_on": args.fail_on,
        "sbom_only": args.sbom_only,
        "sources_ok": sources_ok,
    }
    write_reports(out, build_sbom(packages, findings, source_label), findings, meta)

    if args.sbom_only or args.fail_on == "none":
        return 0

    threshold = severity_rank(args.fail_on.upper())
    blocking = [f for f in findings if severity_rank(f.severity) >= threshold]
    if blocking:
        log(f"FAIL: {len(blocking)} finding(s) at or above {args.fail_on.upper()}")
        return 1
    log("OK: no findings at or above fail-on threshold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
