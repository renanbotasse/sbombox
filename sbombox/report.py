from __future__ import annotations

from pathlib import Path
from typing import Any

from sbombox.models import Finding
from sbombox.util import severity_rank, truncate, utc_now_iso, write_json


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
        "Almost all findings fall here. The **Fixed in** column is the minimum fixed version "
        "on your release line (or the first version newer than yours). |",
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
        "2. Run the test suite after meaningful upgrades.",
        "3. Re-run the scan before making the check required on `main`.",
        "4. Exceptions only with a non-reachability / accepted-risk justification in `.vulnignore`.",
        "",
    ]
    return "\n".join(lines)
