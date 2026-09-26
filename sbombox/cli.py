from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional

from sbombox import NAME, __version__
from sbombox.collect import collect_packages, dedupe_packages
from sbombox.findings import dedupe_findings, github_to_finding, osv_to_finding
from sbombox.http import HttpClient
from sbombox.ignore import apply_ignores, resolve_ignores
from sbombox.models import Finding
from sbombox.report import write_reports
from sbombox.sbom import build_sbom
from sbombox.sources import enrich_nvd, query_github, query_osv
from sbombox.util import log, severity_rank, utc_now_iso, write_json


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sbombox",
        description=f"{NAME}: generate a CycloneDX SBOM and scan Python dependencies for vulnerabilities.",
    )
    p.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Project directory, lock/requirements file, or ignored when --env is set",
    )
    p.add_argument(
        "-o", "--output", default="sbom-report", help="Output directory (default: sbom-report)"
    )
    p.add_argument(
        "--env", action="store_true", help="Scan packages installed in the current environment"
    )
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
    p.add_argument(
        "--no-github",
        action="store_true",
        help="Skip the GitHub Advisory Database query (only OSV is used)",
    )
    p.add_argument(
        "-q", "--quiet", action="store_true", help="Do not print the markdown report to stdout"
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    target = Path(args.target)
    if not args.env and not target.exists():
        log(f"Target not found: {target}")
        return 2

    out = Path(args.output)
    if out.exists() and not out.is_dir():
        log(f"Output path is an existing file, not a directory: {out}")
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

        if not args.no_github:
            gh_raw, gh_ok = query_github(client, packages, token)
            if token:
                sources_ok["github"] = gh_ok
            for raw in gh_raw:
                finding = github_to_finding(raw)
                if finding:
                    findings.append(finding)
        else:
            log("GitHub: skipped (--no-github)")

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
        ignore_ids, ignore_packages = resolve_ignores(args.ignore, Path(args.vulnignore), target)
        findings, ignored_count = apply_ignores(findings, ignore_ids, ignore_packages)
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
    write_reports(out, build_sbom(packages, findings, source_label), findings, meta, quiet=args.quiet)

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
