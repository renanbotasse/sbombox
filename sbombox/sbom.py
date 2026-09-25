from __future__ import annotations

import hashlib
from typing import Any

from sbombox import NAME, __version__
from sbombox.models import Finding, Package
from sbombox.util import normalize_name, utc_now_iso


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
            "tools": [{"vendor": NAME, "name": "sbombox", "version": __version__}],
            "component": {
                "type": "application",
                "name": source_label,
                "version": "0.0.0",
            },
        },
        "components": components,
        "vulnerabilities": vulns,
    }
