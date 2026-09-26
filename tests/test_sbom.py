"""sbom.py: CycloneDX 1.5 document builder."""

from __future__ import annotations

import json
import re

from sbombox.models import Finding, Package
from sbombox.sbom import build_sbom


def _pkg(name="requests", version="2.31.0"):
    return Package(name=name, version=version, source="requirements.txt")


def _finding(**kw):
    base = dict(vuln_id="CVE-2020-0001", package="requests", version="2.31.0", severity="HIGH")
    base.update(kw)
    return Finding(**base)


class TestBuildSbom:
    def test_components_and_purls(self):
        doc = build_sbom([_pkg(), _pkg("Requests", "2.31.0")], [], "requirements.txt")
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.5"
        # duplicates are NOT collapsed here — callers dedupe first
        assert len(doc["components"]) == 2
        comp = doc["components"][0]
        assert comp["purl"] == "pkg:pypi/requests@2.31.0"
        assert comp["bom-ref"] == comp["purl"]
        assert comp["type"] == "library"

    def test_metadata(self):
        doc = build_sbom([_pkg()], [], "poetry.lock")
        assert doc["metadata"]["component"]["name"] == "poetry.lock"
        assert doc["metadata"]["tools"][0]["version"]  # non-empty
        assert "Z" in doc["metadata"]["timestamp"] or doc["metadata"]["timestamp"].endswith("+00:00")

    def test_serial_is_uuid_shape(self):
        doc = build_sbom([_pkg()], [], "requirements.txt")
        m = re.fullmatch(r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", doc["serialNumber"])
        assert m is not None

    def test_serial_unique_same_second(self, monkeypatch):
        # Regression: serial used the 1-second ISO timestamp, so two builds in
        # the same second produced IDENTICAL serialNumbers.
        monkeypatch.setattr("sbombox.util.utc_now_iso", lambda: "2026-09-26T00:00:00Z")
        a = build_sbom([_pkg()], [], "requirements.txt")["serialNumber"]
        b = build_sbom([_pkg()], [], "requirements.txt")["serialNumber"]
        assert a != b

    def test_vuln_affects_ref_uses_bom_ref(self):
        f = _finding()
        doc = build_sbom([_pkg()], [f], "requirements.txt")
        v = doc["vulnerabilities"][0]
        assert v["id"] == "CVE-2020-0001"
        assert v["affects"][0]["ref"] == "pkg:pypi/requests@2.31.0"
        assert v["description"] == "CVE-2020-0001"  # falls back to the ID

    def test_vuln_ref_fallback_when_package_missing(self):
        f = _finding(package="unknownpkg", version="1.0")
        doc = build_sbom([_pkg()], [f], "requirements.txt")
        assert doc["vulnerabilities"][0]["affects"][0]["ref"] == "pkg:pypi/unknownpkg@1.0"

    def test_ratings_cvss_vs_other(self):
        doc = build_sbom([_pkg()], [_finding(cvss=9.8)], "x")
        r = doc["vulnerabilities"][0]["ratings"][0]
        assert r["score"] == 9.8
        assert r["method"] == "CVSSv3"
        assert r["source"]["name"] == "NVD"

        doc2 = build_sbom([_pkg()], [_finding()], "x")
        r2 = doc2["vulnerabilities"][0]["ratings"][0]
        assert r2["method"] == "other"
        assert "score" not in r2

    def test_aliases_and_recommendation(self):
        f = _finding(aliases=["GHSA-xxxx-yyyy-zzzz"], fixed_in="2.31.1")
        v = build_sbom([_pkg()], [f], "x")["vulnerabilities"][0]
        assert v["references"] == [{"id": "GHSA-xxxx-yyyy-zzzz"}]
        assert v["recommendation"] == "Upgrade to 2.31.1 or later"

    def test_empty_packages(self):
        doc = build_sbom([], [], "requirements.txt")
        assert doc["components"] == []
        assert doc["vulnerabilities"] == []

    def test_json_serializable(self):
        doc = build_sbom([_pkg()], [_finding(cvss=7.0)], "x")
        json.dumps(doc)  # must not raise