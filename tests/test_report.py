"""report.py: markdown rendering and the three report files."""

from __future__ import annotations

import json

from sbombox.models import Finding
from sbombox.report import render_markdown, write_reports


def _finding(vid="CVE-2020-1", severity="HIGH", pkg="pyyaml", version="5.3"):
    return Finding(
        vuln_id=vid, package=pkg, version=version, severity=severity,
        summary="Pipe in summary | with pipe and\nnewline and " + "x" * 200,
        fixed_in="5.3.1",
    )


META = {
    "generated_at": "2026-09-26T00:00:00Z",
    "source": "requirements.txt",
    "package_count": 2,
    "ignored_count": 1,
    "fail_on": "high",
    "sbom_only": False,
    "sources_ok": {"osv": True, "github": False},
}


class TestRenderMarkdown:
    def test_empty_findings(self):
        md = render_markdown([], META)
        assert "No vulnerabilities matched" in md
        assert "Packages scanned: **2**" in md
        assert "Ignored: **1**" in md

    def test_severity_summary(self):
        findings = [
            _finding("CVE-1", "CRITICAL"),
            _finding("CVE-2", "HIGH"),
            _finding("CVE-3", "LOW"),
            _finding("CVE-4", "MEDIUM"),
        ]
        md = render_markdown(findings, META)
        assert "**CRITICAL**: 1" in md
        assert "**HIGH**: 1" in md
        assert "**MEDIUM**: 1" in md

    def test_sorted_by_severity_desc(self):
        findings = [_finding("CVE-low", "LOW"), _finding("CVE-crit", "CRITICAL")]
        md = render_markdown(findings, META)
        crit_idx = md.index("CVE-crit")
        low_idx = md.index("CVE-low")
        assert crit_idx < low_idx

    def test_pipe_and_newline_escaped_in_table(self):
        md = render_markdown([_finding("CVE-1", "HIGH")], META)
        row = [l for l in md.splitlines() if "CVE-1" in l][0]
        assert "|" in row  # still a table row
        assert "Pipe in summary" in row
        assert "\n" not in row

    def test_unknown_severity_listed_last(self):
        md = render_markdown([_finding("CVE-1", "UNKNOWN"), _finding("CVE-2", "LOW")], META)
        assert md.index("CVE-2") < md.index("CVE-1")


class TestWriteReports:
    def test_writes_three_files(self, tmp_path):
        write_reports(tmp_path / "out", {}, [_finding()], META, quiet=True)
        assert (tmp_path / "out" / "sbom.cdx.json").is_file()
        assert (tmp_path / "out" / "sbom-report.json").is_file()
        assert (tmp_path / "out" / "sbom-report.md").is_file()

    def test_json_report_shape(self, tmp_path):
        write_reports(tmp_path / "out", {}, [_finding()], META, quiet=True)
        data = json.loads((tmp_path / "out" / "sbom-report.json").read_text())
        assert data["meta"]["package_count"] == 2
        assert data["findings"][0]["id"] == "CVE-2020-1"
        assert data["findings"][0]["nvd_status"] is None

    def test_quiet_suppresses_stdout(self, tmp_path, capsys):
        write_reports(tmp_path / "out", {}, [_finding()], META, quiet=True)
        assert capsys.readouterr().out == ""

    def test_loud_prints_stdout(self, tmp_path, capsys):
        write_reports(tmp_path / "out", {}, [], META, quiet=False)
        assert "Dependency vulnerability report" in capsys.readouterr().out