"""ignore.py: .vulnignore parsing and ID-only filtering."""

from __future__ import annotations

from sbombox.ignore import apply_ignores, load_ignore_file, resolve_ignores
from sbombox.models import Finding


class TestLoadIgnoreFile:
    def test_full_lines(self, tmp_path):
        p = tmp_path / ".vulnignore"
        p.write_text(
            "# header\n\n"
            "CVE-2020-1747  # not reachable | @alice | review-by:2026-12-01\n"
            "GHSA-aaaa-bbbb-cccc\n"
            "pyyaml         # package names are rejected\n",
            encoding="utf-8",
        )
        ids = load_ignore_file(p)
        assert ids == {"CVE-2020-1747", "GHSA-AAAA-BBBB-CCCC"}

    def test_missing_file_return_empty(self, tmp_path):
        assert load_ignore_file(tmp_path / "nope") == set()


class TestResolveIgnores:
    def test_cli_ids(self, tmp_path):
        ids = resolve_ignores(["CVE-2020-1", "cve-2020-2"], tmp_path / "missing", tmp_path)
        assert ids == {"CVE-2020-1", "CVE-2020-2"}

    def test_cli_rejects_package_name(self, tmp_path, capsys):
        ids = resolve_ignores(["pyyaml", "CVE-2020-1"], tmp_path / "missing", tmp_path)
        assert ids == {"CVE-2020-1"}
        assert "advisory ID required" in capsys.readouterr().err

    def test_vulnignore_and_alt_target_file(self, tmp_path):
        (tmp_path / ".vulnignore").write_text("CVE-2020-1\n", encoding="utf-8")
        ids = resolve_ignores([], tmp_path / ".vulnignore", tmp_path)
        assert ids == {"CVE-2020-1"}

    def test_alt_next_to_target_file(self, tmp_path):
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / ".vulnignore").write_text("GHSA-aaaa-bbbb-cccc\n", encoding="utf-8")
        ids = resolve_ignores([], tmp_path / ".vulnignore", proj / "requirements.txt")
        assert ids == {"GHSA-AAAA-BBBB-CCCC"}

    def test_same_file_not_loaded_twice(self, tmp_path):
        v = tmp_path / ".vulnignore"
        v.write_text("CVE-2020-1\nCVE-2020-1\n", encoding="utf-8")
        ids = resolve_ignores([], v, tmp_path)
        assert ids == {"CVE-2020-1"}


class TestApplyIgnores:
    def _finding(self, vid="CVE-2020-1", pkg="pyyaml", version="5.3"):
        return Finding(vuln_id=vid, package=pkg, version=version, severity="HIGH")

    def test_ignore_by_id(self):
        kept, n = apply_ignores([self._finding("CVE-2020-1")], {"CVE-2020-1"})
        assert kept == [] and n == 1

    def test_ignore_by_alias(self):
        f = Finding(
            vuln_id="PYSEC-1",
            package="pyyaml",
            version="5.3",
            severity="HIGH",
            aliases=["CVE-2020-1"],
        )
        kept, n = apply_ignores([f], {"CVE-2020-1"})
        assert kept == [] and n == 1

    def test_no_overlap_keeps_all(self):
        kept, n = apply_ignores([self._finding()], {"CVE-9999-1"})
        assert len(kept) == 1 and n == 0
