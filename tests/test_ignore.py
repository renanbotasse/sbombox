"""ignore.py: .vulnignore parsing, ID vs package classification, filtering."""

from __future__ import annotations

from sbombox.ignore import (
    apply_ignores,
    classify_token,
    load_ignore_file,
    resolve_ignores,
)
from sbombox.models import Finding


class TestClassifyToken:
    def test_ids(self):
        assert classify_token("CVE-2020-1747") == ("id", "CVE-2020-1747")
        assert classify_token("GHSA-xxxx-yyyy-zzzz")[0] == "id"
        assert classify_token("PYSEC-2024-123")[0] == "id"
        assert classify_token("MAL-2024-1234")[0] == "id"
        assert classify_token("cve-2020-1") == ("id", "CVE-2020-1")  # case-insensitive

    def test_package_names(self):
        kind, value = classify_token("pyyaml")
        assert kind == "package" and value == ("pyyaml", None)
        kind, value = classify_token("Pillow")
        assert kind == "package" and value == ("pillow", None)
        kind, value = classify_token("django-rest-framework")
        assert kind == "package" and value == ("django-rest-framework", None)

    def test_package_at_version(self):
        kind, value = classify_token("pyyaml@5.3")
        assert kind == "package" and value == ("pyyaml", "5.3")
        kind, value = classify_token("requests@")
        assert kind == "package" and value == ("requests", None)


class TestLoadIgnoreFile:
    def test_full_lines(self, tmp_path):
        p = tmp_path / ".vulnignore"
        p.write_text(
            "# header\n\n"
            "CVE-2020-1747  # not reachable | @alice | review-by:2026-12-01\n"
            "pyyaml         # dev-only | @bob | review-by:2026-12-01\n"
            "requests@2.31.0\n",
            encoding="utf-8",
        )
        ids, pkgs = load_ignore_file(p)
        assert ids == {"CVE-2020-1747"}
        assert ("pyyaml", None) in pkgs
        assert ("requests", "2.31.0") in pkgs

    def test_missing_file_return_empty(self, tmp_path):
        ids, pkgs = load_ignore_file(tmp_path / "nope")
        assert ids == set() and pkgs == set()


class TestResolveIgnores:
    def test_cli_ids_and_packages(self, tmp_path):
        ids, pkgs = resolve_ignores(["CVE-2020-1", "pyyaml"], tmp_path / "missing", tmp_path)
        assert ids == {"CVE-2020-1"}
        assert pkgs == {("pyyaml", None)}

    def test_vulnignore_and_alt_target_file(self, tmp_path):
        (tmp_path / ".vulnignore").write_text("CVE-2020-1\n", encoding="utf-8")
        ids, pkgs = resolve_ignores([], tmp_path / ".vulnignore", tmp_path)
        assert ids == {"CVE-2020-1"}

    def test_alt_next_to_target_file(self, tmp_path):
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / ".vulnignore").write_text("GHSA-aaaa-bbbb-cccc\n", encoding="utf-8")
        # explicit default path does not exist; target-adjacent file is picked up
        ids, _ = resolve_ignores([], tmp_path / ".vulnignore", proj / "requirements.txt")
        assert ids == {"GHSA-AAAA-BBBB-CCCC"}

    def test_same_file_not_loaded_twice(self, tmp_path):
        v = tmp_path / ".vulnignore"
        v.write_text("CVE-2020-1\nCVE-2020-1\n", encoding="utf-8")
        ids, _ = resolve_ignores([], v, tmp_path)
        assert ids == {"CVE-2020-1"}


class TestApplyIgnores:
    def _finding(self, vid="CVE-2020-1", pkg="pyyaml", version="5.3"):
        return Finding(vuln_id=vid, package=pkg, version=version, severity="HIGH")

    def test_ignore_by_id(self):
        kept, n = apply_ignores(
            [self._finding("CVE-2020-1")], {"CVE-2020-1"}, set()
        )
        assert kept == [] and n == 1

    def test_ignore_by_alias(self):
        f = Finding(vuln_id="PYSEC-1", package="pyyaml", version="5.3", severity="HIGH",
                    aliases=["CVE-2020-1"])
        kept, n = apply_ignores([f], {"CVE-2020-1"}, set())
        assert kept == [] and n == 1

    def test_ignore_by_package(self):
        kept, n = apply_ignores(
            [self._finding("CVE-2020-1"), self._finding("CVE-2020-2")], set(), {("pyyaml", None)}
        )
        assert kept == [] and n == 2

    def test_ignore_package_normalized(self):
        kept, n = apply_ignores([self._finding(pkg="PyYAML")], set(), {("pyyaml", None)})
        assert kept == [] and n == 1

    def test_ignore_package_version_exact(self):
        f = self._finding("CVE-2020-1", version="5.3")
        kept, n = apply_ignores([f, self._finding("CVE-2020-2", version="5.4")], set(), {("pyyaml", "5.3")})
        assert len(kept) == 1 and n == 1
        assert kept[0].version == "5.4"

    def test_no_overlap_keeps_all(self):
        kept, n = apply_ignores([self._finding()], {"CVE-9999-1"}, {("flask", None)})
        assert len(kept) == 1 and n == 0