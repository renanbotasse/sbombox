"""cli.py end-to-end main(): flags, exit codes, report emission (offline)."""

from __future__ import annotations


import pytest

import sbombox.cli as cli
from sbombox.models import Finding, Package


@pytest.fixture
def offline_env(monkeypatch, tmp_path):
    """Route main() through --sbom-only or fully stubbed sources."""
    monkeypatch.setattr(cli, "query_osv", lambda c, p: ([], True))
    monkeypatch.setattr(cli, "query_github", lambda c, p, t: ([], bool(t)))
    monkeypatch.setattr(cli, "enrich_nvd", lambda c, f, k: None)
    return tmp_path


def _project(tmp_path, content="requests==2.31.0\n"):
    (tmp_path / "requirements.txt").write_text(content, encoding="utf-8")
    return tmp_path


class TestArgParser:
    def test_defaults(self):
        args = cli.build_arg_parser().parse_args(["target"])
        assert args.target == "target"
        assert args.output == "sbom-report"
        assert args.fail_on == "high"
        assert args.sbom_only is False
        assert args.quiet is False
        assert args.no_github is False
        assert args.no_nvd is False

    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as e:
            cli.build_arg_parser().parse_args(["--version"])
        assert e.value.code == 0
        out = capsys.readouterr().out
        assert "sbombox" in out and cli.__version__ in out

    def test_fail_on_choices(self):
        with pytest.raises(SystemExit):
            cli.build_arg_parser().parse_args(["t", "--fail-on", "severe"])


class TestMainBasics:
    def test_missing_target_returns_2(self, tmp_path, capsys):
        assert cli.main([str(tmp_path / "missing")]) == 2
        assert "Target not found" in capsys.readouterr().err

    def test_output_path_is_file_returns_2(self, tmp_path, capsys):
        proj = _project(tmp_path)
        blocker = tmp_path / "occupied"
        blocker.write_text("x")
        assert cli.main([str(proj), "--sbom-only", "-o", str(blocker)]) == 2
        assert "existing file" in capsys.readouterr().err

    def test_corrupt_lock_clean_error(self, tmp_path, capsys):
        (tmp_path / "poetry.lock").write_text("= broken [")
        assert cli.main([str(tmp_path), "--sbom-only"]) == 2
        assert "Cannot parse" in capsys.readouterr().err
        assert "Traceback" not in capsys.readouterr().err

    def test_sbom_only_writes_reports(self, offline_env, tmp_path):
        proj = _project(tmp_path)
        rc = cli.main([str(proj), "--sbom-only", "-o", str(tmp_path / "out")])
        assert rc == 0
        assert (tmp_path / "out" / "sbom.cdx.json").is_file()
        assert (tmp_path / "out" / "sbom-report.md").is_file()
        assert (tmp_path / "out" / "sbom-report.json").is_file()

    def test_sbom_only_never_queries_sources(self, offline_env, tmp_path, monkeypatch):
        proj = _project(tmp_path)
        monkeypatch.setattr(cli, "query_osv", lambda c, p: (_ for _ in ()).throw(AssertionError("called")))
        assert cli.main([str(proj), "--sbom-only"]) == 0

    def test_md_printed_by_default(self, offline_env, tmp_path, capsys):
        proj = _project(tmp_path)
        cli.main([str(proj), "--sbom-only"])
        assert "Dependency vulnerability report" in capsys.readouterr().out

    def test_quiet_suppresses_md(self, offline_env, tmp_path, capsys):
        proj = _project(tmp_path)
        cli.main([str(proj), "--sbom-only", "-q"])
        assert "Dependency vulnerability report" not in capsys.readouterr().out


class TestGate:
    @pytest.fixture(autouse=True)
    def _stub_sources(self, offline_env, monkeypatch):
        # Real Vulnerability DB round-trips are stubbed; findings injected per-test.
        monkeypatch.setattr(cli, "collect_packages", lambda t, force_env=False: (
            [Package("requests", "2.31.0")], [], "requirements.txt"))
        monkeypatch.setattr(cli, "query_osv", lambda c, p: ([], True))

    def _run(self, tmp_path, finding, args=()):
        def fake_gh(c, p, t):
            return [], True

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(cli, "query_github", fake_gh)
        monkeypatch.setattr(cli, "enrich_nvd", lambda c, f, k: None)
        try:
            # query_osv must return a raw record so the findings pipeline
            # (osv_to_finding -> dedupe -> ignores -> gate) runs for real.
            monkeypatch.setattr(cli, "query_osv", lambda c, p: ([{"id": "raw"}], True))
            if finding is not None:
                monkeypatch.setattr(cli, "osv_to_finding", lambda raw: finding)
            else:
                monkeypatch.setattr(cli, "osv_to_finding", lambda raw: None)
            return cli.main([str(tmp_path), "-o", str(tmp_path / "out"), *args])
        finally:
            monkeypatch.undo()

    def test_critical_fails_at_high(self, tmp_path):
        f = Finding(vuln_id="CVE-2020-1", package="requests", version="2.31.0", severity="CRITICAL")
        assert self._run(tmp_path, f) == 1

    def test_low_passes_at_high(self, tmp_path):
        f = Finding(vuln_id="CVE-2020-1", package="requests", version="2.31.0", severity="LOW")
        assert self._run(tmp_path, f) == 0

    def test_fail_on_none_always_passes(self, tmp_path):
        f = Finding(vuln_id="CVE-2020-1", package="requests", version="2.31.0", severity="CRITICAL")
        assert self._run(tmp_path, f, ["--fail-on", "none"]) == 0

    def test_fail_on_critical_passes_high(self, tmp_path):
        f = Finding(vuln_id="CVE-2020-1", package="requests", version="2.31.0", severity="HIGH")
        assert self._run(tmp_path, f, ["--fail-on", "critical"]) == 0

    def test_ignored_finding_does_not_fail(self, tmp_path):
        f = Finding(vuln_id="CVE-2020-1", package="requests", version="2.31.0", severity="CRITICAL")
        assert self._run(tmp_path, f, ["--ignore", "CVE-2020-1"]) == 0

    def test_ignored_package_does_not_fail(self, tmp_path):
        f = Finding(vuln_id="CVE-2020-1", package="requests", version="2.31.0", severity="CRITICAL")
        assert self._run(tmp_path, f, ["--ignore", "requests"]) == 0

    def test_package_at_version_ignore_exact(self, tmp_path):
        f = Finding(vuln_id="CVE-2020-1", package="requests", version="2.31.0", severity="CRITICAL")
        assert self._run(tmp_path, f, ["--ignore", "requests@2.31.0"]) == 0

    def test_package_ignore_wrong_version_still_fails(self, tmp_path):
        f = Finding(vuln_id="CVE-2020-1", package="requests", version="2.31.0", severity="CRITICAL")
        assert self._run(tmp_path, f, ["--ignore", "requests@2.0.0"]) == 1

    def test_no_github_flag_skips(self, tmp_path, monkeypatch):
        f = Finding(vuln_id="CVE-2020-1", package="requests", version="2.31.0", severity="LOW")
        called = {"n": 0}

        def fake_gh(c, p, t):
            called["n"] += 1
            return [], True

        monkeypatch.setattr(cli, "query_github", fake_gh)
        monkeypatch.setattr(cli, "enrich_nvd", lambda c, f, k: None)
        monkeypatch.setattr(cli, "osv_to_finding", lambda raw: f)
        rc = cli.main([str(tmp_path), "-o", str(tmp_path / "out"), "--no-github"])
        assert rc == 0
        assert called["n"] == 0

    def test_fail_closed_when_all_sources_dead(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cli, "query_osv", lambda c, p: ([], False))
        monkeypatch.setattr(cli, "query_github", lambda c, p, t: ([], False))
        monkeypatch.setattr(cli, "enrich_nvd", lambda c, f, k: None)
        rc = cli.main([str(tmp_path), "-o", str(tmp_path / "out")])
        assert rc == 2
        assert (tmp_path / "out" / "sbom.cdx.json").is_file()