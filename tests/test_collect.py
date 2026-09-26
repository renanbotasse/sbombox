"""collect.py: requirements parsing, lock files, env, dedupe, error paths."""

from __future__ import annotations

import json

import pytest

from sbombox.collect import (
    _collect_from_file,
    _dist_to_package,
    collect_packages,
    dedupe_packages,
    from_environment,
    from_pipfile_lock,
    from_requirements,
)
from sbombox.models import Package


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


class TestFromRequirements:
    def test_pinned_parsing(self, tmp_path):
        f = _write(tmp_path / "requirements.txt", "requests==2.31.0\nflask==3.0.1\n")
        pkgs, warns = from_requirements(f)
        assert [(p.name, p.version) for p in pkgs] == [("requests", "2.31.0"), ("flask", "3.0.1")]
        assert warns == []

    def test_quoted_versions_and_hash(self, tmp_path):
        f = _write(
            tmp_path / "requirements.txt",
            'click=="8.1.7" --hash=sha256:abc\nurllib3==2.0.7 --hash=sha256:def\n',
        )
        pkgs, warns = from_requirements(f)
        assert [(p.name, p.version) for p in pkgs] == [("click", "8.1.7"), ("urllib3", "2.0.7")]

    def test_unpinned_warns_and_skips(self, tmp_path):
        f = _write(tmp_path / "requirements.txt", "requests==2.31.0\nflask>=2.0\n")
        pkgs, warns = from_requirements(f)
        assert [(p.name, p.version) for p in pkgs] == [("requests", "2.31.0")]
        assert len(warns) == 1 and "Unpinned" in warns[0]

    def test_comments_blank_and_flags(self, tmp_path):
        f = _write(
            tmp_path / "requirements.txt",
            "# comment\n\n--index-url https://pypi.org/simple\n-r other.txt\n"
            "--extra-index-url https://x\nrequests==2.31.0\n",
        )
        (tmp_path / "other.txt").write_text("flask==3.0.1\n")
        pkgs, warns = from_requirements(f)
        names = sorted(p.name for p in pkgs)
        assert names == ["flask", "requests"]

    def test_line_continuation(self, tmp_path):
        f = _write(
            tmp_path / "requirements.txt",
            "requests==2.31.0 \\\n    --hash=sha256:abc\nflake8==6.1.0\n",
        )
        pkgs, warns = from_requirements(f)
        # file order preserved
        assert [(p.name, p.version) for p in pkgs] == [("requests", "2.31.0"), ("flake8", "6.1.0")]

    def test_inline_comment_stripped(self, tmp_path):
        f = _write(tmp_path / "requirements.txt", "requests==2.31.0  # http client\n")
        pkgs, _ = from_requirements(f)
        assert pkgs[0].version == "2.31.0"

    def test_editable_warns(self, tmp_path):
        f = _write(tmp_path / "requirements.txt", "-e ./local-pkg\nrequests==2.31.0\n")
        pkgs, warns = from_requirements(f)
        assert [p.name for p in pkgs] == ["requests"]
        assert any("editable" in w for w in warns)

    def test_unparseable_warns(self, tmp_path):
        f = _write(tmp_path / "requirements.txt", "requests==2.31.0\n!!!garbage!!!\n")
        pkgs, warns = from_requirements(f)
        assert len(pkgs) == 1
        assert any("Unparseable" in w for w in warns)

    def test_recursion_cycle_terminates(self, tmp_path):
        a = _write(tmp_path / "a.txt", "-r b.txt\n")
        _write(tmp_path / "b.txt", "-r a.txt\nrequests==2.31.0\n")
        pkgs, _ = from_requirements(a)
        assert [p.name for p in pkgs] == ["requests"]

    def test_nonextra_options_before_dash(self, tmp_path):
        f = _write(tmp_path / "requirements.txt", "--trusted-host pypi.org\nrequests==2.31.0\n")
        pkgs, _ = from_requirements(f)
        assert [p.name for p in pkgs] == ["requests"]

    def test_missing_file_warns(self, tmp_path):
        pkgs, warns = from_requirements(tmp_path / "nope.txt")
        assert pkgs == []
        assert any("Cannot read" in w for w in warns)


class TestLockFiles:
    def test_poetry_lock(self, tmp_path):
        f = _write(
            tmp_path / "poetry.lock",
            '[[package]]\nname = "requests"\nversion = "2.31.0"\n\n'
            '[[package]]\nname = "flask"\nversion = "3.0.1"\n',
        )
        pkgs, _, _ = collect_packages(tmp_path)
        assert [(p.name, p.version) for p in pkgs] == [("requests", "2.31.0"), ("flask", "3.0.1")]
        assert pkgs[0].source == str(f)

    def test_uv_lock(self, tmp_path):
        _write(
            tmp_path / "uv.lock",
            'version = 1\n[[package]]\nname = "typer"\nversion = "0.9.0"\n',
        )
        pkgs, _, _ = collect_packages(tmp_path)
        assert [(p.name, p.version) for p in pkgs] == [("typer", "0.9.0")]

    def test_lock_precedence_chain(self, tmp_path):
        _write(tmp_path / "requirements.txt", "requests==2.31.0\n")
        _write(tmp_path / "Pipfile.lock", json.dumps({"default": {}}))
        _write(tmp_path / "uv.lock", '[[package]]\nname = "uvpkg"\nversion = "1.0"\n')
        pkgs, _, label = collect_packages(tmp_path)
        assert label == "uv.lock"
        assert [p.name for p in pkgs] == ["uvpkg"]

    def test_pipfile_lock(self, tmp_path):
        data = {
            "default": {"requests": {"version": "==2.31.0"}, "flask": {"version": "==3.0.1"}},
            "develop": {"pytest": {"version": "==8.0.0"}},
            "unpinned": {"foo": {"version": ">=1.0"}},
        }
        f = _write(tmp_path / "Pipfile.lock", json.dumps(data))
        pkgs, _ = from_pipfile_lock(f)
        # insertion order: default section first, then develop
        assert [(p.name, p.version) for p in pkgs] == [
            ("requests", "2.31.0"),
            ("flask", "3.0.1"),
            ("pytest", "8.0.0"),
        ]

    def test_corrupt_poetry_lock_clean_error(self, tmp_path):
        _write(tmp_path / "poetry.lock", "not = = toml [ broken")
        with pytest.raises(SystemExit, match="Cannot parse"):
            collect_packages(tmp_path)

    def test_corrupt_pipfile_clean_error(self, tmp_path):
        f = _write(tmp_path / "Pipfile.lock", "{ not json !")
        with pytest.raises(SystemExit, match="Cannot parse"):
            _collect_from_file(f, [])


class TestEnvironment:
    class FakeDist:
        def __init__(self, metadata=None, version="1.0"):
            self.metadata = metadata
            self.version = version

    def test_normal_dist(self):
        pkg = _dist_to_package(self.FakeDist(metadata={"Name": "fakepkg"}))
        assert pkg is not None and pkg.name == "fakepkg" and pkg.version == "1.0"

    def test_missing_name_no_keyerror(self):
        # Regression: dist.metadata["Name"] raised KeyError for metadata
        # lacking a Name field.
        pkg = _dist_to_package(self.FakeDist(metadata={}))
        assert pkg is None

    def test_none_metadata(self):
        pkg = _dist_to_package(self.FakeDist(metadata=None))
        assert pkg is None

    def test_missing_version(self):
        pkg = _dist_to_package(self.FakeDist(version=""))
        assert pkg is None

    def test_from_environment_runs(self):
        pkgs = from_environment()
        assert isinstance(pkgs, list)


class TestCollectAndDedupe:
    def test_collect_from_file_dispatch(self, tmp_path):
        f = _write(tmp_path / "reqs.txt", "requests==2.31.0\n")
        pkgs, warns, label = _collect_from_file(f, [])
        assert label == "reqs.txt"
        assert len(pkgs) == 1

    def test_unsupported_file(self, tmp_path):
        f = _write(tmp_path / "data.bin", "x")
        with pytest.raises(SystemExit, match="Unsupported dependency file"):
            _collect_from_file(f, [])

    def test_missing_target_falls_to_env(self, tmp_path, monkeypatch):
        monkeypatch.setattr("sbombox.collect.from_environment", lambda: [])
        pkgs, warns, label = collect_packages(tmp_path / "missing")
        assert label == "environment"
        assert pkgs == []
        assert any("No lock/requirements" in w for w in warns)

    def test_target_file_direct(self, tmp_path):
        f = _write(tmp_path / "requirements.txt", "requests==2.31.0\n")
        pkgs, _, label = collect_packages(f)
        assert label == "requirements.txt"
        assert len(pkgs) == 1

    def test_force_env_ignores_target(self, tmp_path):
        _write(tmp_path / "requirements.txt", "requests==2.31.0\n")
        pkgs, _, label = collect_packages(tmp_path, force_env=True)
        assert label == "environment"

    def test_dedupe(self):
        pkgs = [
            Package("Requests", "2.31.0", "a"),
            Package("requests", "2.31.0", "b"),
            Package("requests", "2.31.1", "c"),
            Package("flask", "3.0.1", "d"),
        ]
        out = dedupe_packages(pkgs)
        assert len(out) == 3
        assert out[0].name == "flask"
        assert out[1].name == "Requests"  # first-seen wins
        assert out[2].name == "requests" and out[2].version == "2.31.1"