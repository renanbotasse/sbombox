"""Shared fixtures for the sBOMBox test suite (fully offline)."""

from __future__ import annotations

from typing import Any

import pytest

from sbombox.models import Finding


class FakeClient:
    """HttpClient stand-in: serves canned (status, body) per URL, records calls."""

    def __init__(self, responses: dict[str, tuple[int, Any]] | None = None) -> None:
        self.responses = list((responses or {}).items())
        self.calls: list[tuple[str, str, dict]] = []

    def request(self, url: str, *, method: str = "GET", data: Any = None, headers: dict | None = None):
        self.calls.append((url, method, headers or {}))
        for prefix, (status, body) in self.responses:
            if url.startswith(prefix):
                return status, body
        raise AssertionError(f"Unexpected request: {method} {url}")


class AlwaysFailClient:
    """HttpClient stand-in: every request raises RuntimeError."""

    def request(self, url: str, **_kw):
        raise RuntimeError(f"boom: {url}")


@pytest.fixture
def make_finding():
    def _make(**overrides) -> Finding:
        base = dict(
            vuln_id="CVE-2020-0001",
            package="pyyaml",
            version="5.3",
            severity="HIGH",
        )
        base.update(overrides)
        return Finding(**base)

    return _make