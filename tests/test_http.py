"""http.py: HttpClient with retry/backoff, JSON handling, clean failure."""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request

import pytest

from sbombox.http import HttpClient


class FakeResp:
    def __init__(self, status, body=b"", headers=None):
        self._status = status
        self._body = body
        self.headers = headers or {}

    def getcode(self):
        return self._status

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeUrlOpen:
    def __init__(self, responses):
        # responses: list of (status, body) consumed in order
        self._responses = list(responses)
        self.calls = 0

    def __call__(self, req, timeout=None, context=None):
        self.calls += 1
        status, body = self._responses.pop(0)
        if status >= 400:
            # fp must be file-like: HTTPError.read() delegates to it
            raise urllib.error.HTTPError(req.full_url, status, "err", {}, io.BytesIO(body))
        return FakeResp(status, body)


@pytest.fixture
def client(monkeypatch):
    c = HttpClient(timeout=1.0, max_retries=3)
    monkeypatch.setattr("time.sleep", lambda s: None)
    return c


class TestRequest:
    def test_json_response(self, monkeypatch, client):
        fa = FakeUrlOpen([(200, json.dumps({"a": 1}).encode())])
        monkeypatch.setattr(urllib.request, "urlopen", fa)
        status, data = client.request("https://x.test/api")
        assert status == 200 and data == {"a": 1}
        assert fa.calls == 1

    def test_text_response(self, monkeypatch, client):
        fa = FakeUrlOpen([(200, b"plain text")])
        monkeypatch.setattr(urllib.request, "urlopen", fa)
        status, data = client.request("https://x.test/api")
        assert status == 200 and data == "plain text"

    def test_empty_body(self, monkeypatch, client):
        fa = FakeUrlOpen([(204, b"")])
        monkeypatch.setattr(urllib.request, "urlopen", fa)
        assert client.request("https://x.test/api") == (204, None)

    def test_404_no_retry(self, monkeypatch, client):
        fa = FakeUrlOpen([(404, b"nope")])
        monkeypatch.setattr(urllib.request, "urlopen", fa)
        status, _ = client.request("https://x.test/api")
        assert status == 404 and fa.calls == 1

    def test_429_retries_then_succeeds(self, monkeypatch, client):
        fa = FakeUrlOpen([(429, b"slow"), (429, b"slow"), (200, b"{}")])
        monkeypatch.setattr(urllib.request, "urlopen", fa)
        status, _ = client.request("https://x.test/api")
        assert status == 200 and fa.calls == 3

    def test_500_retries_then_returns_error(self, monkeypatch, client):
        # Design: retryable statuses exhaust retries, then the HTTP error
        # tuple is returned — sources fail closed on non-200 themselves.
        fa = FakeUrlOpen([(500, b"oops")] * (client.max_retries + 1))
        monkeypatch.setattr(urllib.request, "urlopen", fa)
        status, data = client.request("https://x.test/api")
        assert status == 500
        assert data is None
        assert fa.calls == client.max_retries + 1

    def test_urlerror_retries_then_raises(self, monkeypatch, client):
        def boom(req, timeout=None, context=None):
            raise urllib.error.URLError("dns down")

        monkeypatch.setattr(urllib.request, "urlopen", boom)
        with pytest.raises(RuntimeError, match="dns down"):
            client.request("https://x.test/api")

    def test_http_error_payload_json(self, monkeypatch, client):
        fa = FakeUrlOpen([(403, json.dumps({"message": "forbidden"}).encode())])
        monkeypatch.setattr(urllib.request, "urlopen", fa)
        status, data = client.request("https://x.test/api")
        assert status == 403 and data == {"message": "forbidden"}

    def test_post_sends_json(self, monkeypatch, client):
        captured = {}

        def fake(req, timeout=None, context=None):
            captured["method"] = req.get_method()
            captured["data"] = req.data
            captured["headers"] = {k.lower(): v for k, v in req.header_items()}
            return FakeResp(200, b"{}")

        monkeypatch.setattr(urllib.request, "urlopen", fake)
        client.request("https://x.test/api", method="POST", data={"q": 1})
        assert captured["method"] == "POST"
        assert json.loads(captured["data"]) == {"q": 1}
        assert captured["headers"]["content-type"] == "application/json"
        assert "user-agent" in captured["headers"]


class TestBackoff:
    def test_retry_after_used(self):
        assert HttpClient._backoff(0, "5") == 5.0
        assert HttpClient._backoff(0, "1.5") == 1.5
        assert HttpClient._backoff(0, "bogus") == 1.0

    def test_exponential_cap(self):
        assert HttpClient._backoff(0, None) == pytest.approx(1.0)
        assert HttpClient._backoff(3, None) == pytest.approx(8.3)
        # capped at 30
        assert HttpClient._backoff(10, None) == 30.0