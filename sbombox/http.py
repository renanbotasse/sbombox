from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Optional

from sbombox import NAME, __version__
from sbombox.util import log


class HttpClient:
    def __init__(self, timeout: float = 30.0, max_retries: int = 4) -> None:
        self.timeout = timeout
        self.max_retries = max_retries
        self._ctx = ssl.create_default_context()

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        data: Any = None,
        headers: Optional[dict[str, str]] = None,
    ) -> tuple[int, Any]:
        body: Optional[bytes] = None
        hdrs = {"User-Agent": f"{NAME}/{__version__}", "Accept": "application/json"}
        if headers:
            hdrs.update(headers)
        if data is not None:
            body = json.dumps(data).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")

        last_err: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                    raw = resp.read()
                    status = resp.getcode()
                    if not raw:
                        return status, None
                    try:
                        return status, json.loads(raw.decode("utf-8"))
                    except json.JSONDecodeError:
                        return status, raw.decode("utf-8", errors="replace")
            except urllib.error.HTTPError as e:
                last_err = e
                payload = e.read()
                retryable = e.code == 429 or 500 <= e.code < 600
                if retryable and attempt < self.max_retries:
                    wait = self._backoff(attempt, e.headers.get("Retry-After") if e.headers else None)
                    log(f"HTTP {e.code} for {url}; retry in {wait:.1f}s")
                    time.sleep(wait)
                    continue
                try:
                    return e.code, json.loads(payload.decode("utf-8")) if payload else None
                except Exception:
                    return e.code, None
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last_err = e
                if attempt < self.max_retries:
                    wait = self._backoff(attempt, None)
                    log(f"Network error for {url}: {e}; retry in {wait:.1f}s")
                    time.sleep(wait)
                    continue
        raise RuntimeError(f"Request failed after retries: {url}: {last_err}")

    @staticmethod
    def _backoff(attempt: int, retry_after: Optional[str]) -> float:
        if retry_after:
            try:
                return max(1.0, float(retry_after))
            except ValueError:
                pass
        return min(30.0, (2**attempt) + 0.1 * attempt)
