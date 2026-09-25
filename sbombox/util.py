from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def normalize_name(name: str) -> str:
    """PEP 503 normalized name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def severity_rank(s: str) -> int:
    return SEVERITY_ORDER.get((s or "UNKNOWN").upper(), 0)


def max_severity(a: str, b: str) -> str:
    return a if severity_rank(a) >= severity_rank(b) else b


def parse_severity(value: Any) -> str:
    if value is None:
        return "UNKNOWN"
    if isinstance(value, list):
        best = "UNKNOWN"
        for item in value:
            best = max_severity(best, parse_severity(item))
        return best
    if isinstance(value, dict):
        score = str(value.get("score") or "").upper()
        return score if score in SEVERITY_ORDER else "UNKNOWN"
    text = str(value).strip().upper()
    if text in SEVERITY_ORDER:
        return text
    if text == "MODERATE":
        return "MEDIUM"
    return "UNKNOWN"


def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def is_malware(*ids: str) -> bool:
    return any(i.upper().startswith("MAL-") for i in ids if i)


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def first_cve(ids: Iterable[str]) -> Optional[str]:
    for vid in ids:
        if vid.startswith("CVE-"):
            return vid
    return None
