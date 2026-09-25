from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

from sbombox.util import normalize_name


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    source: str = ""

    @property
    def normalized(self) -> str:
        return normalize_name(self.name)

    @property
    def purl(self) -> str:
        return (
            f"pkg:pypi/{urllib.parse.quote(self.normalized)}"
            f"@{urllib.parse.quote(self.version)}"
        )


@dataclass
class Finding:
    vuln_id: str
    package: str
    version: str
    severity: str
    summary: str = ""
    fixed_in: Optional[str] = None
    aliases: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    cvss: Optional[float] = None
    nvd_status: Optional[str] = None
    references: list[str] = field(default_factory=list)

    def all_ids(self) -> set[str]:
        return {i.upper() for i in (self.vuln_id, *self.aliases) if i}
