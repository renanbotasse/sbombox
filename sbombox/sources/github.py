from __future__ import annotations

import concurrent.futures
import urllib.parse
from typing import Any

from sbombox.http import HttpClient
from sbombox.models import Package
from sbombox.util import log

GITHUB_ADVISORIES = "https://api.github.com/advisories"


def query_github(
    client: HttpClient, packages: list[Package], token: str
) -> tuple[list[dict[str, Any]], bool]:
    if not token or not packages:
        if not token:
            log("GitHub: skipped (no GITHUB_TOKEN)")
        return [], bool(token)

    results: list[dict[str, Any]] = []
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    log(f"GitHub Advisories: querying {len(packages)} packages...")

    def fetch_pkg(pkg: Package) -> tuple[list[dict[str, Any]], bool]:
        """Return (advisories, responded). ``responded`` means the API
        actually answered 200 — the old code set ``ok = True`` whenever the
        loop ran, so a source that failed every single request (auth error,
        rate limit, outage) was still reported as healthy and the CLI's
        fail-closed gate could pass on a dead source."""
        q = urllib.parse.urlencode(
            {
                "ecosystem": "pip",
                "affects": f"{pkg.normalized}@{pkg.version}",
                "per_page": "100",
            }
        )
        try:
            status, data = client.request(f"{GITHUB_ADVISORIES}?{q}", headers=headers)
        except RuntimeError as e:
            log(f"GitHub advisories failed for {pkg.normalized}: {e}")
            return [], False
        if status in (401, 403):
            log(f"GitHub advisories auth error HTTP {status}")
            return [], False
        if status != 200:
            log(f"GitHub advisories HTTP {status} for {pkg.normalized}")
            return [], False
        out: list[dict[str, Any]] = []
        if isinstance(data, list):
            for adv in data:
                if not isinstance(adv, dict) or adv.get("withdrawn_at"):
                    continue
                adv = dict(adv)
                adv["_package"] = pkg.normalized
                adv["_version"] = pkg.version
                adv["_source"] = "github"
                out.append(adv)
        return out, True

    done = 0
    any_ok = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        for batch, responded in pool.map(fetch_pkg, packages):
            done += 1
            if done % 20 == 0 or done == len(packages):
                log(f"GitHub: {done}/{len(packages)} packages")
            if responded:
                any_ok = True
            results.extend(batch)
    log(f"GitHub: done ({len(results)} raw hit(s))")
    return results, any_ok
