from __future__ import annotations

import concurrent.futures
import urllib.parse
from typing import Any, Optional

from sbombox.http import HttpClient
from sbombox.models import Package
from sbombox.util import log

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"


def query_osv(client: HttpClient, packages: list[Package]) -> tuple[list[dict[str, Any]], bool]:
    """Return (raw vuln dicts with package context, ok)."""
    if not packages:
        return [], True

    results: list[dict[str, Any]] = []
    ok = False
    total_batches = (len(packages) + 99) // 100
    log(f"OSV: querying {len(packages)} packages ({total_batches} batch(es))...")
    for i in range(0, len(packages), 100):
        chunk = packages[i : i + 100]
        batch_no = i // 100 + 1
        queries = [
            {"package": {"name": p.normalized, "ecosystem": "PyPI"}, "version": p.version}
            for p in chunk
        ]
        try:
            status, data = client.request(OSV_QUERYBATCH, method="POST", data={"queries": queries})
        except RuntimeError as e:
            log(f"OSV querybatch failed: {e}")
            continue
        if status != 200 or not isinstance(data, dict):
            log(f"OSV querybatch HTTP {status}")
            continue
        ok = True

        vuln_ids: list[tuple[Package, str]] = []
        for pkg, res in zip(chunk, data.get("results") or []):
            for v in res.get("vulns") or []:
                vid = v.get("id")
                if vid:
                    vuln_ids.append((pkg, vid))
        log(f"OSV: batch {batch_no}/{total_batches} → {len(vuln_ids)} vuln id(s), fetching details...")

        def fetch_one(item: tuple[Package, str]) -> Optional[dict[str, Any]]:
            pkg, vid = item
            try:
                st, detail = client.request(OSV_VULN.format(id=urllib.parse.quote(vid)))
            except RuntimeError:
                return None
            if st != 200 or not isinstance(detail, dict):
                return None
            detail["_package"] = pkg.normalized
            detail["_version"] = pkg.version
            detail["_source"] = "osv"
            return detail

        done = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for detail in pool.map(fetch_one, vuln_ids):
                done += 1
                if done % 25 == 0 or done == len(vuln_ids):
                    log(f"OSV: details {done}/{len(vuln_ids)}")
                if detail:
                    results.append(detail)
    log(f"OSV: done ({len(results)} raw hit(s))")
    return results, ok
