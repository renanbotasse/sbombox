# SBOMBox

Scan Python dependencies, build a CycloneDX SBOM, and fail CI on `HIGH` / `CRITICAL` findings.

**Needs:** Python 3.9+ (3.11+ for `poetry.lock` / `uv.lock`). No extra pip packages.

---

## 1. Setup

Copy these files into your repo (or keep this folder and point the scan at your project):

```
scripts/sbom_scan.py
scan.sh
.vulnignore
.github/workflows/dependency-scan.yml   # optional, for CI
```

Make the helper executable:

```bash
chmod +x scan.sh
```

That is the whole setup.

---

## 2. Run (simple)

From this folder, scan **your project** (folder with `requirements.txt`, `poetry.lock`, `uv.lock`, or `Pipfile.lock`):

```bash
./scan.sh /path/to/your-project
```

Or scan the current directory:

```bash
./scan.sh .
```

Open the report:

```text
your-project/sbom-report/vuln-report.md
your-project/sbom-report/sbom.cdx.json
```

---

## 3. Common options

| What you want | Command |
|---|---|
| Fast scan (default, skips NVD) | `./scan.sh /path/to/your-project` |
| Full scan with NVD | `./scan.sh --with-nvd /path/to/your-project` |
| SBOM only (no network) | `python3 scripts/sbom_scan.py /path/to/your-project --sbom-only` |
| Include installed/transitive packages | activate your venv, then `python3 scripts/sbom_scan.py /path/to/your-project --env` |

NVD is off by default because without an API key it waits ~6s per CVE. To speed it up when enabled:

```bash
export NVD_API_KEY=your-key
./scan.sh --with-nvd /path/to/your-project
```

---

## 4. What you get

| File | What it is |
|---|---|
| `sbom-report/sbom.cdx.json` | CycloneDX 1.5 SBOM |
| `sbom-report/vuln-report.md` | Human report (how to read it + findings table) |
| `sbom-report/vuln-report.json` | Same findings for scripts |

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Clean (nothing at/above `--fail-on`, default `high`) |
| `1` | Findings at/above the threshold |
| `2` | Error (including no vulnerability source responding) |

---

## 5. Ignore a finding

Add an ID to `.vulnignore` (reason, owner, review date required):

```text
CVE-2020-1747  # not reachable in our app | @alice | review-by:2026-12-01
```

Or once on the CLI:

```bash
python3 scripts/sbom_scan.py /path/to/your-project --ignore CVE-2020-1747
```

---

## 6. CI (optional)

If you added `.github/workflows/dependency-scan.yml`, GitHub Actions runs the scan on:

- PRs / pushes that touch dependency files
- Weekdays (scheduled)
- Manual runs (`workflow_dispatch`)

The job summary shows the markdown report; `sbom-report` is uploaded as an artifact (30 days).

Optional repo secrets: `NVD_API_KEY`. `GITHUB_TOKEN` is provided by Actions automatically.

---

## 7. Quick self-test

```bash
mkdir -p /tmp/vulntest && echo "PyYAML==5.3" > /tmp/vulntest/requirements.txt
./scan.sh /tmp/vulntest
echo $?   # expect 1
```

---

## Notes

- Auto-detects: `poetry.lock` → `uv.lock` → `Pipfile.lock` → `requirements.txt` → installed env
- **Fixed in** prefers the fix on your release line (or the first version newer than yours) — never a downgrade
- `MAL-*` advisories are always `CRITICAL`
- Same CVE/GHSA/PYSEC from multiple sources is shown once

More detail on roadmap items: [`BACKLOG_dependency-security.md`](BACKLOG_dependency-security.md).
