# sBOMBox

Scan Python dependencies, build a CycloneDX SBOM, and fail CI on `HIGH` / `CRITICAL` findings.

**Needs:** Python 3.9+ (3.11+ for `poetry.lock` / `uv.lock`). No extra pip packages.

---

## Layout

```text
sbombox/           # Python package (stdlib only)
  cli.py           # CLI entrypoint
  collect.py       # lock / requirements / env collectors
  findings.py      # normalize + dedupe advisories
  report.py        # markdown / JSON reports
  sbom.py          # CycloneDX builder
  sources/         # OSV, GitHub, NVD clients
scan.sh            # thin wrapper
```

---

## 1. Setup

Clone this repo (or copy `sbombox/`, `scan.sh`, `.vulnignore`, and the optional workflow).

```bash
chmod +x scan.sh
```

---

## 2. Run

```bash
./scan.sh /path/to/your-project
```

Or:

```bash
./scan.sh .
```

Outputs:

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
| SBOM only (no network) | `PYTHONPATH=. python3 -m sbombox /path/to/your-project --sbom-only` |
| Include installed/transitive packages | activate your venv, then `PYTHONPATH=. python3 -m sbombox /path/to/your-project --env` |

```bash
export NVD_API_KEY=your-key
./scan.sh --with-nvd /path/to/your-project
```

---

## 4. What you get

| File | What it is |
|---|---|
| `sbom-report/sbom.cdx.json` | CycloneDX 1.5 SBOM |
| `sbom-report/vuln-report.md` | Human report (how to read it + findings) |
| `sbom-report/vuln-report.json` | Same findings for scripts |

| Exit | Meaning |
|---|---|
| `0` | Clean (nothing at/above `--fail-on`, default `high`) |
| `1` | Findings at/above the threshold |
| `2` | Error (including no vulnerability source responding) |

---

## 5. Ignore a finding

`.vulnignore`:

```text
CVE-2020-1747  # not reachable in our app | @alice | review-by:2026-12-01
```

Or:

```bash
PYTHONPATH=. python3 -m sbombox /path/to/your-project --ignore CVE-2020-1747
```

---

## 6. CI (optional)

Workflow: `.github/workflows/dependency-scan.yml`

Runs on dependency-related PRs/pushes, weekdays, and manual dispatch. Uploads `sbom-report` as an artifact.

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
- **Fixed in** prefers your release line (or the first newer version) — never a downgrade
- `MAL-*` advisories are always `CRITICAL`
- Same CVE/GHSA/PYSEC from multiple sources is shown once
