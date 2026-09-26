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
examples/          # CI workflow template for other repos
scan.sh / run      # local helpers
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
./run sbombox
```

Or with the wrapper directly:

```bash
./scan.sh /path/to/your-project
./scan.sh .
```

Outputs:

```text
your-project/sbom-report/sbom-report.md
your-project/sbom-report/sbom.cdx.json
```

---

## 3. Common options

| What you want | Command |
|---|---|
| Full scan (default via `./run`) | `./run sbombox` |
| Fast scan (skip NVD) | `./run sbombox --fast` |
| Scan another path | `./scan.sh /path/to/your-project` |
| SBOM only (no network) | `PYTHONPATH=. python3 -m sbombox /path/to/your-project --sbom-only` |
| Include installed/transitive packages | activate your venv, then `PYTHONPATH=. python3 -m sbombox /path/to/your-project --env` |
| Skip GitHub Advisory Database | `python3 -m sbombox . --no-github` |
| Quiet CI logs (files still written) | `python3 -m sbombox . --quiet` |
| Version | `python3 -m sbombox --version` |

Or install and use the console script:

```bash
pip install .
sbombox /path/to/your-project
```

Or put keys in `.env` next to `scan.sh` (see `.env.example`). `./scan.sh` loads it automatically.

---

## 4. What you get

| File | What it is |
|---|---|
| `sbom-report/sbom.cdx.json` | CycloneDX 1.5 SBOM |
| `sbom-report/sbom-report.md` | Human report (how to read it + findings) |
| `sbom-report/sbom-report.json` | Same findings for scripts |

| Exit | Meaning |
|---|---|
| `0` | Clean (nothing at/above `--fail-on`, default `high`) |
| `1` | Findings at/above the threshold |
| `2` | Error (including no vulnerability source responding) |

---

## 5. Ignore a finding

Only **advisory IDs** are accepted (`CVE-` / `GHSA-` / `PYSEC-` / `MAL-`).  
Package-name ignores are rejected on purpose — they would silence every future finding for that package.

`.vulnignore`:

```text
CVE-2020-1747  # not reachable in our app | @alice | review-by:2026-12-01
```

Or:

```bash
PYTHONPATH=. python3 -m sbombox /path/to/your-project --ignore CVE-2020-1747
```

---

## 6. CI/CD

### This repository (sBOMBox)

GitHub Actions (`.github/workflows/ci.yml`):

- `pytest` offline suite
- live smoke: `--sbom-only`, gate on `PyYAML==5.3`, `--ignore` clears the gate

### Your application repo

1. Copy `sbombox/`, `scan.sh`, `.vulnignore` (and optionally `run`) into the app repo.
2. Copy [`examples/dependency-scan.yml`](examples/dependency-scan.yml) to `.github/workflows/dependency-scan.yml`.
3. Optional: add repo secret `NVD_API_KEY` (Actions already provides `GITHUB_TOKEN`).
4. Optional: make **sBOMBox scan** a required check on `main`.

The example workflow runs on dependency file changes, weekday schedule, and manual dispatch; it uploads `sbom-report/` as an artifact.

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
