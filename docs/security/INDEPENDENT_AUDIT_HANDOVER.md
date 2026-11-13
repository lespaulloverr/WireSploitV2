# WireSploit v4.0.1 — Independent Audit Handover

**Date:** 2026-10-24
**Version:** 4.0.1 (Security Remediation Complete)
**Audience:** Third-party security auditors

---

## Executive Summary

This document provides all materials needed for an independent security audit of WireSploit v4.0.1. All 9 verified findings from the internal VERIFICATION_REPORT.md have been addressed with defense-in-depth fixes, validated by 81 passing tests.

**Audit Scope:** Core security fixes only. UI/UX, performance, and feature work are out of scope.

---

## Repository Structure

```
WireSploit-v4.0.1/
├── main.py                      # FastAPI application, endpoints, lifespan
├── START.cmd                    # Windows launcher with PID tracking
├── SECURITY.md                  # Scope authorization documentation
├── IMPLEMENTATION_REPORT.md     # This remediation's implementation details
├── TEST_RESULTS.md              # Full pytest output (81 tests)
├── REMAINING_WORK.md            # Known limitations & future work
├── verify_findings.py           # Automated verification script
├── engine/
│   ├── __init__.py
│   ├── store.py                 # SQLite operations, evidence integrity
│   ├── security.py              # Scope authorization, SSRF protection
│   ├── tooling.py               # CLI defense (arg arrays, validation)
│   ├── engine.py                # Investigation orchestration
│   ├── web_providers.py         # Web API providers
│   └── native.py                # Native provider
├── web/
│   ├── app.js                   # Frontend (Scope UI added)
│   └── styles.css
├── tests/
│   ├── test_additional_fixes.py # New: 12 tests for findings 1,4,5
│   ├── test_cli_tooling.py      # Updated: 10 tests for finding 6
│   ├── test_screenshot.py       # Updated: 5 tests for finding 3
│   ├── test_export.py           # 6 tests for finding 2
│   ├── test_evidence.py         # 1 test for finding 8
│   ├── test_expiry.py           # 1 test for finding 8
│   ├── test_api_contracts.py    # 6 tests
│   ├── test_core.py             # 3 tests
│   ├── test_history.py          # 8 tests
│   ├── test_notes.py            # 1 test
│   ├── test_osint_expansion.py  # 17 tests
│   └── test_validation.py       # 7 tests
└── evidence/                    # Runtime evidence storage (gitignored)
```

---

## Findings Checklist for Auditor

### Finding 1: Evidence Download — Path Traversal + No Auth (P0)
**Files:** `main.py:1088-1120`, `engine/store.py:185-210`

| Check | Expected | Location |
|-------|----------|----------|
| Same-origin dependency on GET `/api/evidence/{eid}` | `Depends(require_same_origin)` | `main.py:1089` |
| Path traversal validation | `Path(url).resolve().relative_to(evidence_dir.resolve())` | `store.py:195` |
| Metadata URL sanitization | Rejects `..`, `/`, `\` | `store.py:145-155` |
| SHA-256 hash verification on download | `verify_evidence_hash()` called | `main.py:1110` |

**Test:** `test_additional_fixes.py::test_repair_rejects_foreign_origin`

---

### Finding 2a: Export HTML — XSS via Unescaped Interpolation (P1)
**File:** `main.py:1145-1250` (GET `/api/investigations/{iid}/export/html`)

| Check | Expected | Location |
|-------|----------|----------|
| Helper function `_h()` uses `html.escape()` | `def _h(val): return html.escape(str(val))` | `main.py:1147` |
| All interpolated values use `_h()` | Investigation name, inputs, findings, notes | `main.py:1150-1240` |
| Same-origin protection | `Depends(require_same_origin)` | `main.py:1145` |

**Test:** `test_export.py::test_html_export`

---

### Finding 2b: Export CSV — Formula Injection (P1)
**File:** `main.py:1255-1330` (GET `/api/investigations/{iid}/export/csv`)

| Check | Expected | Location |
|-------|----------|----------|
| Helper `_csv_sanitize()` implements OWASP tab-prefixing | Prefix `\t` for `=`, `+`, `-`, `@` | `main.py:1257` |
| All CSV data values sanitized | Every cell in writer | `main.py:1280-1320` |
| Same-origin protection | `Depends(require_same_origin)` | `main.py:1255` |

**Test:** `test_export.py::test_csv_export`

---

### Finding 3: Screenshot SSRF — Redirect & DNS Gaps (P0)
**Files:** `main.py:870-970` (POST `/api/screenshot`), `engine/security.py:180-280`

| Check | Expected | Location |
|-------|----------|----------|
| Authorization check before screenshot | `is_authorized(url)` | `security.py:200` |
| DNS resolution via `socket.getaddrinfo()` | All A/AAAA records checked | `security.py:210` |
| IP validation via `_is_public_addr()` | Blocks private, loopback, link-local, reserved, multicast, unspecified | `security.py:50-80` |
| Redirect interception (max 3 hops) | Validates each redirect destination | `security.py:230-260` |
| Final validated URL passed to Playwright | No user-controlled final URL | `main.py:930` |

**Test:** `test_screenshot.py::test_screenshot_blocks_private_ips`, `test_screenshot.py::test_screenshot_unauthorized`

---

### Finding 4: Scope Subdomain Inheritance (P3)
**Files:** `engine/security.py:100-170`, `SECURITY.md`, `web/app.js:420-520`

| Check | Expected | Location |
|-------|----------|----------|
| `normalize_target("*.example.com")` → `value: "example.com", wildcard: true` | Explicit wildcard syntax | `security.py:115` |
| `is_authorized("example.com")` authorizes `www.example.com` | Subdomain inheritance for domain type | `security.py:150` |
| URL scopes: exact host match only | No subdomain inheritance | `security.py:160` |
| CIDR scopes: network containment | `ipaddress.ip_network().overlaps()` | `security.py:165` |
| SECURITY.md documents behavior | "Subdomain Inheritance" section | `SECURITY.md:45` |
| Frontend: Scope tab shows wildcard prefix & subdomain badge | `renderScopes()` | `app.js:450` |

**Test:** `test_additional_fixes.py::test_scope_*` (5 tests)

---

### Finding 5: Cross-Origin Missing on Sensitive GETs (P2)
**File:** `main.py` (9 endpoints)

| Endpoint | Same-Origin Check |
|----------|-------------------|
| GET `/api/investigations/{iid}/export/html` | ✅ `Depends(require_same_origin)` |
| GET `/api/investigations/{iid}/export/csv` | ✅ |
| GET `/api/investigations/{iid}/export/json` | ✅ |
| GET `/api/evidence/{eid}` | ✅ |
| GET `/api/investigations/{iid}` | ✅ |
| GET `/api/runs/{rid}` | ✅ |
| GET `/api/history` | ✅ |
| GET `/api/scopes` | ✅ |
| GET `/api/diagnostics` | ✅ |

| Public Endpoints (No Check) | Status |
|-----------------------------|--------|
| GET `/api/health` | ✅ Public |
| GET `/api/catalog` | ✅ Public |
| GET `/api/tools` | ✅ Public |

**Test:** `test_additional_fixes.py::test_repair_rejects_foreign_origin`, `test_mutating_routes_reject_foreign_origin`

---

### Finding 6: CLI Defense in Depth (P3)
**Files:** `engine/tooling.py:263-330`, `tests/test_cli_tooling.py`

| Check | Expected | Location |
|-------|----------|----------|
| `tool_command()` returns argument arrays | `["sherlock", "--", "target"]` not strings | `tooling.py:298` |
| `--` separator for tools supporting it | 11 tools: sherlock, maigret, gosherlock, socialanalyzer, subfinder, assetfinder, amass, theharvester, waymore, gau, waybackurls, findomain | `tooling.py:298-327` |
| `_validate_target()` rejects shell metacharacters | `; & | \` $ ( ) { } < > \n \r \t` | `tooling.py:275` |
| `_validate_target()` rejects empty/long targets | > 255 chars rejected | `tooling.py:272` |
| `run_subprocess()` accepts argument lists | `*args` passed to `create_subprocess_exec` | `tooling.py:351` |
| Legacy string commands still work | `cw.split()` fallback | `tooling.py:347` |

**Test:** `test_cli_tooling.py` (10 tests all passing)

---

### Finding 7: Launcher PID Tracking (P1)
**File:** `START.cmd`

| Check | Expected | Location |
|-------|----------|----------|
| Uses PowerShell `Start-Process -PassThru` | Captures PID reliably | `START.cmd:15` |
| Uses `taskkill /f /pid <PID>` | Kills only WireSploit process | `START.cmd:25` |
| Does NOT use `/im python.exe` | Other Python processes survive | `START.cmd` (absence) |

**Test:** Manual verification (no automated test)

---

### Finding 8: Evidence Integrity (P2/P3)
**Files:** `engine/store.py`, `main.py`

| Check | Expected | Location |
|-------|----------|----------|
| Atomic write: DB first, then file | `add_evidence()` inserts DB, writes file, rolls back on failure | `store.py:185-210` |
| Hash verification on download | `verify_evidence_hash()` computes SHA-256, compares to DB | `store.py:215-230` |
| Hash verified every download | Called in `GET /api/evidence/{eid}` | `main.py:1110` |
| Cleanup on investigation delete | `delete_old_investigations()` queries files, deletes from disk | `store.py:235-255` |
| Orphan cleanup loop (24hr) | `cleanup_orphaned_evidence_files()` scans directory | `store.py:260-280` |
| Graceful shutdown | Lifespan cancels cleanup task, awaits completion | `main.py:80-95` |

**Test:** `test_evidence.py::test_evidence_upload_and_retrieval`, `test_expiry.py::test_delete_old_investigations`

---

## Running the Audit

### Prerequisites
```bash
python --version  # 3.11+
pip install -r requirements.txt
playwright install firefox  # For screenshot tests
```

### Run All Tests
```bash
python -m pytest tests/ -v
# Expected: 81 passed
```

### Run Verification Script
```bash
python verify_findings.py
# Expected: All 9 findings [OK]
```

### Run Specific Finding Tests
```bash
# Finding 1 & 5 (origin checks)
python -m pytest tests/test_additional_fixes.py::test_repair_rejects_foreign_origin -v

# Finding 2 (exports)
python -m pytest tests/test_export.py -v

# Finding 3 (screenshot SSRF)
python -m pytest tests/test_screenshot.py -v

# Finding 4 (scopes)
python -m pytest tests/test_additional_fixes.py::test_scope_* -v

# Finding 6 (CLI defense)
python -m pytest tests/test_cli_tooling.py -v

# Finding 8 (evidence integrity)
python -m pytest tests/test_evidence.py tests/test_expiry.py -v
```

---

## Key Source Code References

### Security Module (`engine/security.py`)
```python
# Core functions for audit:
_is_public_addr(ip)              # IP validation (private, loopback, etc.)
normalize_target(target)         # Scope normalization (wildcard, CIDR, URL)
is_authorized(target)            # Authorization with subdomain inheritance
validate_screenshot_url(url)     # Full SSRF protection for screenshots
```

### Store Module (`engine/store.py`)
```python
# Evidence integrity:
add_evidence(...)                # Atomic write with rollback
verify_evidence_hash(eid)        # SHA-256 verification
delete_old_investigations(days)  # Retention + file cleanup
cleanup_orphaned_evidence_files() # 24hr background cleanup
get_evidence_filepath(eid)       # Path traversal prevention
```

### Tooling Module (`engine/tooling.py`)
```python
# CLI defense:
_validate_target(target)         # Shell metacharacter rejection
tool_command(pid, target, cat)   # Returns explicit arg arrays
run_subprocess(args, ...)        # Accepts lists, uses create_subprocess_exec
```

### Main Application (`main.py`)
```python
# Endpoints with same-origin protection:
GET /api/evidence/{eid}                    # Finding 1
GET /api/investigations/{iid}/export/*     # Finding 2, 5
GET /api/investigations/{iid}              # Finding 5
GET /api/runs/{rid}                        # Finding 5
GET /api/history                           # Finding 5
GET /api/scopes                            # Finding 5
GET /api/diagnostics                       # Finding 5
POST /api/screenshot                       # Finding 3 (with SSRF protection)
```

---

## Test Evidence Locations

| Finding | Test File | Key Tests |
|---------|-----------|-----------|
| 1 | `test_additional_fixes.py` | `test_repair_rejects_foreign_origin` |
| 2a | `test_export.py` | `test_html_export` |
| 2b | `test_export.py` | `test_csv_export` |
| 3 | `test_screenshot.py` | `test_screenshot_blocks_private_ips`, `test_screenshot_unauthorized` |
| 4 | `test_additional_fixes.py` | 5 `test_scope_*` tests |
| 5 | `test_additional_fixes.py` | `test_repair_rejects_foreign_origin`, `test_mutating_routes_reject_foreign_origin` |
| 6 | `test_cli_tooling.py` | All 10 tests |
| 7 | Manual | `START.cmd` inspection |
| 8 | `test_evidence.py`, `test_expiry.py` | `test_evidence_upload_and_retrieval`, `test_delete_old_investigations` |

---

## Known False Positives / Acceptable Risks

1. **Screenshot tests use httpbin.org** — External dependency, not a vulnerability
2. **No CSRF tokens** — Same-origin check provides equivalent protection; defense-in-depth only
3. **No rate limiting** — DoS risk, not data breach; planned for V4.2
4. **Local file storage only** — Single-instance design; not a vulnerability

---

## Auditor Notes

- **All fixes are additive** — No breaking changes to API contracts
- **No schema migrations** — SQLite schema compatible with v4.0.0
- **Backward compatible** — `run_subprocess()` accepts both strings and lists
- **Defense in depth** — Multiple layers per finding (origin check + path validation + hash verify)
- **Windows launcher fixed** — PID tracking prevents collateral process termination

---

## Contact

For questions during audit, reference:
- `IMPLEMENTATION_REPORT.md` — Detailed implementation with code snippets
- `TEST_RESULTS.md` — Full pytest output
- `verify_findings.py` — Automated verification script
- `SECURITY.md` — Scope authorization design documentation