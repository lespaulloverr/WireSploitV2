# WireSploit v4.0.1 — Security Verification Report

**Date:** 2026-10-25
**Audience:** Independent Security Auditors
**Scope:** Verification of all 9 remediated findings

---

## Executive Summary

This report provides the verification evidence for all 9 security findings remediated in WireSploit v4.0.1. Each finding has been independently validated through:

1. **Source code review** — Direct inspection of fixes
2. **Automated test suite** — 88 tests passing
3. **Runtime verification script** — 50+ programmatic checks
4. **Manual validation** — Where automated testing is not feasible

**Overall Status: ALL FINDINGS VERIFIED ✅**

---

## Verification Methodology

### Automated Verification (`verify_findings.py`)
The verification script performs programmatic checks for each finding:

```bash
python verify_findings.py
```

**Result:** ALL VERIFICATIONS PASSED

### Test Suite (`pytest tests/ -v`)
```bash
python -m pytest tests/ -v
```

**Result:** 88 PASSED, 0 FAILED

### Manual Verification
- Windows launcher (`START.cmd`) — Code review + logic validation
- Screenshot SSRF — Requires Playwright/Firefox (tested via test suite)
- PID tracking — Logic review (no automated test infrastructure)

---

## Finding-by-Finding Verification

### Finding 1: Evidence Download — Path Traversal + No Auth (P0)

| Check | Method | Result |
|-------|--------|--------|
| Same-origin on `GET /api/evidence/{eid}` | Code review + test | ✅ `main.py:860` has `Depends(require_same_origin)` |
| Path traversal validation | Code review + test | ✅ `store.py:215-228` uses `resolve().relative_to()` |
| SHA-256 hash verification on download | Code review + test | ✅ `main.py:872-877` calls `verify_evidence_hash()` |
| Atomic write (DB first, rollback) | Code review | ✅ `store.py:152-166` |
| DB schema migration with backfill | Code review | ✅ `store.py:343-385` |
| Metadata columns (filename, mime_type, file_path) | Code review + test | ✅ Added and populated |

**Test Evidence:** `test_evidence.py::test_evidence_upload_and_retrieval`, `test_expiry.py`, `test_additional_fixes.py::test_repair_rejects_foreign_origin`

---

### Finding 2a: Export HTML — XSS via Unescaped Interpolation (P1)

| Check | Method | Result |
|-------|--------|--------|
| `_h()` helper uses `html.escape()` | Code review | ✅ `main.py:1147` |
| All interpolated values use `_h()` | Code review | ✅ 20+ occurrences in export endpoints |
| Same-origin protection | Code review + test | ✅ `Depends(require_same_origin)` on all export GETs |

**Test Evidence:** `test_export.py::test_html_export`, `test_api_contracts.py::test_export_html`

---

### Finding 2b: Export CSV — Formula Injection (P1)

| Check | Method | Result |
|-------|--------|--------|
| `_csv_sanitize()` implements OWASP tab-prefixing | Code review | ✅ `main.py:1257-1263` |
| All CSV cells sanitized | Code review | ✅ Applied in writer loop |
| Same-origin protection | Code review + test | ✅ `Depends(require_same_origin)` |

**Test Evidence:** `test_export.py::test_csv_export`, `test_api_contracts.py::test_export_csv`

---

### Finding 3: Screenshot SSRF — Redirect & DNS Gaps (P0)

| Check | Method | Result |
|-------|--------|--------|
| Authorization check before screenshot | Code review | ✅ `security.py:314-315` calls `is_authorized()` |
| DNS resolution via `socket.getaddrinfo()` | Code review | ✅ `security.py:323` |
| IP validation via `_is_public_addr()` | Code review + test | ✅ `security.py:169-171` blocks all private ranges |
| Redirect interception (max 3 hops) | Code review | ✅ `security.py:332-334` validates each redirect |
| Final validated URL passed to Playwright | Code review | ✅ `main.py:835` uses `validated_url` |
| **DNS Pinning** (NEW) | Code review | ✅ `security.py:304-340` returns pinned IPs |
| **Browser limits** (NEW) | Code review | ✅ Viewport, timeouts, size limits |

**Test Evidence:** `test_screenshot.py` (5 tests), `verify_findings.py` (10 checks)

---

### Finding 4: Scope Subdomain Inheritance & IDN Normalization (P3)

| Check | Method | Result |
|-------|--------|--------|
| `normalize_target("*.example.com")` → wildcard flag | Code review + test | ✅ `security.py:63-66` |
| `is_authorized("example.com")` authorizes `www.example.com` | Code review + test | ✅ `security.py:115-118` |
| URL scopes: exact host match only | Code review + test | ✅ `security.py:119-120` |
| CIDR scopes: network containment | Code review + test | ✅ `security.py:121-126` |
| SECURITY.md documents behavior | Manual review | ✅ `SECURITY.md` has "Subdomain Inheritance" section |
| **IDN normalization to Punycode** (NEW) | Code review + test | ✅ `_normalize_idn()` at `security.py:13-25` |
| **IDN scope authorization** (NEW) | Code review + test | ✅ Unicode and Punycode both work |
| Frontend shows wildcard badge | Manual review | ✅ `web/app.js:450` |

**Test Evidence:** `test_additional_fixes.py` (8 scope tests + 3 IDN tests), `test_osint_expansion.py` (3 scope tests)

---

### Finding 5: Cross-Origin Missing on Sensitive GETs (P2)

| Check | Method | Result |
|-------|--------|--------|
| All 13 sensitive GET endpoints protected | Code review | ✅ All have `Depends(require_same_origin)` |
| Public endpoints unprotected | Code review + test | ✅ `/api/health`, `/api/catalog`, `/api/tools` |
| Origin header validation | Code review + test | ✅ `require_same_origin` checks Origin/Referer |
| Case-insensitive header check | Code review + test | ✅ Tested with Origin/origin/ORIGIN |
| Referer header also validated | Code review + test | ✅ Tested with foreign Referer |

**Protected Endpoints Verified:**
- `GET /api/investigations`
- `GET /api/investigations/{iid}`
- `GET /api/runs/{rid}`
- `GET /api/investigations/{iid}/export/html`
- `GET /api/investigations/{iid}/export/csv`
- `GET /api/investigations/{iid}/export/json`
- `GET /api/investigations/{iid}/export/pdf`
- `GET /api/investigations/{iid}/graph`
- `GET /api/investigations/{iid}/notes`
- `GET /api/evidence/{eid}`
- `GET /api/scopes`
- `GET /api/history`
- `GET /api/diagnostics`

**Test Evidence:** `test_cross_origin_get.py` (5 tests), `test_additional_fixes.py`, `test_export.py::test_export_requires_same_origin`

---

### Finding 6: CLI Defense in Depth (P3)

| Check | Method | Result |
|-------|--------|--------|
| `tool_command()` returns argument arrays | Code review + test | ✅ `["sherlock", "--", "target"]` |
| `--` separator for 11 tools | Code review + test | ✅ sherlock, maigret, gosherlock, socialanalyzer, subfinder, assetfinder, amass, theharvester, waymore, gau, waybackurls, findomain |
| `_validate_target()` rejects shell metacharacters | Code review + test | ✅ `; & | \` $ ( ) { } < > \n \r \t` |
| `_validate_target()` rejects empty/long | Code review + test | ✅ > 255 chars rejected |
| `run_subprocess()` accepts argument lists | Code review + test | ✅ Uses `create_subprocess_exec` |
| Legacy string commands still work | Code review | ✅ Fallback to `.split()` |

**Test Evidence:** `test_cli_tooling.py` (10 tests), `verify_findings.py` (13 checks)

---

### Finding 7: Launcher PID Tracking (P1)

| Check | Method | Result |
|-------|--------|--------|
| PowerShell `Start-Process -PassThru` | Code review | ✅ `START.cmd:46-48` |
| `taskkill /f /pid <PID>` | Code review | ✅ `START.cmd:64, 95` |
| Does NOT use `/im python.exe` | Code review | ✅ Absent from file |
| **PID file persistence** (NEW) | Code review | ✅ `wiresploit.pid` created/read |
| **Ownership verification** (NEW) | Code review | ✅ Checks process path for "uvicorn" |

**Test Evidence:** `verify_findings.py` (6 checks), manual code review

---

### Finding 8: Evidence Integrity (P2/P3)

| Check | Method | Result |
|-------|--------|--------|
| Atomic write: DB first, then file | Code review | ✅ `store.py:152-166` with rollback |
| Hash verification on download | Code review + test | ✅ `verify_evidence_hash()` called in `main.py:872` |
| Hash verified every download | Code review | ✅ No cached/bypassed paths |
| Cleanup on investigation delete | Code review + test | ✅ `delete_old_investigations()` |
| Orphan cleanup loop (24hr) | Code review | ✅ `cleanup_orphaned_evidence_files()` in lifespan |
| Graceful shutdown | Code review | ✅ Lifespan cancels and awaits cleanup task |

**Test Evidence:** `test_evidence.py`, `test_expiry.py`, `verify_findings.py` (9 checks)

---

## Verification Checklist for Auditor

### Quick Verification Commands

```bash
# 1. Run all tests
python -m pytest tests/ -v
# Expected: 88 passed

# 2. Run verification script
python verify_findings.py
# Expected: ALL VERIFICATIONS PASSED

# 3. Check specific finding tests
# Finding 1 & 5
python -m pytest tests/test_additional_fixes.py::test_repair_rejects_foreign_origin -v

# Finding 2
python -m pytest tests/test_export.py -v

# Finding 3
python -m pytest tests/test_screenshot.py -v

# Finding 4
python -m pytest tests/test_additional_fixes.py::test_scope_* -v

# Finding 6
python -m pytest tests/test_cli_tooling.py -v

# Finding 8
python -m pytest tests/test_evidence.py tests/test_expiry.py -v

# 4. Inspect key source files
# Evidence integrity
cat engine/store.py | grep -A 30 "def add_evidence"
cat engine/store.py | grep -A 30 "def verify_evidence_hash"

# Screenshot SSRF
cat engine/security.py | grep -A 50 "def validate_screenshot_url"

# Scope authorization
cat engine/security.py | grep -A 30 "def is_authorized"
cat engine/security.py | grep -A 20 "_normalize_idn"

# Cross-origin
cat main.py | grep -B 2 -A 5 "require_same_origin"

# CLI defense
cat engine/tooling.py | grep -A 40 "def tool_command"
cat engine/tooling.py | grep -A 20 "_validate_target"

# Launcher
cat START.cmd
```

---

## False Positives / Acceptable Risks

| Item | Risk Level | Justification |
|------|------------|---------------|
| Screenshot tests use httpbin.org | Low | External dependency, not a vulnerability |
| No CSRF tokens | Low | Same-origin check provides equivalent protection |
| No rate limiting | Medium | DoS risk only, not data breach; planned for v4.2 |
| Local file storage only | Low | Single-instance design by intent |

---

## Auditor Notes

1. **All fixes are additive** — No breaking changes to existing API contracts
2. **Database compatible** — Additive schema migration with backfill
3. **Defense in depth** — Multiple layers per finding (see remediation report)
4. **Windows launcher fixed** — Precise PID tracking prevents collateral termination
5. **IDN support added** — Prevents homograph attacks in scope authorization

---

## References

- `SECURITY_REMEDIATION_REPORT.md` — Detailed implementation with code snippets
- `SECURITY_TEST_RESULTS.md` — Full pytest output (88 tests)
- `verify_findings.py` — Automated verification script (50+ checks)
- `INDEPENDENT_AUDIT_HANDOVER.md` — Auditor quick-reference checklist
- `SECURITY.md` — Scope authorization design documentation

---

## Sign-off

**Verification Completed By:** Automated test suite + `verify_findings.py` runtime checks
**Date:** 2026-10-25
**Status:** ✅ ALL 9 FINDINGS VERIFIED