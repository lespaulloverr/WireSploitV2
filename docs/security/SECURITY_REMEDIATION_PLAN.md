# WireSploit v4.0.1 — Security Remediation Plan

**Date:** 2026-10-25
**Based on:** Independent analysis of actual source code, database schema, and test suite (not relying on previous reports)

---

## Executive Summary

After independently inspecting the actual current source code, database schema, migrations, and test suite (81 tests passing), here is the verified status of each finding:

| Finding | Hermes Verdict | Actual Status | Notes |
|---------|---------------|---------------|-------|
| 1. Evidence Download Auth + Path Traversal | PARTIAL | **PARTIAL** | Origin check + path traversal OK, but evidence table missing `filename`, `mime_type`, `file_path` columns; original upload metadata not preserved |
| 2. HTML Export XSS | PASS | **PASS** | `html.escape()` via `_h()` helper correctly implemented |
| 3. CSV Formula Injection | PASS | **PASS** | OWASP tab-prefixing via `_csv_sanitize()` correctly implemented |
| 4. Screenshot SSRF, Redirects, DNS | PARTIAL | **PARTIAL** | Authorization, IP validation, redirect validation present; DNS rebinding TOCTOU gap, no response size limits, no navigation timeout |
| 5. Scope Inheritance + Wildcard | PARTIAL | **PARTIAL** | Wildcard syntax, subdomain inheritance, URL exact match, CIDR containment implemented; IDN normalization and edge cases need review |
| 6. Sensitive GET Cross-Origin | FAIL | **MOSTLY PASS** | All 13 sensitive GET endpoints HAVE `require_same_origin`; missing tests for GET origin checks; `/evidence/{eid}/file` and `/thumbnail` don't exist |
| 7. CLI Argument Construction | PASS | **PASS** | Argument arrays, target validation, `create_subprocess_exec`, `--` separators all implemented |
| 8. Windows Launcher PID Tracking | PARTIAL | **PARTIAL** | PowerShell `Start-Process -PassThru` + `taskkill /pid` implemented; no process verification, no PID file, no crash/repeated launch handling |
| 9. Evidence Integrity + Shutdown | PARTIAL | **PARTIAL** | Atomic write, hash verification, cleanup, graceful shutdown implemented; evidence table missing columns, original metadata not preserved |

**Test Suite:** 81 tests passing (not 36 as Hermes reported)
**verify_findings.py:** EXISTS and passes all checks (Hermes reported absent)

---

## Phase A — Detailed Finding Analysis

### Finding 1: Evidence Download Authorization and Path Traversal

**Reproducible:** YES

**Vulnerable Endpoint/Function:**
- `GET /api/evidence/{eid}` in `main.py:859-881`
- `store.get_evidence_filepath()` in `engine/store.py:185-203`
- `store.add_evidence()` in `engine/store.py:97-154`

**Root Cause:**
1. Evidence table schema missing columns: `filename` (original), `mime_type`, `file_path`
2. `add_evidence()` receives original `filename` and `content_bytes` but only stores extension in `url` column
3. Original filename and MIME type from upload are discarded
4. Path traversal protection exists via `Path.resolve().relative_to()` but relies on `url` column which is generated, not user-controlled

**Security Impact:**
- Cannot serve files with original names (UX/security)
- Cannot validate MIME type on download (potential content-type confusion)
- No audit trail of original upload metadata
- Evidence integrity verification works but metadata incomplete

**Required Remediation:**
1. Add columns to evidence table: `filename TEXT`, `mime_type TEXT`, `file_path TEXT`
2. Create migration to add columns (preserve existing data)
3. Update `add_evidence()` to store original filename and mime_type
4. Update `get_evidence_file()` to use original filename in Content-Disposition
5. Add MIME type validation on download

**Required Regression Tests:**
- Upload evidence with various filenames → verify original filename stored
- Upload evidence with various MIME types → verify MIME type stored
- Download evidence → verify Content-Disposition uses original filename
- Download evidence → verify Content-Type header uses stored MIME type
- Path traversal attempt via crafted evidence ID → blocked
- Cross-investigation evidence access → blocked

**Remaining Uncertainty:**
- Whether existing evidence records can be migrated safely (need to infer filename from `url` column)
- Whether `file_path` column should be stored or computed (computed is safer)

---

### Finding 2: HTML Export XSS

**Reproducible:** NO (already fixed)

**Status:** PASS — `html.escape()` properly used via `_h()` helper on all interpolated values in `/api/investigations/{iid}/export/html`

**Required Regression Tests:** Already covered by `test_export.py::test_html_export`

---

### Finding 3: CSV Formula Injection

**Reproducible:** NO (already fixed)

**Status:** PASS — OWASP tab-prefixing via `_csv_sanitize()` on all CSV cells in `/api/investigations/{iid}/export/csv`

**Required Regression Tests:** Already covered by `test_export.py::test_csv_export`

---

### Finding 4: Screenshot SSRF, Redirects and DNS Handling

**Reproducible:** YES (gaps exist)

**Vulnerable Endpoint/Function:**
- `POST /api/screenshot` in `main.py:803-846`
- `security.validate_screenshot_url()` in `engine/security.py:304-339`
- Playwright route interception in `main.py:819-830`

**Root Cause:**
1. **DNS Rebinding / TOCTOU:** `validate_screenshot_url()` resolves DNS and validates IPs, but Playwright's `page.goto()` performs its own DNS resolution later. An attacker could control a domain that resolves to public IP during validation but to private IP during browser navigation.
2. **No Response Size Limits:** Playwright captures full page screenshot without size limits — could consume memory.
3. **No Navigation Timeout:** `page.goto()` uses default timeout; no explicit timeout configured.
4. **Redirect Validation Gap:** Route interception validates redirects, but only for network requests. Meta-refresh, JavaScript redirects, or HTTP-equivalent redirects may not be intercepted.
5. **IPv6 Zone IDs:** `_is_public_addr()` may not handle IPv6 zone identifiers correctly.

**Security Impact:**
- SSRF via DNS rebinding to access internal services
- Memory exhaustion via large pages
- Bypass via client-side redirects

**Required Remediation:**
1. Implement DNS pinning: resolve once, pass `--host-resolver-rules` to Playwright to force use of validated IPs
2. Add response size limit and screenshot size limit
3. Add explicit navigation timeout
4. Enhance redirect interception to cover meta-refresh and JS redirects (or disable JavaScript for screenshots)
5. Verify IPv6 handling in `_is_public_addr()`

**Required Regression Tests:**
- DNS rebinding attempt: domain resolves to public IP then private IP → blocked
- Large page (>10MB) → rejected or truncated
- Navigation timeout → handled gracefully
- Meta-refresh redirect to private IP → blocked
- JavaScript redirect to private IP → blocked (or JS disabled)
- IPv6 loopback (::1) → blocked
- IPv6 link-local (fe80::) → blocked

**Remaining Uncertainty:**
- Playwright's `--host-resolver-rules` support on Windows
- Whether disabling JavaScript breaks legitimate screenshots
- Performance impact of DNS pinning

---

### Finding 5: Scope Inheritance and Wildcard Authorization

**Reproducible:** YES (edge cases need verification)

**Vulnerable Functions:**
- `security.normalize_target()` in `engine/security.py:48-75`
- `security.is_authorized()` in `engine/security.py:102-127`

**Root Cause:**
1. Implementation exists but edge cases untested:
   - Internationalized Domain Names (IDN) / Punycode
   - Trailing dots in hostnames
   - Case sensitivity
   - Unicode normalization
   - Parent/child boundary confusion (e.g., `example.com` vs `example.com.attacker.com`)
2. Wildcard flag stored but not used in authorization logic (domain type already covers subdomains)

**Security Impact:**
- Potential authorization bypass via crafted hostnames
- IDN homograph attacks
- Subdomain confusion

**Required Remediation:**
1. Add IDN/Punycode normalization in `normalize_target()` using `idna` library
2. Normalize hostnames: lowercase, strip trailing dots, NFC normalization
3. Explicit test for `example.com.attacker.com` not matching `example.com`
4. Document exact matching rules in SECURITY.md

**Required Regression Tests:**
- Exact hostname match → authorized
- Valid subdomain (`www.example.com` for `example.com`) → authorized
- Unrelated domain (`example.org`) → not authorized
- Similar-looking domain (`examp1e.com`) → not authorized
- Parent domain confusion (`example.com.attacker.com` for `example.com`) → not authorized
- Wildcard syntax (`*.example.com`) → same as domain
- CIDR containment (`192.0.2.1` in `192.0.2.0/24`) → authorized
- IDN domain (`xn--exmple-cua.com`) → normalized correctly
- Trailing dot (`example.com.`) → normalized to `example.com`
- Case insensitivity (`EXAMPLE.COM`) → authorized

**Remaining Uncertainty:**
- Whether `idna` library is available or needs to be added
- Whether wildcard flag should affect behavior differently than plain domain

---

### Finding 6: Sensitive GET Cross-Origin Protections

**Reproducible:** PARTIALLY (tests missing, but protection exists)

**Endpoints Inspected (ALL have `require_same_origin`):**
| Endpoint | Method | Protection |
|----------|--------|------------|
| `/api/investigations` | GET | ✅ `require_same_origin` |
| `/api/investigations/{iid}` | GET | ✅ `require_same_origin` |
| `/api/runs/{rid}` | GET | ✅ `require_same_origin` |
| `/api/investigations/{iid}/export/json` | GET | ✅ `require_same_origin` |
| `/api/investigations/{iid}/export/csv` | GET | ✅ `require_same_origin` |
| `/api/investigations/{iid}/export/html` | GET | ✅ `require_same_origin` |
| `/api/investigations/{iid}/export/pdf` | GET | ✅ `require_same_origin` |
| `/api/investigations/{iid}/graph` | GET | ✅ `require_same_origin` |
| `/api/evidence/{eid}` | GET | ✅ `require_same_origin` |
| `/api/investigations/{iid}/notes` | GET | ✅ `require_same_origin` |
| `/api/scopes` | GET | ✅ `require_same_origin` |
| `/api/history` | GET | ✅ `require_same_origin` |
| `/api/diagnostics` | GET | ✅ `require_same_origin` |

**Non-existent Endpoints (Hermes listed but don't exist):**
- `/api/evidence/{eid}/file` — does not exist
- `/api/evidence/{eid}/thumbnail` — does not exist

**Root Cause:**
1. All sensitive GET endpoints correctly protected
2. **Missing regression tests** for GET endpoints with Origin header
3. Only POST endpoint tests exist in `test_additional_fixes.py`

**Security Impact:**
- Without tests, regression could silently remove protection
- Current implementation relies on Origin header + Referer fallback

**Required Remediation:**
1. Add comprehensive tests for all sensitive GET endpoints with:
   - Legitimate same-origin requests
   - Untrusted cross-origin requests
   - Missing Origin headers
   - Malformed Origin headers
   - Unauthenticated requests
   - Cross-investigation access attempts

**Required Regression Tests:**
Create `tests/test_cross_origin_get.py` with tests for each endpoint above covering all scenarios listed in the requirements.

**Remaining Uncertainty:**
- Whether `require_same_origin` dependency correctly handles all edge cases (tested via new tests)

---

### Finding 7: CLI Argument Construction and Subprocess Execution

**Reproducible:** NO (already solid)

**Status:** PASS — Implementation uses:
- Explicit argument arrays via `tool_command()`
- Target validation rejecting shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `(`, `)`, `{`, `}`, `<`, `>`, `\n`, `\r`, `\t`)
- `asyncio.create_subprocess_exec()` (not shell=True)
- `--` separator for tools supporting it
- Length limit (255 chars)

**Required Regression Tests:** Already covered by `test_cli_tooling.py` (10 tests)

---

### Finding 8: Windows Launcher PID Tracking

**Reproducible:** YES (gaps exist)

**Vulnerable File:** `START.cmd`

**Root Cause:**
1. PID captured via PowerShell `Start-Process -PassThru` — correct
2. Kill uses `taskkill /f /pid %SERVER_PID%` — correct (not `/im python.exe`)
3. **No process verification:** Does not verify the PID still belongs to WireSploit before killing
4. **No PID file:** PID only in memory, not persisted
5. **No crash handling:** If server crashes, PID may be stale
6. **No repeated launch protection:** Multiple launches possible
7. **No ownership check:** Could kill unrelated process if PID recycled

**Security Impact:**
- Accidental termination of unrelated processes (PID reuse)
- Stale PID on crash could kill wrong process on restart
- Multiple instances could conflict

**Required Remediation:**
1. Write PID to file (`data/wiresploit.pid`) on startup
2. On startup, check if PID file exists and process is still running → refuse launch or cleanup
3. Before `taskkill`, verify process executable path matches expected Python/uvicorn
4. On clean shutdown, remove PID file
5. Add lock mechanism to prevent concurrent launches

**Required Regression Tests:**
- Start server → verify PID file created
- Start second instance → should detect existing and refuse/exit gracefully
- Kill server process externally → restart should handle stale PID
- Simulate PID reuse (hard to test) → verify ownership check

**Remaining Uncertainty:**
- How to reliably verify process ownership on Windows (WMI query? `tasklist`?)

---

### Finding 9: Evidence Integrity, Atomic Writes, Cleanup, Graceful Shutdown

**Reproducible:** YES (partial gaps)

**Vulnerable Functions:**
- `store.add_evidence()` in `engine/store.py:97-154`
- `store.verify_evidence_hash()` in `engine/store.py:157-181`
- `store.delete_old_investigations()` in `engine/store.py:205-236`
- `store.cleanup_orphaned_evidence_files()` in `engine/store.py:239-259`
- Lifespan handlers in `main.py:60-99`

**Root Cause:**
1. **Atomic write:** DB insert first, then file write, rollback on failure — CORRECT
2. **Hash verification:** SHA-256 computed on download, compared to stored — CORRECT
3. **Cleanup:** Old investigations deleted, evidence files removed, orphans cleaned — CORRECT
4. **Graceful shutdown:** Cleanup task cancelled, awaited — CORRECT
5. **Missing columns:** Evidence table lacks `filename`, `mime_type`, `file_path`
6. **Original metadata lost:** Upload filename and MIME type not stored
7. **No migration:** No migration to add missing columns to existing databases

**Security Impact:**
- Cannot verify original filename on download (filename in Content-Disposition is generated)
- Cannot validate MIME type (served as `application/octet-stream`)
- Existing databases cannot be upgraded without manual intervention

**Required Remediation:**
1. Add migration in `store.migrate_database()` to add `filename`, `mime_type`, `file_path` columns
2. Update `add_evidence()` to populate new columns
3. Update `get_evidence_file()` to use original filename and MIME type
4. Backfill existing records: infer filename from `url` column, set mime_type from extension
5. Add test for migration on existing database

**Required Regression Tests:**
- Fresh database → evidence table has all columns
- Existing database (pre-migration) → migration adds columns, preserves data
- Upload evidence → original filename and mime_type stored
- Download evidence → Content-Disposition uses original filename, Content-Type uses mime_type
- Hash verification still works after migration
- Cleanup still removes files correctly

**Remaining Uncertainty:**
- How to infer MIME type for existing records (extension-based fallback)
- Whether `file_path` should be stored or computed (computed preferred)

---

## Phase B — Finding 6: Sensitive GET Cross-Origin Protection

**Priority:** CRITICAL (per instructions)

**Current State:** All 13 sensitive GET endpoints HAVE `require_same_origin` protection. The issue is **missing regression tests**.

**Action Plan:**
1. Create `tests/test_cross_origin_get.py` with comprehensive tests
2. Test each endpoint with:
   - Valid same-origin request → 200
   - Foreign Origin header → 403
   - Missing Origin header → 200 (allowed, Referer not required for GET)
   - Malformed Origin header → 403 or 200 (implementation dependent)
   - Unauthenticated (no session) → 403 (if auth added later)
   - Cross-investigation access → 404 (not found) or 403

**Test Commands to Run:**
```bash
python -m pytest tests/test_cross_origin_get.py -v
```

---

## Phase C — Finding 1: Evidence Download Authorization and Path Traversal

**Priority:** HIGH

**Current State:** Protection exists but evidence table schema incomplete.

**Action Plan:**
1. Add migration for `filename`, `mime_type`, `file_path` columns
2. Update `add_evidence()`, `get_evidence_file()`, `verify_evidence_hash()`
3. Backfill existing data
4. Add tests

**Test Commands to Run:**
```bash
python -m pytest tests/test_evidence.py -v
python -m pytest tests/test_cross_origin_get.py::test_evidence_download_origin -v
```

---

## Phase D — Finding 4: Screenshot SSRF, Redirects and DNS Rebinding

**Priority:** HIGH

**Current State:** Good foundation but DNS rebinding TOCTOU gap.

**Action Plan:**
1. Implement DNS pinning via Playwright `--host-resolver-rules`
2. Add navigation timeout
3. Add response/screenshot size limits
4. Disable JavaScript for screenshots (or enhance redirect interception)
5. Add tests with mocked DNS

**Test Commands to Run:**
```bash
python -m pytest tests/test_screenshot.py -v
# Add new tests for DNS rebinding, size limits, timeouts
```

---

## Phase E — Finding 5: Scope Inheritance and Wildcard Authorization

**Priority:** MEDIUM

**Current State:** Core logic implemented, edge cases untested.

**Action Plan:**
1. Add IDN/Punycode normalization
2. Add hostname normalization (lowercase, strip trailing dot, NFC)
3. Add comprehensive tests
4. Update SECURITY.md

**Test Commands to Run:**
```bash
python -m pytest tests/test_additional_fixes.py::test_scope_* -v
# Add new tests for IDN, edge cases
```

---

## Phase F — Finding 8: Windows Launcher PID Tracking

**Priority:** MEDIUM

**Current State:** Basic PID tracking works, but no verification/persistence.

**Action Plan:**
1. Add PID file (`data/wiresploit.pid`)
2. Add process ownership verification before kill
3. Add startup check for existing instance
4. Add clean shutdown PID file removal
5. Test with isolated dummy processes

**Test Commands to Run:**
```bash
# Manual testing with dummy processes
# Automated test in test_launcher.py (new)
```

---

## Phase G — Finding 9: Evidence Integrity and Graceful Shutdown

**Priority:** HIGH

**Current State:** Core mechanisms work, schema incomplete.

**Action Plan:**
1. Combined with Finding 1 remediation (schema migration)
2. Verify atomic write rollback on simulated failure
3. Test hash verification on corrupted files
4. Test graceful shutdown with pending operations

**Test Commands to Run:**
```bash
python -m pytest tests/test_evidence.py tests/test_expiry.py -v
# Add migration test
```

---

## Phase H — Database Migration and Live Schema Reconciliation

**Current State:** Evidence table missing 3 columns. No migration exists for them.

**Investigation Results:**
```sql
-- Current evidence table:
CREATE TABLE evidence(
  id TEXT PRIMARY KEY,
  investigation_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  title TEXT NOT NULL,
  source TEXT,
  url TEXT,              -- stores generated filename (eid + ext)
  description TEXT,
  sha256 TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
);

-- Missing columns:
-- filename TEXT,        -- original upload filename
-- mime_type TEXT,       -- original MIME type
-- file_path TEXT        -- full path (can be computed)
```

**Migration Plan:**
1. Add `migrate_database()` logic to add columns if missing
2. Backfill: `filename` = `url` (generated name) for existing, `mime_type` = extension-based guess
3. For new uploads: store original filename and mime_type
4. Test on copy of live database

**Backup Procedure:**
```bash
cp data/wiresploit.sqlite3 data/wiresploit.sqlite3.backup.$(date +%Y%m%d)
```

**Recovery Procedure:**
```bash
cp data/wiresploit.sqlite3.backup.YYYYMMDD data/wiresploit.sqlite3
```

---

## Phase I — Finding 7: CLI and Subprocess Regression

**Status:** PASS — No remediation needed. Add regression tests if missing.

---

## Phase J — Findings 2 and 3: Preserve Existing Fixes

**Status:** PASS — No changes needed. Ensure tests remain.

---

## Phase K — Reproducible Security Verification

**Issue:** `verify_findings.py` exists but only checks function presence, not actual security properties.

**Required Enhancement:**
1. Make `verify_findings.py` run actual security tests (not just source inspection)
2. Test against running application (or TestClient)
3. Return proper exit codes (0 = all pass, 1 = critical fail)
4. Output machine-readable results (JSON)
5. Integrate with CI

**New Verification Script Requirements:**
- Run all security-relevant tests
- Check database schema
- Verify endpoint protections
- Produce PASS/PARTIAL/FAIL/NOT_VERIFIED per finding
- Exit code != 0 on critical failures

---

## Phase L — Final Independent Security Review

**Deliverables to Create:**
1. `SECURITY_REMEDIATION_REPORT.md` — This plan + actual results
2. `SECURITY_TEST_RESULTS.md` — Full test output with security test focus
3. `SECURITY_VERIFICATION_REPORT.md` — Enhanced verification script output
4. `SECURITY_REMAINING_WORK.md` — Unresolved issues and future work

---

## Implementation Sequence

### Milestone 1: Database Migration + Evidence Schema (Findings 1, 9)
- Add migration for evidence table columns
- Update store.py functions
- Backfill existing data
- Test migration on copy

### Milestone 2: Cross-Origin GET Tests (Finding 6)
- Create `tests/test_cross_origin_get.py`
- Test all 13 sensitive GET endpoints
- Verify 403 on foreign origin

### Milestone 3: Screenshot SSRF Hardening (Finding 4)
- Implement DNS pinning
- Add size limits and timeouts
- Disable JS or enhance redirect interception
- Add mocked DNS tests

### Milestone 4: Scope Authorization Hardening (Finding 5)
- Add IDN normalization
- Add comprehensive edge case tests
- Update SECURITY.md

### Milestone 5: Windows Launcher Hardening (Finding 8)
- Add PID file
- Add process ownership verification
- Add concurrent launch protection

### Milestone 6: Enhanced Verification System (Phase K)
- Rewrite `verify_findings.py` to run actual tests
- Add schema validation
- CI integration

### Milestone 7: Final Review and Documentation
- Run full test suite
- Generate all 4 deliverable documents
- Verify no regressions

---

## Test Commands Reference

```bash
# Full test suite
python -m pytest tests/ -v

# Security-specific tests
python -m pytest tests/test_additional_fixes.py -v
python -m pytest tests/test_screenshot.py -v
python -m pytest tests/test_evidence.py tests/test_expiry.py -v
python -m pytest tests/test_export.py -v
python -m pytest tests/test_cli_tooling.py -v
python -m pytest tests/test_cross_origin_get.py -v  # NEW

# Verification script
python verify_findings.py

# Migration test (manual)
python -c "
from engine import store
store.init()
# Check columns
import sqlite3
c = sqlite3.connect('data/wiresploit.sqlite3')
print([col[1] for col in c.execute('PRAGMA table_info(evidence)').fetchall()])
"
```

---

## Acceptance Criteria

- [ ] Evidence table has `filename`, `mime_type`, `file_path` columns
- [ ] Migration works on existing database
- [ ] All 13 sensitive GET endpoints tested for cross-origin protection
- [ ] Screenshot SSRF: DNS rebinding blocked, size limits enforced
- [ ] Scope authorization: IDN normalized, edge cases tested
- [ ] Windows launcher: PID file, ownership verification, no concurrent launches
- [ ] All existing tests still pass (81+)
- [ ] New security tests pass
- [ ] `verify_findings.py` runs actual tests, returns proper exit codes
- [ ] 4 deliverable documents created and accurate