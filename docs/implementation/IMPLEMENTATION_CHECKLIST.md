# WireSploit v4.0.1 — Security Remediation Implementation Checklist

**Source:** VERIFICATION_REPORT.md (9 verified findings)
**Baseline:** 73 tests passing
**Target:** All P0/P1 fixes implemented, full test suite passing

---

## Phase 0: Baseline (COMPLETED ✅)
- [x] Read VERIFICATION_REPORT.md
- [x] Read AUDIT_REPORT.md
- [x] Read PATCH_NOTES_V4.0.1.md
- [x] Run full test suite (73 passed)
- [x] Create this checklist

---

## Phase 1: Critical Security Fixes (P0/P1)

### Finding 1: Evidence Download — Path Traversal + No Auth (P0) ✅ COMPLETED
**Files:** `main.py` (GET /api/evidence/{eid}), `store.py` (get_evidence_filepath)
- [x] Add `Depends(require_same_origin)` to GET /api/evidence/{eid}
- [x] Add path traversal validation in `get_evidence_filepath`: `Path(url).resolve().relative_to(evidence_dir.resolve())`
- [x] Reject/sanitize `url` field in metadata-only evidence (disallow `..`, `/`, `\`)
- [x] **Tests:** Foreign origin rejected; `../` in `url` returns 404; uploaded evidence still works

### Finding 3: Screenshot SSRF — Redirect & DNS Gaps (P0) ✅ COMPLETED
**Files:** `main.py` (POST /api/screenshot), `engine/security.py` (reuse `_safe_get_public_host`)
- [x] Before `page.goto()`, resolve hostname and validate all IPs via `_is_public_addr`
- [x] Use Playwright's `page.route()` to intercept and validate redirects
- [x] Reuse `_safe_get_public_host` logic to pre-validate, then pass validated final URL to Playwright
- [x] **Tests:** Screenshot rejects redirect to private IP; rejects DNS rebinding; authorized public URL works

### Finding 2: Export HTML — XSS via Unescaped Interpolation (P1) ✅ COMPLETED
**Files:** `main.py` (GET /api/investigations/{iid}/export/html)
- [x] Use `html.escape()` on all interpolated values (inputs, findings, evidence, notes)
- [x] **Tests:** HTML export escapes `<script>`, `&`, `"`, `'`, `<`, `>`; benign data renders correctly

### Finding 2: Export CSV — Formula Injection (P1) ✅ COMPLETED
**Files:** `main.py` (GET /api/investigations/{iid}/export/csv)
- [x] Prefix cells starting with `=`, `+`, `-`, `@` with `\t` or `'` (OWASP recommendation)
- [x] **Tests:** CSV export prefixes formula-starting cells; benign data renders correctly

---

## Phase 2: Reliability & Integrity (P1/P2)

### Finding 7: Launcher PID Tracking — START.cmd Kills All python.exe (P1) ✅ COMPLETED
**Files:** `START.cmd`
- [x] Track PID of started server (like `START.ps1` does) - using PowerShell to capture PID
- [x] Use `taskkill /f /pid <PID>` instead of `/im python.exe`
- [x] **Tests:** Other Python processes survive launcher timeout

### Finding 8: Evidence Integrity — Hash Verification, Atomic Write, Cleanup (P2) ✅ COMPLETED
**Files:** `store.py` (add_evidence, get_evidence_filepath, delete_old_investigations), `main.py` (download, shutdown)
- [x] Verify SHA-256 on download: compare hash with stored hash
- [x] Reverse file/DB order: insert DB record first, then write file; on failure, delete file
- [x] In `delete_old_investigations`, also delete evidence files from disk (query before CASCADE)
- [x] Add shutdown event handler for graceful cleanup (lifespan)
- [x] Add periodic evidence directory scan for orphaned files
- [x] **Tests:** Corrupted file rejected; crash leaves no orphans; retention deletes files

### Finding 5: Cross-Origin Missing on Sensitive GETs (P2) ✅ COMPLETED
**Files:** `main.py` (add Depends to sensitive GETs)
- [x] Add `require_same_origin` to: exports, evidence download, investigation details, runs, history, scopes, diagnostics
- [x] **Tests:** Foreign origin returns 403 on all sensitive GETs; public endpoints (health, catalog) allow foreign Origin

---

## Phase 3: Hardening & Documentation (P3)

### Finding 4: Scope Subdomain Inheritance Undocumented (P3)
**Files:** `SECURITY.md`, `engine/security.py` (is_authorized)
- [ ] Document subdomain inheritance in `SECURITY.md` and API docs
- [ ] Consider adding explicit wildcard syntax (`*.example.com`) with opt-in
- [ ] Add UI indication in Tool Manager when subdomains are implicitly covered
- [ ] **Tests:** Exact domain match works; subdomain match works; non-subdomain rejected; wildcard if implemented

### Finding 6: CLI Defense in Depth (P3)
**Files:** `engine/tooling.py` (tool_command, run_subprocess)
- [ ] Use explicit argument lists instead of `split()`: `["tool", target]`
- [ ] Add `--` separator before user input where tools support it
- [ ] **Tests:** No regression in tool execution; validated inputs safe; never uses shell=True

### Finding 8 (cont.): Shutdown Handler (P3) ✅ COMPLETED (done in Finding 8)
**Files:** `main.py` (startup/shutdown lifespan)
- [x] Add lifespan shutdown handler for graceful cleanup
- [x] **Tests:** Cleanup loop stops cleanly on shutdown

---

## Phase 4: Test Coverage Expansion (Ongoing)
- [ ] Add regression tests for all above fixes to existing test files
- [ ] Add `tests/test_security_fixes.py` for new integration tests
- [ ] Add property-based tests for validation boundaries
- [ ] Run full test suite after each fix

---

## Deliverables (to create at end)
- [ ] `IMPLEMENTATION_REPORT.md` — What was fixed, code locations, test evidence
- [ ] `TEST_RESULTS.md` — Full pytest output with pass/fail per test file
- [ ] `REMAINING_WORK.md` — Unaddressed findings, known limitations, future work
- [ ] `INDEPENDENT_AUDIT_HANDOVER.md` — Checklist for third-party review

---

## Progress Tracking

| Phase | Task | Status | Tests Added |
|-------|------|--------|-------------|
| 1.1 | Evidence Download Auth + Path Validation | ⬜ Pending | - |
| 1.2 | Screenshot SSRF Redirect/DNS Validation | ⬜ Pending | - |
| 1.3 | Export HTML Escaping | ⬜ Pending | - |
| 1.4 | Export CSV Formula Protection | ⬜ Pending | - |
| 2.1 | Launcher PID Tracking (START.cmd) | ⬜ Pending | - |
| 2.2 | Evidence Integrity (Hash/Atomic/Cleanup) | ⬜ Pending | - |
| 2.3 | Sensitive GET Origin Checks | ⬜ Pending | - |
| 3.1 | Scope Documentation | ⬜ Pending | - |
| 3.2 | CLI Defense in Depth | ⬜ Pending | - |
| 3.3 | Shutdown Handler | ⬜ Pending | - |

---

## Notes
- Run `pytest tests/ -v` after EACH fix to ensure no regressions
- All fixes are additive — no schema migrations needed
- No feature flags required — safety-only changes
- Update `CHANGELOG.md` after each phase
- Document scope subdomain behavior in `SECURITY.md` immediately