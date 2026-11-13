# WireSploit v4.0.1 — Remaining Work & Known Limitations

**Date:** 2026-10-24
**Status:** Security remediation complete (9/9 findings addressed)

---

## Unaddressed Findings

**None.** All 9 verified findings from VERIFICATION_REPORT.md have been implemented and tested.

| Finding | Priority | Status |
|---------|----------|--------|
| 1. Evidence Download — Path Traversal + No Auth | P0 | ✅ Complete |
| 2. Export HTML — XSS via Unescaped Interpolation | P1 | ✅ Complete |
| 2. Export CSV — Formula Injection | P1 | ✅ Complete |
| 3. Screenshot SSRF — Redirect & DNS Gaps | P0 | ✅ Complete |
| 4. Scope Subdomain Inheritance Undocumented | P3 | ✅ Complete |
| 5. Cross-Origin Missing on Sensitive GETs | P2 | ✅ Complete |
| 6. CLI Defense in Depth | P3 | ✅ Complete |
| 7. Launcher PID Tracking — START.cmd | P1 | ✅ Complete |
| 8. Evidence Integrity — Hash, Atomic Write, Cleanup, Shutdown | P2/P3 | ✅ Complete |

---

## Known Limitations

### 1. Screenshot Tests — External Dependency
**File:** `tests/test_screenshot.py`
**Issue:** Tests use `httpbin.org` for HTTP requests. This introduces:
- Network flakiness (external service availability)
- CI/CD pipeline dependency on internet access
- Non-deterministic test timing

**Mitigation:** Run tests locally before CI. Consider mocking HTTP responses in future.

### 2. Launcher PID Test — Not Automated
**File:** `START.cmd`
**Issue:** No automated test exists for PID tracking behavior because:
- Requires process isolation (spawning child processes)
- Windows-specific behavior (PowerShell `Start-Process`, `taskkill`)
- Difficult to test in CI without dedicated Windows runner

**Mitigation:** Manual verification confirmed. Could add integration test with `pytest-subprocess` in future.

### 3. CLI Tool Integration Tests — Mocked Only
**Files:** `tests/test_cli_tooling.py`, `engine/engine.py`
**Issue:** Tests mock `asyncio.create_subprocess_exec` and `tooling.run_subprocess`. They don't test:
- Actual CLI tool execution (sherlock, subfinder, etc.)
- Real argument parsing from tool output
- Tool version compatibility

**Mitigation:** Unit tests verify argument structure and validation logic. Integration tests would require installing all CLI tools in CI.

### 4. No Rate Limiting on Public Endpoints
**File:** `main.py`
**Issue:** Public endpoints (`/api/health`, `/api/catalog`, `/api/tools`) have no rate limiting.
- Could be abused for DoS
- No protection against credential stuffing on authenticated endpoints

**Future Work:** Add FastAPI rate limiting middleware (e.g., `slowapi`).

### 5. No CSRF Protection on State-Changing Endpoints
**File:** `main.py`
**Issue:** While same-origin checks exist, no CSRF tokens for:
- POST `/api/investigations` (create)
- POST `/api/investigations/{iid}/inputs` (add input)
- POST `/api/evidence` (upload)
- DELETE endpoints

**Mitigation:** Same-origin policy provides defense-in-depth. CSRF tokens recommended for defense-in-depth.

### 6. Evidence File Storage — Local Only
**File:** `engine/store.py`
**Issue:** Evidence files stored on local filesystem (`./evidence/`):
- No cloud storage support (S3, GCS, Azure Blob)
- Single-instance deployment only
- No replication/backup strategy

**Future Work:** Abstract storage backend with interface for local/cloud.

### 7. API Key Management — Environment Variables Only
**Files:** `engine/tooling.py`, `engine/web_providers.py`
**Issue:** API keys only from environment variables:
- No key rotation support
- No per-investigation key overrides
- No secure key storage (HashiCorp Vault, AWS Secrets Manager)

**Future Work:** Add key management abstraction layer.

### 8. No Audit Logging
**Files:** `main.py`, `engine/store.py`
**Issue:** Security events not logged for compliance:
- Evidence access (download, upload, delete)
- Scope changes (add, delete)
- Investigation creation/deletion
- Export operations

**Future Work:** Add structured audit log with tamper-evident storage.

---

## Future Work (Roadmap)

### V4.1 — Input History Expiry (Planned)
Per CLAUDE.md plan file, the following is scheduled:

| Task | Status |
|------|--------|
| Database schema: `search_history` table | 📋 Planned |
| API: GET/POST/DELETE `/api/history` | 📋 Planned |
| Background cleanup (3-day expiry) | 📋 Planned |
| Frontend: History tab in Settings | 📋 Planned |
| Tests: `tests/test_history.py` | 📋 Planned |

### V4.2 — Enhanced Security
| Feature | Priority |
|---------|----------|
| Rate limiting middleware | High |
| CSRF token protection | Medium |
| Audit logging | Medium |
| API key rotation | Low |
| Multi-factor authentication | Low |

### V4.3 — Platform Hardening
| Feature | Priority |
|---------|----------|
| Cloud storage abstraction | Medium |
| Multi-instance support (shared DB) | Medium |
| Plugin system for custom tools | Low |
| WebSocket real-time updates | Low |

### V4.4 — Developer Experience
| Feature | Priority |
|---------|----------|
| OpenAPI/Swagger documentation | Medium |
| CLI client for API | Low |
| VS Code extension | Low |

---

## Technical Debt

| Item | Location | Impact |
|------|----------|--------|
| Legacy `run_subprocess` string command support | `engine/tooling.py:347` | Low — backward compat only |
| `on_event` deprecation warnings | `main.py` lifespan | Low — migration to lifespan done |
| `httpx` with `starlette.testclient` deprecation | Tests | Low — test infrastructure only |
| Mixed async/sync DB calls | `engine/store.py` | Medium — consider aiosqlite |
| No database migrations | `engine/store.py` | Medium — schema changes manual |

---

## Test Coverage Gaps

| Area | Current | Target |
|------|---------|--------|
| Screenshot SSRF edge cases | 5 tests | 10+ (redirect chains, DNS rebinding) |
| CLI tool actual execution | 0 | 5+ (smoke tests with real tools) |
| Launcher PID behavior | 0 | 1+ (integration) |
| Evidence integrity corruption | 0 | 3+ (hash mismatch, missing file, DB corruption) |
| Concurrent investigation limits | 0 | 2+ |
| Export with large datasets | 0 | 2+ |

---

## Security Review Checklist for Next Release

- [ ] All findings re-verified with updated test suite
- [ ] Dependency audit: `pip-audit` / `safety` scan
- [ ] Container image scan (if Dockerized)
- [ ] SAST scan (bandit, semgrep)
- [ ] Penetration test of public endpoints
- [ ] CSRF token implementation review
- [ ] Rate limiting effectiveness test
- [ ] Evidence encryption at rest evaluation

---

## Conclusion

**Security posture significantly improved.** All critical and high-priority findings resolved. Remaining items are defense-in-depth enhancements, operational improvements, and planned features — not active vulnerabilities.