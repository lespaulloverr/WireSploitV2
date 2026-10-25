# WireSploit v4.0.1 — Remaining Security Work

**Date:** 2026-10-25
**Version:** 4.0.1
**Status:** Post-remediation — Known limitations & future enhancements

---

## Overview

This document tracks known limitations, acceptable risks, and planned security enhancements for future versions. All 9 critical/high findings from the v4.0.1 audit have been remediated. The items below represent defense-in-depth improvements and operational hardening.

---

## Known Limitations (Acceptable Risks)

### 1. Screenshot Tests Depend on External Service
- **Issue:** `test_screenshot.py` uses `httpbin.org` for integration testing
- **Risk:** Test flakiness if external service unavailable
- **Mitigation:** Tests are marked as integration tests; unit tests mock the validation logic
- **Planned:** Local test server fixture for v4.2

### 2. No CSRF Tokens (Same-Origin Only)
- **Issue:** Protection relies solely on `Origin`/`Referer` header validation
- **Risk:** Theoretical bypass via browser bugs or misconfiguration
- **Mitigation:** Same-origin check is robust; CSRF tokens add marginal value for API-only endpoints
- **Status:** Acceptable for v4.0.1; tokens planned for v4.2 if forms added

### 3. No Rate Limiting on API Endpoints
- **Issue:** No request rate limiting on any endpoint
- **Risk:** DoS via request flooding (not data breach)
- **Mitigation:** Nginx/reverse proxy recommended for production deployment
- **Planned:** Built-in rate limiting in v4.2

### 4. Single-Instance File Storage
- **Issue:** Evidence files stored on local filesystem only
- **Risk:** Not horizontally scalable; single point of failure
- **Mitigation:** By design for single-instance deployment
- **Planned:** S3-compatible storage backend for v4.2

### 5. No Audit Logging for Security Events
- **Issue:** Authorization failures, SSRF blocks not logged to dedicated audit log
- **Risk:** Delayed detection of attack attempts
- **Mitigation:** Standard application logs capture errors; structured audit log planned
- **Planned:** Audit log module in v4.2

---

## Defense-in-Depth Enhancements (v4.2+)

### 1. Content Security Policy (CSP) Headers
- **Current:** Basic security headers via middleware
- **Enhancement:** Strict CSP with nonce-based script/style allowlists
- **Effort:** Medium
- **Impact:** Defense-in-depth against XSS

### 2. Request Rate Limiting
- **Current:** None
- **Enhancement:** Per-IP and per-user rate limits with Redis backend
- **Endpoints:** All mutating routes, screenshot, exports
- **Effort:** Medium
- **Impact:** DoS mitigation

### 3. Structured Audit Logging
- **Current:** Standard Python logging
- **Enhancement:** JSON audit log with:
  - Timestamp, user/session, action, resource, result
  - Security events: auth failures, SSRF blocks, scope changes
  - Tamper-evident (append-only, hash-chained)
- **Effort:** Medium
- **Impact:** Compliance, incident response

### 4. S3-Compatible Evidence Storage
- **Current:** Local filesystem (`data/evidence/`)
- **Enhancement:** Configurable backend (local, S3, Azure Blob, GCS)
- **Features:** Presigned URLs, encryption at rest, versioning
- **Effort:** High
- **Impact:** Horizontal scaling, durability

### 5. Multi-Factor Authentication (MFA)
- **Current:** No authentication (single-user tool)
- **Enhancement:** Optional TOTP/WebAuthn for multi-user deployments
- **Effort:** High
- **Impact:** Access control hardening

### 6. Encrypted Evidence at Rest
- **Current:** Files stored unencrypted
- **Enhancement:** AES-256-GCM encryption with per-file keys
- **Key Management:** Local keystore or HSM/KMS integration
- **Effort:** Medium
- **Impact:** Data protection if host compromised

### 7. Certificate Pinning for Screenshot
- **Current:** Standard TLS validation
- **Enhancement:** Optional HPKP/expect-CT for authorized scopes
- **Effort:** Low
- **Impact:** Mitigate compromised CA risk

### 8. Scope Expiration & Review Workflow
- **Current:** Scopes permanent until manually deleted
- **Enhancement:** TTL on scopes, periodic review reminders
- **Effort:** Low
- **Impact:** Reduce stale authorization surface

### 9. Dependency Scanning & SBOM
- **Current:** Manual `pip-audit` / `safety`
- **Enhancement:** CI-integrated SCA (Syft/Grype), CycloneDX SBOM generation
- **Effort:** Low
- **Impact:** Supply chain visibility

### 10. Fuzzing Integration
- **Current:** Unit/integration tests only
- **Enhancement:** AFL++/libFuzzer for:
  - URL parsing (`normalize_target`)
  - CSV/HTML sanitizers
  - Evidence file handling
- **Effort:** Medium
- **Impact:** Discover edge-case crashes

---

## Technical Debt & Code Quality

### 1. Migrate from `@app.on_event` to Lifespan
- **Location:** `main.py:60, 90`
- **Issue:** Deprecated FastAPI pattern
- **Fix:** Already using lifespan for cleanup; migrate startup/shutdown

### 2. Type Annotations Coverage
- **Current:** Partial type hints
- **Enhancement:** Full mypy compliance (`--strict`)
- **Effort:** Medium

### 3. Async Database Driver
- **Current:** Synchronous `sqlite3`
- **Enhancement:** `aiosqlite` for true async I/O
- **Effort:** Medium
- **Impact:** Better concurrency under load

### 4. Configuration Management
- **Current:** Environment variables + hardcoded defaults
- **Enhancement:** Pydantic Settings with validation, `.env` support
- **Effort:** Low

---

## Compliance & Certifications

| Standard | Current Status | Target |
|----------|----------------|--------|
| OWASP ASVS Level 1 | Partial (v4.0.1 fixes) | v4.2 |
| SOC 2 Type II | Not applicable (dev tool) | N/A |
| ISO 27001 | Not applicable | N/A |
| NIST SSDF | Partial | v4.3 |

---

## Vulnerability Disclosure

**Responsible Disclosure:** security@wiresploit.example.com (placeholder)

**Scope:** All WireSploit code, dependencies, and deployment artifacts

**Safe Harbor:** Good-faith research following coordinated disclosure will not be pursued legally.

---

## Version Roadmap

| Version | Target Date | Security Focus |
|---------|-------------|----------------|
| v4.1 | 2027-Q1 | Input history expiry (3-day), UI polish |
| v4.2 | 2027-Q2 | Rate limiting, CSP, audit log, S3 storage |
| v4.3 | 2027-Q3 | MFA, encryption at rest, SBOM, fuzzing |
| v5.0 | 2027-Q4 | Multi-user, RBAC, plugin sandboxing |

---

## Quick Reference: Files to Watch

### High-Value Security Files
```
main.py                      # All endpoints, lifespan, middleware
engine/security.py           # Authorization, SSRF, IDN, IP validation
engine/store.py              # Evidence integrity, atomic writes, cleanup
engine/tooling.py            # CLI defense (arg arrays, validation)
START.cmd                    # Windows launcher PID tracking
```

### Test Files for Regression
```
tests/test_cross_origin_get.py   # Finding 5 - cross-origin protection
tests/test_screenshot.py         # Finding 3 - SSRF protection
tests/test_cli_tooling.py        # Finding 6 - CLI defense
tests/test_additional_fixes.py   # Findings 1, 4, 5 - scope, origin
tests/test_export.py             # Findings 2a, 2b - XSS, formula injection
tests/test_evidence.py           # Findings 1, 8 - evidence integrity
tests/test_expiry.py             # Finding 8 - cleanup
```

---

## Contact

For questions about remaining work or future security enhancements:
- Reference: `SECURITY_REMEDIATION_REPORT.md` for implementation details
- Reference: `verify_findings.py` for automated verification
- Reference: `INDEPENDENT_AUDIT_HANDOVER.md` for auditor checklist