# WireSploit v4.0.1 — Kali Linux Integration Project Audit

**Date:** 2026-10-25  
**Version:** 4.0.1  
**Purpose:** Complete architectural audit of existing WireSploit codebase prior to Kali Linux tool integration

---

## Executive Summary

WireSploit v4.0.1 is a **local-first OSINT investigation workspace** built as a FastAPI web application with a single-page JavaScript frontend. It provides a unified interface for public-source intelligence gathering, evidence management, and report generation. The system is designed for single-instance deployment on 8 GB Windows laptops with no required cloud dependencies.

This audit documents the complete architecture to inform the Kali Linux integration project (Phase 2+).

---

## 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        WireSploit v4.0.1                        │
├─────────────────────────────────────────────────────────────────┤
│  Frontend (web/)                                                │
│  ├── index.html          — SPA entry point                      │
│  ├── app.js              — 4000+ lines, all UI logic            │
│  └── styles.css          — Dark theme, responsive CSS           │
├─────────────────────────────────────────────────────────────────┤
│  Backend (main.py + engine/)                                    │
│  ├── main.py             — FastAPI app, 900+ lines              │
│  │   ├── 25+ REST endpoints                                    │
│  │   ├── Lifespan handlers (startup/shutdown)                  │
│  │   ├── Same-origin protection middleware                     │
│  │   ├── Export endpoints (JSON/CSV/HTML/PDF)                 │
│  │   ├── Screenshot capture with SSRF hardening                │
│  │   └── Evidence upload/download with hash verification       │
│  ├── engine/store.py       — SQLite persistence layer           │
│  ├── engine/security.py    — Scope auth, SSRF, IDN, IP checks  │
│  ├── engine/tooling.py     — CLI tool registry & execution     │
│  ├── engine/engine.py      — Investigation orchestration        │
│  ├── engine/native.py      — Built-in OSINT providers          │
│  ├── engine/web_providers.py — 30+ web API providers           │
│  ├── engine/catalog.py     — 130+ curated web resources        │
│  ├── engine/awesome_catalog.py — Awesome OSINT derived catalog │
│  └── validation.py         — Input classification & validation │
├─────────────────────────────────────────────────────────────────┤
│  Infrastructure                                               │
│  ├── START.cmd             — Windows launcher with PID tracking │
│  ├── requirements.txt      — Python dependencies                │
│  ├── data/                 — SQLite DB + evidence files        │
│  └── tests/                — 88 passing tests                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Core Components Deep Dive

### 2.1 Tool Registry & Integrations

#### `engine/catalog.py` — Curated Web Resources (130+ entries)
- **Purpose**: Launchpad for external OSINT web services (not automated)
- **Structure**: List of dicts with `id`, `name`, `category`, `url`, `description`, `query_template`
- **Categories**: username, social, domain, ip, archives, geolocation, images, public_records, search, security
- **Integration**: Exposed via `GET /api/catalog` endpoint, merged with Awesome OSINT catalog
- **Key trait**: "External resource" flag — WireSploit never claims their results as automated findings

#### `engine/awesome_catalog.py` — Awesome OSINT Derived (130 entries)
- **Purpose**: Structured catalog from public Awesome OSINT list
- **Structure**: Tuples of `(name, category, url, description)` → converted to dicts
- **Source**: Community-maintained Awesome OSINT list
- **Categories**: General Search, National Search, Meta/Privacy Search, Breach Awareness, Threat Intelligence, Network Intelligence, Public Records, Documents, Knowledge Graph, Image Search, Geolocation, Web Archives, Domain/DNS, Code Search, Developer Intelligence, Social/Forums, Identity, Username, Email, Phone, Domain/Recon, Recon Framework, Documents/Metadata, Web Crawler, Threat Intelligence, OSINT Resources, Fact Checking, News, Companies, Maritime, etc.
- **Integration**: `as_catalog()` function returns list of dicts with `source: "awesome-osint"`, `integration: "external"`

#### `engine/tooling.py` — CLI Tool Registry (23 tools)
- **Purpose**: Registry of locally-installed CLI tools that WireSploit can execute
- **Tool Specs**: `Spec` class with `id`, `name`, `kind`, `categories`, `automated`, `authorized_only`, `deep_only`, `url`
- **Tool Kinds**: `native` (built-in), `web` (API providers), `cli` (external executables)
- **CLI Tools Registered** (11 with `--` separator):
  - Username: sherlock, maigret, gosherlock, socialanalyzer, blackbird
  - Domain: subfinder, assetfinder, amass, theharvester, waymore, gau, waybackurls, findomain
- **Security**: `_validate_target()` rejects shell metacharacters (`; & | ` $ ( ) { } < > \n \r \t`)
- **Execution**: `run_subprocess()` uses `asyncio.create_subprocess_exec()` with explicit arg arrays
- **Diagnostics**: `diagnose(tid)` checks PATH for CLI tools, env vars for API keys

#### `engine/native.py` — Built-in Providers (13 providers)
- **Purpose**: Pure-Python OSINT providers with no external dependencies (except phonenumbers)
- **Providers**:
  - `username_lookup` — 19 sites (GitHub, Reddit, X, TikTok, etc.) via HTTP HEAD/GET
  - `email_lookup` — DNS MX, Gravatar, public search links
  - `phone_lookup` — phonenumbers lib for carrier/region metadata
  - `ip_lookup` — ipwho.is, reverse DNS, ASN
  - `domain_lookup` — DNS records, RDAP, crt.sh certificates, TLS cert inspection
  - `geolocation_lookup` — Nominatim (OSM) forward/reverse geocoding
  - `archive_lookup` — Wayback Machine CDX API
  - `technical_lookup` — Passive + authorized active HTTP checks
  - `public_records_lookup` — UK Companies House, OpenCorporates, SEC EDGAR, Gazette, Wikidata
  - `search_links` — Search query builder (Google, Bing, DuckDuckGo)
  - `analyze_file` — Local file metadata (PDF, Office, images with EXIF/OCR)
- **Security**: All HTTP via `_safe_get_public_host()` with redirect validation + IP allowlist

#### `engine/web_providers.py` — Web API Providers (30+ providers)
- **Purpose**: Passive API-based OSINT providers (require API keys for some)
- **Categories**: Username (GitHub, GitLab, Reddit, HackerNews, Bluesky), Email (Gravatar), Domain (RDAP, crt.sh, Google DoH, Cloudflare DoH, Wayback, Common Crawl), IP (Shodan InternetDB, IPWhois, RIPEstat, IPQuery, CertSpotter, urlscan.io, VirusTotal, AbuseIPDB, GreyNoise), CVE (NVD, CISA KEV), Extended (WhatsMyName, Open-Meteo, Overpass, Wikipedia Geo, Wikidata, OpenAlex)
- **Security**: All use `_public_ip()` validation (rejects private IPs), bounded concurrency, cached datasets

### 2.2 Backend Execution Architecture

#### `engine/engine.py` — Investigation Orchestrator
- **Entry Points**: 
  - `launch(rid, iid)` — Spawns background thread running `run()`
  - `run(rid, iid)` — Main investigation loop (8 stages max)
- **Flow**:
  1. Load investigation, requeue user inputs as identifiers (stage 0)
  2. For each stage (0-7): select queued identifiers
  3. For each identifier: determine applicable categories via `cats(kind, srm)`
  4. Select providers: `native` + automated specs matching category + auth/deep flags
  5. Execute providers via `provider(pid, cat, target, srm)` with 95s timeout
  6. Store findings via `store.add_finding()`, discover new identifiers via `discover()`
  7. Job cap: 200 jobs max per investigation
- **Provider Dispatch**:
  - `native` → `engine/native.py` functions
  - `web` specs → `tooling.web_providers.run()`
  - `cli` specs → `tooling.tool_command()` → `tooling.run_subprocess()`
- **Output Parsers**: `parse_username_output()`, `parse_domain_lines()`, `parse_kv_output()`

#### `engine/tooling.py` — CLI Execution Layer
- **`tool_command(pid, target, cat)`** → Returns `[args_list, working_dir]` or `None`
  - Returns explicit argument arrays (NOT strings) to prevent shell injection
  - 11 tools use `--` separator before target argument
  - Validates target via `_validate_target()` first
- **`run_subprocess(cw, wd, timeout, stdin_text)`** — Safe subprocess execution
  - Accepts both legacy string commands and new argument lists
  - Uses `asyncio.create_subprocess_exec(*args)` — no shell=True
  - Timeout handling with process kill
  - Returns `(exit_code, stdout, stderr)`

### 2.3 Investigation & Evidence Systems

#### `engine/store.py` — SQLite Persistence Layer
- **Database**: SQLite with WAL mode, foreign keys enabled (`data/wiresploit.sqlite3`)
- **Tables**:
  - `investigations` — id, name, status, created_at, updated_at, srm_authorized, permanent
  - `inputs` — id, investigation_id, kind, value, normalized, source, created_at
  - `runs` — id, investigation_id, status, stage, total_stages, current, started_at, finished_at, error
  - `jobs` — id, run_id, category, target, provider, status, message, started_at, finished_at
  - `findings` — id, run_id, category, provider, entity_key, value, url, confidence, exact_match, evidence_json, created_at (UNIQUE on run_id, entity_key, provider)
  - `identifiers` — id, investigation_id, kind, value, normalized, status, stage (UNIQUE on investigation_id, kind, normalized)
  - `events` — id (auto), run_id, level, message, meta_json, created_at
  - `evidence` — id, investigation_id, kind, title, source, url, description, sha256, created_at, **filename, mime_type, file_path** (NEW v4.0.1)
  - `investigation_notes` — id, investigation_id, note, created_at
  - `search_history` — id, query, kind, created_at (NEW v4.0.1)
- **Key Functions**:
  - `add_evidence()` — **Atomic write**: DB insert FIRST, then file write with rollback on failure
  - `verify_evidence_hash(eid)` — SHA-256 verification on every download
  - `get_evidence_filepath(eid)` — Path traversal prevention via `resolve().relative_to(evidence_dir)`
  - `delete_old_investigations(days=3)` — Cascade delete + evidence file cleanup
  - `cleanup_orphaned_evidence_files()` — Scan evidence dir for files not in DB
  - `cleanup_search_history(days=3)` — 3-day TTL for search history
  - `migrate_database()` — Additive schema migration with backfill

#### Evidence Integrity (v4.0.1 Hardening)
- **Atomic Write Pattern**: DB record created before file write; rollback on failure
- **SHA-256 Verification**: Every download validates hash against DB record
- **Path Traversal Prevention**: `Path.resolve().relative_to(evidence_dir)` on all file operations
- **Orphan Cleanup**: 24-hour background task removes unreferenced files
- **Graceful Shutdown**: Lifespan handler cancels and awaits cleanup task

### 2.4 Results Interpretation Architecture

#### Finding Data Model (Unified Across All Providers)
```python
{
    'entity_key': 'domain:subfinder:sub.example.com',  # Unique deduplication key
    'platform': 'Subfinder',                            # Provider display name
    'value': 'sub.example.com',                         # Primary finding value
    'url': 'https://sub.example.com',                   # Optional reference URL
    'source_tools': ['subfinder'],                      # Provenance chain
    'evidence': {
        'exact_match': True,
        'source': 'Output from subfinder',
        'raw_output_snippet': 'sub.example.com'
    }
}
```

#### Deduplication Strategy
- **Entity Key Format**: `{type}:{provider}:{normalized_value}`
- **UNIQUE Constraint**: Database enforces `(run_id, entity_key, provider)` uniqueness
- **Cross-Provider Correlation**: `discover()` function extracts emails, usernames, domains, CVEs from findings to seed next stage

#### Confidence Scoring
- Default: 0.5 (50%)
- Exact match flag: `exact_match: true` for direct tool output
- Provider-specific evidence includes HTTP status, final URL, page titles, metadata

### 2.5 Authentication / Permissions

#### Scope Authorization (`engine/security.py`)
- **Storage**: `data/authorized_scopes.json` (JSON array)
- **Scope Types**: `domain`, `url`, `ip`, `cidr`
- **Subdomain Inheritance**: Domain scopes authorize all subdomains (`example.com` → `www.example.com`, `api.example.com`)
- **Wildcard Syntax**: `*.example.com` normalized to `example.com` with `wildcard: true` flag
- **URL Scopes**: Exact host match only
- **CIDR Scopes**: IP network containment via `ipaddress.ip_network()`
- **IDN Normalization**: `_normalize_idn()` converts Unicode to Punycode (`bücher.de` → `xn--bcher-kva.de`) to prevent homograph attacks
- **Authorization Check**: `is_authorized(value)` called before ALL active operations

#### Protected Endpoints (Require Scope Authorization)
- `POST /api/security/snapshot` — Web security assessment
- `POST /api/security/probe` — Limited port probe (16 common ports)
- `POST /api/screenshot` — Browser screenshot capture

#### Same-Origin Protection (`main.py:require_same_origin`)
- **13 Sensitive GET Endpoints** protected:
  - `/api/investigations`, `/api/investigations/{iid}`, `/api/runs/{rid}`
  - `/api/investigations/{iid}/export/*` (html, csv, json, pdf)
  - `/api/investigations/{iid}/graph`, `/api/investigations/{iid}/notes`
  - `/api/evidence/{eid}`, `/api/scopes`, `/api/history`, `/api/diagnostics`
- **Public Endpoints** (intentionally unprotected): `/api/health`, `/api/catalog`, `/api/tools`
- **Validation**: Checks `Origin` header first, falls back to `Referer` header

### 2.6 Export Functionality

#### Four Export Formats (`main.py` lines 1145-1350)
1. **JSON** — Complete investigation dump (inputs, runs, findings, evidence, notes)
2. **CSV** — Findings + notes with **OWASP formula injection prevention** (`_csv_sanitize()` tab-prefixes `= + - @`)
3. **HTML** — Full report with **HTML escaping** (`_h()` uses `html.escape()`)
4. **PDF** — ReportLab generated document

#### Security Features
- All export endpoints protected by `require_same_origin`
- CSV: Every cell sanitized via `_csv_sanitize()`
- HTML: Every interpolated value escaped via `_h()`

### 2.7 Database Schema & Migrations

#### Schema Version: Implicit (migrate_database() is additive)
- **Migrations Applied** (v4.0.1):
  - `investigations.permanent` column (default 0)
  - `evidence.filename`, `evidence.mime_type`, `evidence.file_path` columns
  - Backfill: `filename` from `url`, `mime_type` from extension
  - `search_history` table with `created_at` index

#### Key Indexes
- `idx_findings_run` on `findings(run_id)`
- `idx_events_run` on `events(run_id)`
- `idx_search_history_created` on `search_history(created_at)`

### 2.8 Frontend Navigation / UI

#### `web/app.js` — Single-Page Application (4000+ lines)
- **State Management**: Global `state = { view, iid, timer }`
- **Views**: dashboard, new, investigations, tools, evidence, diagnostics, settings
- **Investigation View**: Tabs for findings, activity, evidence, notes
- **Tool Manager**: Three tabs — Integrations (23 tools), Resources (260+ web resources), Scopes
- **Evidence UI**: Upload modal, screenshot capture modal, thumbnail preview for images
- **Settings**: Resources policy, Privacy, History (3-day expiry UI)
- **Security**: `esc()` function for HTML escaping in frontend

#### Key UI Features
- Real-time run progress polling (stage, percentage, job list)
- Scope management with wildcard badge (`🌐 Subdomains covered`)
- Search history with delete/clear all
- Notes CRUD with character counter
- Permanent investigation toggle

### 2.9 Existing Tests & Documentation

#### Test Suite (88 tests passing)
| File | Tests | Coverage |
|------|-------|----------|
| `test_additional_fixes.py` | 13 | Findings 1, 4, 5 + IDN |
| `test_api_contracts.py` | 9 | Core API contracts |
| `test_cli_tooling.py` | 10 | Finding 6 (CLI defense) |
| `test_core.py` | 3 | Health, catalog, tools |
| `test_cross_origin_get.py` | 5 | Finding 5 (13 GET endpoints) |
| `test_evidence.py` | 1 | Findings 1, 8 (evidence integrity) |
| `test_expiry.py` | 1 | Finding 8 (cleanup) |
| `test_export.py` | 5 | Findings 2a, 2b, 5 |
| `test_history.py` | 8 | Search history CRUD + expiry |
| `test_notes.py` | 1 | Notes CRUD |
| `test_osint_expansion.py` | 17 | OSINT providers + scope auth |
| `test_screenshot.py` | 5 | Finding 3 (SSRF) |
| `test_validation.py` | 7 | Input validation |

#### Documentation Files
- `SECURITY_REMEDIATION_REPORT.md` — Detailed fix documentation for 9 findings
- `SECURITY_VERIFICATION_REPORT.md` — Auditor verification checklist
- `SECURITY_TEST_RESULTS.md` — Full pytest output
- `SECURITY_REMAINING_WORK.md` — Known limitations & v4.2+ roadmap
- `SECURITY.md` — Scope authorization design doc
- `INDEPENDENT_AUDIT_HANDOVER.md` — Auditor quick reference
- `verify_findings.py` — 50+ runtime verification checks

---

## 3. Security Architecture Summary

### Defense-in-Depth Layers Implemented

| Finding | Layer 1 | Layer 2 | Layer 3 | Layer 4 |
|---------|---------|---------|---------|---------|
| 1. Evidence Download | Same-origin | Path traversal validation | Hash verification | Atomic write |
| 2a. Export HTML XSS | Same-origin | `html.escape()` all values | CSP (browser) | — |
| 2b. Export CSV Formula | Same-origin | OWASP tab-prefixing | — | — |
| 3. Screenshot SSRF | Auth check | DNS resolution + IP validation | Redirect validation | DNS pinning + browser limits |
| 4. Scope/IDN | Explicit wildcard | Subdomain inheritance logic | IDN normalization | Docs + UI badge |
| 5. Cross-Origin GETs | 13 endpoints protected | Origin header check | Referer header check | Case-insensitive |
| 6. CLI Defense | Arg arrays (no shell) | `--` separator | Target validation | Safe subprocess exec |
| 7. Launcher PID | PowerShell Start-Process | taskkill /pid | PID file persistence | Ownership verification |
| 8. Evidence Integrity | Atomic DB-first write | Hash verify on download | 24hr orphan cleanup | Graceful shutdown |

### Security Boundaries
1. **Network**: All outbound HTTP validates IPs against `_is_public_addr()` (blocks private, loopback, link-local, reserved, multicast, unspecified)
2. **Filesystem**: Evidence files confined to `data/evidence/` via path resolution
3. **Process**: CLI tools executed via explicit arg arrays, no shell interpretation
4. **Authorization**: Scope-based gating on all active assessment endpoints
5. **Origin**: Same-origin policy on all sensitive GET endpoints

---

## 4. Integration Points for Kali Tools

### Existing Patterns to Leverage
1. **Tool Registry** (`engine/tooling.py:Spec` class) — Add Kali tools as new `Spec` entries with `kind="cli"`
2. **Provider Dispatch** (`engine/engine.py:provider()`) — CLI tools automatically routed via `tooling.tool_command()`
3. **Output Parsers** — Extend `parse_domain_lines()`, `parse_username_output()`, `parse_kv_output()` for Kali tool output formats
4. **Diagnostics** — `tooling.diagnose()` already checks PATH for executables
5. **Category System** — `cats(kind, srm)` maps input types to research categories
6. **Scope Authorization** — New active Kali tools can use `authorized_only` / `deep_only` flags

### Extension Points
- **New CLI Tools**: Add to `_SPECS` in `tooling.py` with appropriate categories
- **New Web Providers**: Add to `PROVIDERS` dict in `web_providers.py`
- **New Catalog Resources**: Add to `WEB_TOOLS` in `catalog.py` or `AWESOME_RESOURCES` in `awesome_catalog.py`
- **New Export Formats**: Add endpoint in `main.py` following existing pattern
- **New Input Types**: Extend `validation.py` and `classify()` in `engine.py`

---

## 5. Current Limitations & Gaps for Kali Integration

| Area | Current State | Gap for Kali Integration |
|------|---------------|-------------------------|
| Tool Installation | Manual (user installs in PATH) | No automated Kali package detection/install |
| Tool Categories | 6 categories (username, social, email, domain, ip, search) | Kali has 14+ categories needing mapping |
| Active Scanning | Limited (port probe, security snapshot) | Kali tools are predominantly active/intrusive |
| Reporting | Basic exports | No Kali-style report templates |
| Credential Testing | None (by design) | Kali has many credential tools needing auth gating |
| Wireless/Bluetooth | None | Major Kali category missing |
| Exploitation | None (by design) | Kali has exploitation frameworks |
| Forensics | Local file analysis only | No disk/memory forensics integration |
| Reverse Engineering | None | Major Kali category missing |
| Hardware/HF/RFID | None | Major Kali category missing |

---

## 6. Files Modified in v4.0.1 Security Remediation

```
main.py                    # Core endpoints, screenshot, exports, evidence, lifespan
engine/store.py            # Evidence integrity, DB migration, cleanup
engine/security.py         # Scope auth, IDN, SSRF validation, IP checks
engine/tooling.py          # CLI defense (arg arrays, validation, subprocess)
START.cmd                  # Windows launcher with PID tracking
SECURITY.md                # Scope authorization documentation
web/app.js                 # Frontend scope UI (wildcard badge)
tests/test_cross_origin_get.py    # New: 5 cross-origin tests
tests/test_additional_fixes.py    # Updated: +3 IDN tests
tests/test_evidence.py             # Fixed: filename assertion
verify_findings.py               # Enhanced: runtime tests
```

---

## 7. Conclusion

WireSploit v4.0.1 provides a **solid, security-hardened foundation** for Kali Linux integration:

**Strengths:**
- ✅ Defense-in-depth security architecture (9 findings remediated)
- ✅ Extensible tool registry with CLI/web/native provider types
- ✅ Unified finding data model with provenance tracking
- ✅ Scope-based authorization with subdomain inheritance
- ✅ Atomic evidence storage with integrity verification
- ✅ Comprehensive test coverage (88 tests, 50+ verification checks)
- ✅ Local-first design, no required cloud dependencies

**Ready for Phase 2:** The architecture cleanly supports adding Kali tools as new `Spec` entries in the tool registry, with automatic routing through the existing execution pipeline. The scope authorization system provides the necessary gating for active/intrusive tools.

---

*End of KALI_PROJECT_AUDIT.md*