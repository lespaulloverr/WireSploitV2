# WireSploit v4.0.1 — Kali Linux Integration Implementation Plan

**Date:** 2026-10-25  
**Version:** 4.0.1  
**Prerequisites:** KALI_PROJECT_AUDIT.md, KALI_CATEGORY_COVERAGE.md  
**Status:** Awaiting user approval before Phase 2 execution

---

## Executive Summary

This plan details the implementation of Kali Linux tool integration into WireSploit v4.0.1+, leveraging the existing security-hardened architecture. The integration follows WireSploit's **OSINT-first philosophy** with defense-in-depth security: all active/intrusive Kali tools are gated behind scope authorization (`authorized_only: true`, `deep_only: true`) and explicit operator confirmation.

**Scope:** Phase 2A (EXECUTABLE tools) + Phase 2B (RESTRICTED tools with auth gating)  
**Timeline:** 4-6 weeks for Phase 2A, 6-8 weeks for Phase 2B  
**Architecture:** Extends existing `engine/tooling.py` Spec registry, `engine/engine.py` provider dispatch, and `engine/security.py` scope authorization

---

## 1. Reusable Components (Zero New Infrastructure)

The following WireSploit v4.0.1 components require **no modification** for Kali tool integration:

| Component | File | Reuse Mechanism |
|-----------|------|-----------------|
| **Tool Registry** | `engine/tooling.py:Spec` class | Add new `Spec` entries with `kind="cli"` |
| **Provider Dispatch** | `engine/engine.py:provider()` | CLI tools auto-routed via `tooling.tool_command()` |
| **Output Parsers** | `engine/engine.py:parse_*()` | Extend `parse_domain_lines()`, `parse_username_output()`, `parse_kv_output()` |
| **Diagnostics** | `engine/tooling.py:diagnose()` | Already checks PATH for executables |
| **Category Mapping** | `engine/engine.py:cats()` | Map Kali categories to existing `kind` + `srm` logic |
| **Scope Authorization** | `engine/security.py:is_authorized()` | New tools respect existing `authorized_only`/`deep_only` flags |
| **Evidence Storage** | `engine/store.py:add_evidence()` | Tool outputs (screenshots, logs, PCAPs) stored with SHA-256 integrity |
| **Export System** | `main.py` export endpoints | Kali findings included in JSON/CSV/HTML/PDF exports |
| **Frontend Tool Manager** | `web/app.js` (Integrations tab) | New tools appear automatically via `GET /api/tools` |
| **Background Cleanup** | `main.py` lifespan + `store.py` | Orphaned Kali evidence files cleaned via 24hr loop |
| **Windows Launcher** | `START.cmd` | PID tracking works for any spawned subprocess |

---

## 2. Missing Pieces (New Implementation Required)

### 2.1 Tool Registry Extensions (`engine/tooling.py`)

| Missing Piece | Specification |
|---------------|---------------|
| **Kali Tool Specs** | ~50 new `Spec` entries across 13 categories (see §4) |
| **Category Constants** | Add Kali category enums to `cats()` function |
| **Output Parser Registry** | New parsers for: `nmap_xml`, `masscan_json`, `nuclei_json`, `hydra_output`, `hashcat_show`, `sqlmap_log`, `bloodhound_json`, `volatility_json` |
| **Tool Version Detection** | Enhance `diagnose()` to parse `--version`/`-V` for compatibility checks |
| **Install Hints** | Add `install_hint` field to `Spec` (e.g., `apt install kali-tools-top10`, `pip install nuclei`) |

### 2.2 Scope Authorization Enhancements (`engine/security.py`)

| Missing Piece | Specification |
|---------------|---------------|
| **Tool-Level Scope Override** | Allow `Spec.scope_override` to restrict tools to sub-scope (e.g., WiFi tools only for `cidr` scopes with wireless interfaces) |
| **Credential Vault Reference** | Add `credential_ref` field to `Spec` for tools needing secrets (Hashcat masks, Hydra userlists) — references `data/credentials.json` (new, encrypted) |
| **Network Interface Binding** | For wireless/tools requiring specific interfaces, validate interface exists and is in monitor mode |

### 2.3 New Data Models

| Model | File | Purpose |
|-------|------|---------|
| `CredentialStore` | `engine/credentials.py` (NEW) | Encrypted storage for wordlists, API keys, hashcat masks; AES-256-GCM with per-entry keys |
| `ToolExecutionContext` | `engine/tooling.py` | Captures: tool, target, scope, operator, timestamp, PID, exit_code, stdout_path, stderr_path |
| `KaliCategory` | `engine/kali_categories.py` (NEW) | Enum mapping Kali categories → WireSploit `kind` + risk classification |

### 2.4 Frontend Enhancements (`web/app.js`)

| Feature | Specification |
|---------|---------------|
| **Tool Filter by Classification** | Tabs: "Executable", "Restricted (Auth Required)", "Educational (Catalog Only)" |
| **Restricted Tool Confirmation Modal** | Shows: tool, target, scope match, requires explicit "I authorize this" checkbox |
| **Credential Manager UI** | Settings → Credentials: add/edit encrypted wordlists, API keys (AES-256-GCM) |
| **Tool Diagnostics Panel** | Click tool → shows version, PATH location, install hint, last run status |
| **Kali Category Badges** | Color-coded badges matching `KALI_CATEGORY_COVERAGE.md` classification |

---

## 3. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        WIRESPLOIT v4.1+ ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────┐  │
│  │   Frontend   │───▶│  FastAPI     │───▶│   Engine     │───▶│  Tooling │  │
│  │  (web/app.js)│    │  (main.py)   │    │ (engine.py)  │    │ (tools)  │  │
│  └──────────────┘    └──────────────┘    └──────┬───────┘    └────┬─────┘  │
│         │                   │                   │                 │        │
│         ▼                   ▼                   ▼                 ▼        │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                      SECURITY LAYER (engine/security.py)             │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │  │
│  │  │   Scope     │  │   SSRF      │  │   IDN       │  │  Credential│  │  │
│  │  │   Auth      │  │   Guard     │  │   Normalize │  │  Vault     │  │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘  │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│         │                   │                   │                 │        │
│         ▼                   ▼                   ▼                 ▼        │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────┐  │
│  │   Store      │    │  Evidence    │    │  Credential  │    │  Native  │  │
│  │  (SQLite)    │    │  (Files)     │    │  Store (NEW) │    │  Providers│  │
│  └──────────────┘    └──────────────┘    └──────────────┘    └──────────┘  │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    KALI TOOL REGISTRY (engine/tooling.py)            │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐    │  │
│  │  │ EXECUTABLE  │ │ RESTRICTED  │ │ EDUCATIONAL │ │   PARSERS   │    │  │
│  │  │  (auto)     │ │ (auth gate) │ │ (catalog)   │ │ (output)    │    │  │
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘    │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Security Requirements (Non-Negotiable)

### 4.1 Mandatory Controls for RESTRICTED Tools

| Control | Implementation | Verification |
|---------|----------------|--------------|
| **Scope Authorization** | `Spec.authorized_only = true` + `is_authorized(target)` check before dispatch | Unit test: unauthorized target → 403 |
| **Deep Mode Gate** | `Spec.deep_only = true` + investigation `deep` flag check | Unit test: shallow mode → tool skipped |
| **Operator Confirmation** | Frontend modal with "I authorize this" checkbox + audit log | Integration test: no confirm → tool not executed |
| **Credential Isolation** | Credentials never in command line; passed via stdin/env file with 600 perms | Code review: no credentials in `ps aux` |
| **Output Sanitization** | All tool output parsed via registered parsers; raw output stored as evidence only | Test: malicious output → no XSS/injection in findings |
| **Resource Limits** | Per-tool timeout (default 300s), memory limit (512MB), output size cap (10MB) | `run_subprocess()` enforces via `asyncio.wait_for` + `resource.setrlimit` |
| **Network Isolation** | RESTRICTED tools inherit `_safe_get_public_host()` IP validation | Test: private IP target → blocked before tool runs |

### 4.2 Credential Vault (`engine/credentials.py`)

```python
# New module: encrypted credential storage
class CredentialStore:
    # AES-256-GCM, per-entry keys derived from master key (PBKDF2, 100k iterations)
    # Master key from env var WIRESPOILT_CRED_KEY or auto-generated on first run
    # Stored at: data/credentials.enc (encrypted), data/credentials.meta (index)
    
    def store(self, name: str, kind: str, secret: str, metadata: dict) -> str:
        """Returns credential_id for reference in Spec.credential_ref"""
    
    def retrieve(self, credential_id: str) -> str:
        """Decrypts and returns secret; logs access audit trail"""
    
    def list_credentials(self, kind: str = None) -> List[dict]:
        """Returns metadata only (no secrets)"""
```

**Credential Kinds:** `wordlist`, `api_key`, `hashcat_mask`, `hydra_userlist`, `ssh_key`, `ntlm_hash`

### 4.3 Audit Logging for Restricted Tools

Every RESTRICTED tool execution logs to `events` table with:
```json
{
  "level": "SECURITY",
  "message": "RESTRICTED tool executed",
  "meta_json": {
    "tool_id": "hydra",
    "tool_name": "Hydra",
    "target": "ssh://192.168.1.100",
    "scope_match": "cidr:192.168.1.0/24",
    "operator": "local_user",
    "credential_refs": ["cred_abc123"],
    "exit_code": 0,
    "duration_ms": 45231
  }
}
```

---

## 5. Dependencies

### 5.1 New Python Dependencies (requirements.txt additions)

| Package | Version | Purpose | Justification |
|---------|---------|---------|---------------|
| `cryptography` | >=42.0 | AES-256-GCM for credential vault | Standard, audited, no native deps on Windows |
| `pyyaml` | >=6.0 | Tool spec YAML config (optional) | Human-editable tool definitions |
| `defusedxml` | >=0.7 | Safe XML parsing for nmap/nessus output | Prevents XXE in parsers |
| `python-magic` | >=0.4 | MIME detection for evidence files | Already in requirements; verify present |

### 5.2 System Dependencies (Kali/Ubuntu/Windows)

| Tool Category | Package Manager | Notes |
|---------------|-----------------|-------|
| **Information Gathering** | `kali-tools-information-gathering` | Metapackage; includes nmap, masscan, dnsrecon, etc. |
| **Vulnerability Analysis** | `kali-tools-vulnerability` | OpenVAS, Nikto, WPScan, Lynis |
| **Web Applications** | `kali-tools-web` | Burp Suite (manual), sqlmap, commix, nuclei |
| **Password Attacks** | `kali-tools-password` | Hydra, Hashcat, John, Crunch, CeWL |
| **Wireless** | `kali-tools-wireless` | Aircrack-ng, Kismet, Wifite, Reaver |
| **Reverse Engineering** | `kali-tools-reversing` | Ghidra, Radare2, Cutter, Binwalk, apktool |
| **Exploitation** | `kali-tools-exploitation` | Metasploit, SearchSploit, CrackMapExec |
| **Sniffing/Spoofing** | `kali-tools-sniffing` | Wireshark (tshark), Ettercap, Bettercap, mitmproxy |
| **Post Exploitation** | `kali-tools-post-exploitation` | BloodHound, CrackMapExec, LaZagne |
| **Forensics** | `kali-tools-forensics` | Autopsy, Volatility3, Bulk-Extractor, SleuthKit |
| **Reporting** | `kali-tools-reporting` | Dradis, Faraday, Pipal |
| **Social Engineering** | `kali-tools-social-engineering` | SET, Gophish, King-Phisher |

**Windows:** Use WSL2 with Kali or Chocolatey/Scoop for individual tools. `START.cmd` already supports WSL via `wsl -d kali-linux`.

---

## 6. Implementation Order

### Phase 2A: EXECUTABLE Tools (Weeks 1-4)
**Goal:** Add 20+ passive/authorized-active CLI tools with zero new security surface

| Week | Deliverable | Tools | Files Modified |
|------|-------------|-------|----------------|
| 1 | **Kali Category Enum + Spec Scaffold** | — | `engine/kali_categories.py` (NEW), `engine/tooling.py` |
| 1-2 | **Reverse Engineering (Static)** | `ghidra` (headless), `radare2`, `binwalk`, `strings`, `exiftool` | `tooling.py`, `engine.py` (parsers) |
| 2 | **Forensics Enhancement** | `volatility3`, `bulk-extractor`, `foremost`, `scalpel`, `ddrescue` | `tooling.py`, `native.py` (extend `analyze_file`) |
| 2-3 | **Information Gathering Additions** | `masscan`, `dnsx`, `dnsgen`, `dnsrecon`, `fierce`, `altdns`, `dnstwist` | `tooling.py`, `catalog.py` (cross-ref) |
| 3 | **Passive Network Capture** | `tshark`, `p0f`, `zeek` (if available) | `tooling.py`, new parser `parse_pcap()` |
| 3-4 | **Reporting Integration** | `dradis` CLI, `faraday` CLI, `pipal` | `tooling.py`, export endpoints |
| 4 | **Frontend: Classification Tabs + Diagnostics** | — | `web/app.js`, `web/styles.css` |
| 4 | **Tests** | Unit + integration for all 2A tools | `tests/test_kali_phase2a.py` (NEW) |

### Phase 2B: RESTRICTED Tools (Weeks 5-10)
**Goal:** Add credential testing, exploitation, post-exploitation tools with full auth gating

| Week | Deliverable | Tools | Files Modified |
|------|-------------|-------|----------------|
| 5 | **Credential Vault** | — | `engine/credentials.py` (NEW), `engine/security.py` |
| 5-6 | **Vulnerability Scanners** | `nikto`, `wpscan`, `nuclei`, `dalfox`, `arjun` | `tooling.py`, parsers |
| 6-7 | **Password Attacks** | `hydra`, `hashcat`, `john`, `crunch`, `cewl` | `tooling.py`, `credentials.py` integration |
| 7 | **Web Exploitation** | `sqlmap`, `commix`, `xsser` (safe flags only) | `tooling.py`, strict parser allowlists |
| 7-8 | **Post-Exploitation** | `bloodhound` (ingest), `crackmapexec`, `ldapdomaindump` | `tooling.py`, AD-specific parsers |
| 8 | **Wireless (Conditional)** | `aircrack-ng`, `kismet` (passive) | `tooling.py`, interface detection |
| 8-9 | **Frontend: Confirmation Modal + Credential Manager** | — | `web/app.js`, `web/styles.css` |
| 9-10 | **Tests + Audit Log Verification** | — | `tests/test_kali_phase2b.py` (NEW), `verify_findings.py` |

### Phase 2C: EDUCATIONAL Catalog (Week 11)
**Goal:** Populate catalog with frameworks/GUI tools for operator awareness

| Week | Deliverable | Tools | Files Modified |
|------|-------------|-------|----------------|
| 11 | **Framework Catalog Entries** | Metasploit, Burp Suite, OWASP ZAP, SET, Gophish, BloodHound GUI | `catalog.py`, `awesome_catalog.py` |
| 11 | **Lab Environment Catalog** | DVWA, bWAPP, Mutillidae, Juice Shop | `catalog.py` |
| 11 | **Documentation** | Update `SECURITY.md` with Kali tool auth model | `SECURITY.md` |

---

## 7. Testing Strategy

### 7.1 Test Pyramid

| Level | Target | Tools | Count |
|-------|--------|-------|-------|
| **Unit** | Tool command construction, validation, parsing | `test_tool_command_*`, `test_parse_*` | 50+ |
| **Integration** | Tool dispatch via engine, scope auth, evidence storage | `test_kali_dispatch.py`, `test_kali_auth.py` | 20+ |
| **E2E** | Full investigation with Kali tools (mocked) | `test_kali_e2e.py` | 10+ |
| **Security** | Auth bypass attempts, credential leakage, SSRF via tools | `test_kali_security.py` | 15+ |

### 7.2 Test Infrastructure

```python
# tests/conftest.py additions
@pytest.fixture
def kali_tool_mock(monkeypatch):
    """Mock external Kali tools with controlled output"""
    async def mock_run_subprocess(cw, wd, timeout, stdin_text=None):
        # Return canned output based on tool name in cw[0]
        return MOCK_OUTPUTS.get(cw[0], (0, "", ""))
    monkeypatch.setattr("engine.tooling.run_subprocess", mock_run_subprocess)

@pytest.fixture
def authorized_scope(tmp_path):
    """Create investigation with authorized scope for restricted tools"""
    # Creates investigation + scope + returns (iid, scope)
```

### 7.3 Mock Output Library (`tests/kali_mocks.py`)

```python
MOCK_OUTPUTS = {
    "subfinder": (0, "sub1.example.com\nsub2.example.com\n", ""),
    "nmap": (0, "<nmaprun>...</nmaprun>", ""),  # XML output
    "hydra": (0, "[22][ssh] host: 192.168.1.1 login: admin password: password123", ""),
    "hashcat": (0, "hash:password\n", ""),
    "nuclei": (0, '{"template-id":"cve-2021-44228","matcher-name":"log4j"}\n', ""),
    "sqlmap": (0, "Parameter 'id' is vulnerable. Payload: 1' OR '1'='1", ""),
}
```

### 7.4 Regression Prevention

- All existing 88 tests must continue passing
- New tests added per tool: `test_tool_command_<tool>`, `test_parse_<tool>`
- `verify_findings.py` extended with Kali-specific checks
- CI: Run full suite on every PR; fail on any regression

---

## 8. Configuration & Deployment

### 8.1 Tool Auto-Discovery (Optional Enhancement)

```python
# engine/tooling.py addition
def discover_kali_tools() -> List[Spec]:
    """Scan PATH for known Kali tool binaries; return Spec entries for found tools"""
    KNOWN_KALI_TOOLS = {
        "nmap": {"categories": ["network"], "kind": "cli"},
        "masscan": {"categories": ["network"], "kind": "cli"},
        # ... 50+ entries
    }
    # Only returns Spec for tools actually found in PATH
```

### 8.2 Settings Persistence

Add to `data/settings.json`:
```json
{
  "kali_integration": {
    "enabled": true,
    "auto_discover": true,
    "restricted_mode": "confirm",  // "confirm" | "deny" | "allow"
    "credential_vault_enabled": true,
    "tool_timeouts": {
      "hydra": 600,
      "hashcat": 1800,
      "sqlmap": 300,
      "nuclei": 120
    }
  }
}
```

### 8.3 Windows Deployment Notes

- **WSL2 Required** for most Kali tools on Windows
- `START.cmd` already detects WSL: `wsl -d kali-linux -e <tool>`
- Tool paths: `/usr/bin/<tool>` in WSL → mapped via `wslpath`
- Credential vault works cross-platform (pure Python `cryptography`)

---

## 9. Risk Assessment & Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Tool output parsing breaks on version change | High | Medium | Version detection in `diagnose()`; parser version guards |
| Credential vault master key loss | Low | High | Auto-generate + backup prompt; export/import CLI |
| RESTRICTED tool executed without auth | Low | Critical | Double-check: engine + frontend + audit log |
| Tool hangs indefinitely | Medium | Medium | `asyncio.wait_for()` with configurable timeout; process kill |
| Evidence storage fills disk | Low | High | 24hr orphan cleanup + max evidence size config |
| Windows/WSl path confusion | Medium | Low | Abstract paths in `tool_command()`; test on both |

---

## 10. Deliverables Checklist

### Code Deliverables
- [ ] `engine/kali_categories.py` — Category enum + risk classification
- [ ] `engine/credentials.py` — Encrypted credential vault
- [ ] `engine/tooling.py` — ~50 new Spec entries + parser registry
- [ ] `engine/engine.py` — Extended `cats()`, new parsers
- [ ] `engine/security.py` — Credential vault integration, tool-level scope override
- [ ] `main.py` — Credential vault init in lifespan
- [ ] `web/app.js` — Classification tabs, confirmation modal, credential manager
- [ ] `web/styles.css` — Category badges, modal styles
- [ ] `requirements.txt` — New dependencies

### Test Deliverables
- [ ] `tests/test_kali_phase2a.py` — EXECUTABLE tool tests
- [ ] `tests/test_kali_phase2b.py` — RESTRICTED tool tests (auth gating)
- [ ] `tests/test_kali_security.py` — Security regression tests
- [ ] `tests/kali_mocks.py` — Mock output library
- [ ] `tests/conftest.py` — Updated fixtures

### Documentation Deliverables
- [ ] `SECURITY.md` — Updated with Kali tool authorization model
- [ ] `KALI_TOOL_REFERENCE.md` — Per-tool documentation (usage, flags, output format)
- [ ] `CHANGELOG.md` — v4.1 Kali integration entry

---

## 11. Approval Gate

**This plan requires explicit user approval before Phase 2 execution begins.**

### Approval Criteria
- [ ] Review `KALI_PROJECT_AUDIT.md` — Architecture understanding confirmed
- [ ] Review `KALI_CATEGORY_COVERAGE.md` — Classification decisions accepted
- [ ] Review this `KALI_IMPLEMENTATION_PLAN.md` — Scope, timeline, security model accepted
- [ ] Confirm target environment (Kali native / WSL2 / Windows + individual tools)
- [ ] Confirm Phase 2A vs 2B priority (or parallel)

### Next Steps Upon Approval
1. Create feature branch: `git checkout -b feature/kali-integration-phase2a`
2. Implement `engine/kali_categories.py` and credential vault scaffold
3. Begin Phase 2A Week 1 deliverables
4. Weekly progress updates with test results

---

## 12. Appendix: Tool Specification Template

Each Kali tool added to `engine/tooling.py` follows this Spec template:

```python
Spec(
    id="tool_id",                    # Unique identifier (lowercase, no spaces)
    name="Tool Display Name",        # Human-readable name
    kind="cli",                      # "cli" | "web" | "native"
    categories=["category1", "cat2"], # WireSploit categories (see cats())
    automated=True,                  # Can run in automated investigation
    authorized_only=False,           # True for RESTRICTED tools
    deep_only=False,                 # True for deep-mode only tools
    classification="executable",     # "executable" | "restricted" | "educational"
    kali_category="Information Gathering",  # From KALI_CATEGORY_COVERAGE.md
    install_hint="apt install tool-name",   # Installation guidance
    credential_ref=None,             # CredentialStore ID if needed
    scope_override=None,             # Optional: restrict to scope sub-type
    parser="parse_tool_output",      # Parser function name in engine.py
    timeout=300,                     # Seconds (default 300)
    args_template=["tool", "--arg", "{target}"],  # Template with {target} placeholder
    separator="--",                  # Separator before target (None if not needed)
)
```

---

*End of KALI_IMPLEMENTATION_PLAN.md*