# AI Investigator Architecture Audit

**Date**: 2026-11-10  
**Project**: WireSploit v4.0.1  
**Location**: `C:\Users\smecy\Downloads\WireSploit-v4.0.1-Patched\WireSploit-v4.0.1`

---

## 1. Existing Architecture Overview

### 1.1 Backend (Python/FastAPI)

**Entry Point**: `main.py` - FastAPI application with:
- RESTful API for investigations, tools, evidence, exports
- WebSocket-free polling for real-time updates (2-second intervals)
- Thread-based async execution for investigation runs
- Same-origin policy enforcement for security

**Core Modules** (`engine/`):
| Module | Purpose | Key Classes/Functions |
|--------|---------|----------------------|
| `store.py` | SQLite persistence layer | `connect()`, `create_investigation()`, `add_finding()`, `add_evidence()`, migrations |
| `engine.py` | Investigation execution engine | `run()`, `launch()`, `provider()`, `discover()`, `cats()` |
| `tooling.py` | Tool registry & execution | `Spec`, `SPEC_BY_ID`, `tool_command()`, `run_subprocess()`, parsers |
| `security.py` | Authorization & validation | `validate_screenshot_url()`, `is_authorized()`, scopes |
| `native.py` | Built-in OSINT providers | Username, email, phone, IP, domain lookups |
| `web_providers.py` | External web API providers | URLScan, Shodan, CERT Spotter, etc. |
| `credentials.py` | Encrypted credential vault | `CredentialKind`, `get_vault()` |
| `kali_env.py` / `kali_categories.py` | Kali tool classification | Categories, classifications, risk levels |

### 1.2 Database Schema (SQLite)

**Tables**:
- `investigations` - Core investigation records
- `inputs` - User-provided targets
- `runs` - Investigation execution runs
- `jobs` - Individual tool executions within runs
- `findings` - Discovered intelligence with provenance
- `identifiers` - Discovered entities for recursive investigation
- `events` - Audit/log events per run
- `evidence` - Uploaded/captured evidence files with SHA-256 verification
- `investigation_notes` - User notes
- `search_history` - Search query history

### 1.3 Frontend (Vanilla JS)

**Files**:
- `web/index.html` - Minimal entry point
- `web/app.js` - Complete SPA with:
  - Dashboard, New Investigation, Investigations list, Tool Manager, Evidence, Diagnostics, Settings
  - Polling-based live updates
  - Graph visualization (force-directed SVG)
  - Map workspace (canvas-based)
  - Screenshot capture modal
  - Evidence upload
  - Notes management
- `web/styles.css` - Dark theme with CSS variables, responsive design

### 1.4 Tool Registry

**80+ tools registered** in `tooling.py` across categories:
- **Web providers** (20+): URLScan, Shodan, CERT Spotter, VirusTotal, GitHub, etc.
- **CLI tools - Executable** (20+): radare2, binwalk, strings, exiftool, volatility3, masscan, dnsx, etc.
- **CLI tools - Restricted** (25+): nikto, wpscan, nuclei, hydra, hashcat, sqlmap, bloodhound, etc.
- **CLI tools - Username** (5): sherlock, maigret, blackbird, gosherlock, socialanalyzer
- **CLI tools - Domain** (8): subfinder, assetfinder, amass, theharvester, waymore, gau, waybackurls, findomain

**Tool Classification System**:
- `EXECUTABLE` - Safe for automated pipeline
- `RESTRICTED` - Requires SRM authorization + deep mode
- `EDUCATIONAL` - Catalog only, not executed

---

## 2. Test Baseline

**Command**: `python -m pytest -q`  
**Result**: 86 passed, 2 failed (1:52:14)

**Failures** (both in `test_screenshot.py`):
1. `test_screenshot_endpoint` - Playwright timeout (90s) navigating to example.com
2. `test_screenshot_integration_with_evidence` - Same timeout issue

**Root Cause**: Network/Playwright configuration issue in test environment (DNS resolution failures in httpx during redirect validation)

**Note**: These are pre-existing failures, not introduced by AI Investigator work.

---

## 3. Integration Opportunities for AI Investigator

### 3.1 Natural Extension Points

| Existing Component | AI Integration Point |
|-------------------|---------------------|
| `engine.py` `run()` | Replace fixed 8-stage loop with AI-driven planning |
| `tooling.py` `SPEC_BY_ID` | Tool registry for AI tool selection |
| `store.py` schema | Extend with AI investigation tables |
| `main.py` API routes | Add `/api/ai/*` endpoints |
| `web/app.js` navigation | Add "AI Investigator" tab |
| `engine/native.py` providers | Wrap as AI-accessible tools |

### 3.2 Database Extensions Needed

New tables for AI Investigator:
```sql
ai_investigations       -- AI-driven investigation sessions
ai_objectives           -- Parsed user objectives
ai_tasks                -- AI-generated tasks
ai_executions           -- Tool execution records
ai_findings             -- AI-processed findings
ai_sources              -- Source tracking with credibility
ai_entities             -- Extracted entities
ai_relationships        -- Entity relationships with provenance
ai_memory               -- Compressed investigation context
ai_events               -- AI decision audit trail
```

### 3.3 Configuration

Existing `config.py` has `ENABLE_AI: False` - natural feature flag location.

---

## 4. Potential Conflicts & Risks

| Risk | Mitigation |
|------|------------|
| Database migration conflicts | Use `store.migrate_database()` pattern; version migrations |
| Tool execution conflicts | Reuse `tooling.run_subprocess()` with existing timeout/error handling |
| Frontend state management | Follow existing `state` pattern in `app.js` |
| Authentication/authorization | Extend existing `require_same_origin` dependency |
| Resource constraints (8GB RAM) | Implement lazy loading, bounded concurrency, local-first Ollama |

---

## 5. Proposed Implementation Approach

### Milestone 1: Foundation (Week 1)
- Create `engine/ai_investigator/` module structure
- Implement database migrations for AI tables
- Create provider abstraction (Ollama + cloud)
- Define Pydantic schemas for structured AI output

### Milestone 2: Tool Registry (Week 1-2)
- Wrap existing tools as AI-accessible capabilities
- Implement execution policy (PASSIVE/SENSITIVE/RESTRICTED)
- Create standardized tool result format

### Milestone 3: Autonomous Engine (Week 2-3)
- Implement orchestrator with state machine
- Build planner/evaluator with structured prompts
- Implement task queue and iteration loop

### Milestone 4: Memory & Intelligence (Week 3)
- Persistent findings, entities, relationships
- Context compression for model calls
- Deduplication and source verification

### Milestone 5: Frontend (Week 3-4)
- AI Investigator navigation tab
- Investigation creation wizard
- Live activity monitor with SSE
- Findings, graph, report views

### Milestone 6: Hybrid AI (Week 4)
- Ollama integration with model detection
- Cloud provider abstraction
- Intelligent routing with privacy-aware context

### Milestone 7: Verification (Week 4)
- Full test suite (new + regression)
- End-to-end investigation test
- Performance profiling on 8GB target hardware

---

## 6. Key Files to Modify/Create

### New Files
```
engine/ai_investigator/
    __init__.py
    investigator.py          # Main orchestrator
    orchestrator.py          # Execution controller
    planner.py               # AI planning
    evaluator.py             # AI evaluation
    model_router.py          # Local/cloud routing
    tool_registry.py         # Tool discovery/wrapping
    tool_executor.py         # Standardized execution
    memory.py                # Context management
    context_builder.py       # Prompt context building
    entity_extractor.py      # NER from findings
    relationship_engine.py   # Entity relationships
    source_verifier.py       # Source credibility
    report_generator.py      # Final reports
    execution_policy.py      # PASSIVE/SENSITIVE/RESTRICTED
    checkpoint_manager.py    # Resume capability
    schemas.py               # Pydantic models
    providers/
        __init__.py
        base.py
        ollama.py
        cloud.py
    prompts/
        planner.txt
        evaluator.txt
        extractor.txt
        verifier.txt
        report.txt

web/ components (integrated into app.js)
```

### Modified Files
- `main.py` - Add `/api/ai/*` routes
- `engine/store.py` - Add AI tables and migration
- `engine/tooling.py` - Export tool metadata for AI
- `config.py` - Add AI configuration options
- `web/app.js` - AI Investigator UI
- `web/styles.css` - AI-specific styles

---

## 7. Hardware Constraints (Target Environment)

- **OS**: Windows 11
- **CPU**: Intel Core i5-1235U (10 cores, 12 threads)
- **GPU**: Integrated Intel Iris Xe
- **RAM**: 8 GB (critical constraint)
- **Storage**: SSD

**Implications**:
- No large local models (>4GB)
- Single model in memory at a time
- Aggressive context compression
- SQLite WAL mode for concurrent access
- Lazy-loaded modules
- Configurable concurrency (default: 2 parallel tools, 1 model request)

---

## 8. Next Steps

1. ✅ Complete architecture audit (this document)
2. Create implementation plan with milestones
3. Begin Milestone 1: Foundation - database migrations, module skeleton
4. Set up Ollama integration for local inference
5. Create tool registry adapter for existing tools

---

*This audit is based on actual codebase inspection as of 2026-11-10.*