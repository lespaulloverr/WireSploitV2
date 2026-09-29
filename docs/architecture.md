# Architecture

WireSploit V4 deliberately uses a small local architecture so the base application can run without Ollama, a cloud AI service or a large collection of third-party tools.

## Runtime flow

```text
Browser
  │
  ▼
FastAPI (`main.py`)
  │
  ├── Investigation API
  ├── Tool API
  └── Diagnostics API
  │
  ▼
SQLite store (`engine/store.py`)
  │
  ▼
Investigation engine (`engine/engine.py`)
  │
  ├── native providers (`engine/native.py`)
  ├── web providers (`engine/web_providers.py`)
  └── optional tools (`engine/tooling.py`)
  │
  ▼
findings / jobs / events / identifiers / evidence
```

## Persistence

The database is created automatically at `data/wiresploit.sqlite3`.

The database contains separate records for:

- investigations
- inputs
- runs
- jobs
- findings
- identifiers
- events
- evidence

The local database is ignored by Git. Contributors should never commit investigation data.

## Provider isolation

Providers are treated as separate units. A provider can return findings, return no findings, or fail. The orchestration layer records the result and continues where possible instead of treating one provider failure as an automatic whole-run failure.

## Optional tools

`engine/tooling.py` contains the registry for external command-line integrations. The registry is not proof that a tool is installed. Diagnostics check the current environment and report its state.

This distinction is important: a catalogue entry means WireSploit knows about a tool; a `ready` diagnostic means the current environment passed the tool's diagnostic check.

## Security model

The V4 UI stores an explicit `srm_authorized` flag on an investigation. Higher-risk technical modules are intended to remain behind explicit authorization and non-intrusive controls.

Contributors must not bypass those controls merely to make a feature easier to use.

## Current architectural boundaries

V4 does not yet provide:

- a complete plugin installation manager;
- a visual graph/map subsystem;
- a full evidence/screenshot capture subsystem;
- a complete export pipeline;
- a built-in AI orchestration layer;
- a production installer.

These should be added as deliberate modules rather than by reintroducing the split legacy architecture that V4 replaced.
