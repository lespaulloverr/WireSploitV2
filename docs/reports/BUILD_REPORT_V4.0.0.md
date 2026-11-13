# WireSploit 4.0.0 — Fresh Slate Rebuild

## Architecture change
The old 3.x application mixed the legacy `app.db` job system with a separate V2 case database and two orchestration paths. WireSploit 4 removes that split from the user-facing investigation engine.

The new path is:

`UI -> Investigation API -> SQLite investigation store -> background run thread -> staged identifier queue -> providers -> findings -> provenance/events`

The core engine does not require Ollama or an optional CLI tool to create or run an investigation.

## Included
- New investigation workspace UI
- Single investigation persistence model
- Exact target input with auto classification
- Staged identifier discovery
- Provider isolation and statuses
- Optional installed-tool integration through the existing tool registry
- Explicit SRM authorization switch for higher-risk technical modules
- Findings, activity and evidence views
- Diagnostics and tool manager
- Windows `START.cmd` and `START.ps1`
- Existing provider/tool registry carried forward as an additive layer

## Verification performed
- `pytest -q`: 3 passed
- Python `compileall`: passed
- Node `--check web/app.js`: passed
- Static frontend routes tested with FastAPI TestClient
- Investigation creation tested
- Input creation tested
- Start Investigation tested end-to-end with a deterministic provider stub
- Run polling tested until completion
- Findings persistence tested

## Important test boundary
The build environment is Linux, so Windows-specific third-party CLI execution cannot be truthfully claimed as tested here. The core application and provider-selection path were tested independently of those optional Windows tools.
