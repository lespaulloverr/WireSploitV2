# WireSploit

**Version:** 4.0.0

WireSploit is a local-first public-source investigation workspace for Windows 11. It provides a single investigation model, staged identifier discovery, provider isolation, findings/provenance storage, diagnostics, and an additive registry for optional external tools.

V4.0.0 is a **working fresh-slate core release, not the final feature-complete WireSploit specification**. The repository is intentionally open for contributors to improve the application.

## What works in V4.0.0

- FastAPI backend with a local SQLite investigation store.
- Browser-based investigation workspace.
- Multiple inputs per investigation with automatic input classification.
- Background investigation runs with staged identifier discovery.
- Provider isolation so an individual provider failure does not have to stop the whole run.
- Findings, jobs, events, identifiers and evidence persistence.
- Exact-match metadata on findings.
- Native public-source providers for common username, email, phone, IP, domain, geolocation and search workflows.
- Web-provider adapters and an external-tool registry.
- Tool diagnostics showing which optional integrations are actually available in the current environment.
- Explicit SRM authorization state for higher-risk technical modules.
- Windows `START.cmd` and `START.ps1` launchers.
- Automated tests for the health endpoint, static files and an end-to-end investigation run using a deterministic provider stub.

## What is not complete yet

The following parts of the broader WireSploit roadmap are **not complete in V4.0.0**:

- Full evidence-capture workflow, including screenshots.
- JSON/CSV/HTML/PDF export workflow exposed through the UI.
- Visual relationship graph and map workspace.
- Proper file/image investigation upload workflow.
- Tool installation, repair, import and disable workflows.
- Three-day temporary search-history expiry.
- Complete investigation editing/notes workflow.
- Fully implemented Low/Balanced/High resource modes.
- Full installer/setup wizard.
- A built-in AI/Ollama layer in the V4 core.

See [`docs/roadmap.md`](docs/roadmap.md) for the contributor roadmap.

## Requirements

- Windows 11 is the primary supported platform for the current release.
- Python 3.13 or a compatible recent Python 3 release.
- Internet access is required for providers that query public web services.
- Optional third-party OSINT tools are **not** required to run the core application.

The core application does not require Ollama or a cloud AI provider.

## Optional Tool Integration

WireSploit integrates with a variety of optional OSINT and security tools to enhance its capabilities. These tools are categorized into two types:

- **Automated tools**: These tools are automatically detected and used by WireSploit if they are installed and configured correctly. They require no additional setup beyond installation.
- **Manual tools**: These tools require manual installation, configuration, or API key setup before they can be used. WireSploit will not automatically invoke these tools; instead, they must be explicitly selected and configured in the Tool Manager.

To install and configure optional tools, navigate to the Tool Manager in the application. The Tool Manager provides diagnostic information for each tool, indicating whether it is ready, missing, or requires manual intervention.

For detailed installation instructions for specific tools, refer to the tool's upstream documentation or the `docs/tools/` directory (if available).

Note: Some tools may have specific requirements or may not be compatible with all Windows 11 configurations. Always refer to the tool's official documentation for the most accurate installation guidance.

## Quick start on Windows

### Option 1 — double-click launcher

1. Install Python 3.
2. Open this repository folder.
3. Double-click `START.cmd`.
4. The local server starts on `127.0.0.1:8765` and the browser opens automatically.

The CMD launcher starts the server in a separate command window so you can see runtime output while developing.

### Option 2 — PowerShell

Run:

```powershell
.\START.ps1
```

If Windows blocks PowerShell scripts because of the local execution policy, use `START.cmd` or start the server manually instead.

### Manual start

```powershell
python -m pip install -r requirements.txt
python -m uvicorn main:app --host 127.0.0.1 --port 8765
```

Then open `http://127.0.0.1:8765/` in a browser.

## Development setup

Create a virtual environment if you want an isolated development installation:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

Run the tests:

```powershell
python -m pytest -q
```

Run a syntax check for the frontend:

```powershell
node --check web/app.js
```

Compile-check the Python source:

```powershell
python -m compileall -q .
```

The application creates its local SQLite database under `data/`. That directory is deliberately ignored by Git because investigation data is local and may contain sensitive information.

## Project structure

```text
WireSploit/
├── .github/workflows/      # CI checks for pull requests and pushes
├── docs/                   # Architecture, development, providers, tools and roadmap
├── engine/                 # Investigation engine, storage, providers and tool registry
├── tests/                  # Automated tests
├── web/                    # Browser UI
├── main.py                 # FastAPI application and API routes
├── START.cmd               # Windows CMD launcher
├── START.ps1               # PowerShell launcher
├── requirements.txt        # Runtime dependencies
├── requirements-dev.txt    # Runtime + development/test dependencies
└── README.md
```

## Architecture

The V4 investigation path is:

```text
Browser UI
   ↓
FastAPI investigation API
   ↓
SQLite investigation store
   ↓
Background investigation run
   ↓
Staged identifier queue
   ↓
Native/web/optional-tool providers
   ↓
Findings + provenance + events
```

The core engine is designed so optional external tools can fail or be unavailable without making the base application unusable.

Read [`docs/architecture.md`](docs/architecture.md) before making larger architectural changes.

## Contributing

Contributions are welcome, especially from people comfortable with Python, FastAPI, SQLite, JavaScript/CSS, testing, provider integrations or Windows tooling.

Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request.

Good first areas include:

- Evidence capture and screenshots.
- Export formats.
- Investigation notes/editing.
- Provider tests and provider error handling.
- Tool diagnostics and installation workflows.
- Frontend accessibility and responsive behaviour.
- Map and relationship visualisations.
- File/image analysis workflows.
- Windows startup and packaging improvements.

## Security and responsible use

WireSploit is intended for authorised research, investigations and public-source analysis. Do not use it to access accounts, systems or data without permission.

Do not commit API keys, passwords, cookies, tokens, personal investigation databases, or other private data. See [`SECURITY.md`](SECURITY.md) for reporting security issues and [`docs/development.md`](docs/development.md) for repository hygiene.

## License

No license has been selected for this repository yet. Before publishing a public GitHub repository, the project owner should choose and add a license appropriate to how they want other people to use, modify and distribute WireSploit.

## Current release status

V4.0.0 has been tested for the core application path. The supplied build report records 3 passing automated tests, Python compilation, frontend syntax validation, static-route checks, investigation creation, input creation, deterministic run execution and run polling.

Optional Windows third-party CLI integrations were not claimed as tested in the build environment.