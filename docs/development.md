# Development Guide

## Environment

Recommended Windows development setup:

```powershell
python --version
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

If PowerShell execution policy prevents activation, you can run the environment's Python directly or use the CMD launcher for normal application testing.

## Tests

Run all tests:

```powershell
python -m pytest -q
```

Run Python compilation:

```powershell
python -m compileall -q .
```

Run the frontend syntax check:

```powershell
node --check web/app.js
```

## Manual smoke test

1. Start `START.cmd`.
2. Open the browser at `http://127.0.0.1:8765/`.
3. Create an investigation.
4. Add an input.
5. Start the investigation.
6. Watch the run status and findings.
7. Open diagnostics and inspect tool availability.

## Database during development

The first application import creates `data/wiresploit.sqlite3`.

For a clean local state, stop the application and delete the local `data/` directory. Do not delete or commit a shared database because investigation data is user data.

## Adding a provider

Keep provider-specific code isolated. Define:

1. accepted input type;
2. request/lookup logic;
3. timeout behaviour;
4. output normalisation;
5. provenance/source information;
6. exact-match metadata where relevant;
7. failure handling;
8. tests.

Do not make a remote provider mandatory for the application to boot.

## Windows considerations

The core project is intended for Windows users. Avoid assuming Unix-only paths or shell commands in user-facing workflows.

The Linux build environment used for the V4 verification could not validate Windows-specific third-party executables. Keep that limitation in mind when changing `engine/tooling.py` or launch scripts.

## Dependency changes

Keep runtime dependencies in `requirements.txt` and development/test-only dependencies in `requirements-dev.txt`.

When adding a dependency, explain why it is needed and whether the core application can still operate if an optional integration is unavailable.
