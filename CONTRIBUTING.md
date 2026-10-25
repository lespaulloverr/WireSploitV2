# Contributing to WireSploit

Thanks for helping improve WireSploit.

The project is currently a fresh-slate V4 core. Small, focused pull requests are easier to review than large unrelated changes.

## Before you start

1. Read the README and the relevant files under `docs/`.
2. Check existing GitHub issues before starting a new feature.
3. For substantial changes, open an issue first so the intended behaviour can be discussed.
4. Never use real personal investigation data, credentials, API keys or private datasets in tests or examples.

## Development workflow

```text
Fork → branch → make a focused change → run tests/checks → open a pull request
```

Suggested branch names:

- `feature/evidence-capture`
- `fix/provider-timeout`
- `docs/contributor-guide`
- `test/domain-provider`

## Local setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

Run:

```powershell
python -m pytest -q
node --check web/app.js
python -m compileall -q .
```

## Where to make changes

- `main.py` — HTTP API and application wiring.
- `engine/engine.py` — investigation orchestration and run lifecycle.
- `engine/native.py` — native public-source/provider logic.
- `engine/web_providers.py` — web provider adapters.
- `engine/tooling.py` — optional external-tool registry and diagnostics.
- `engine/catalog.py` / `engine/awesome_catalog.py` — provider/tool catalogue data.
- `engine/store.py` — SQLite schema and persistence.
- `engine/security.py` — SRM/authorization-related controls.
- `web/index.html` — application shell.
- `web/app.js` — frontend behaviour and views.
- `web/styles.css` — frontend styling.
- `tests/` — automated tests.

## Provider contributions

A provider should:

- Have a clearly defined input and output.
- Return provenance/source information where possible.
- Fail cleanly when the remote service is unavailable.
- Avoid turning a provider timeout into a whole-investigation failure.
- Respect the project's exact-match expectations.
- Avoid collecting information that is not needed for the provider's documented purpose.
- Include tests where practical.

## Optional tool contributions

Optional CLI tools must remain optional. A missing external executable should produce an accurate diagnostic state rather than breaking the core application.

Do not describe a tool as installed or working unless the diagnostic code actually confirms it in the current environment.

## Pull requests

A good pull request should explain:

- What changed.
- Why it changed.
- How it was tested.
- Any Windows-specific behaviour.
- Any new dependencies.
- Any security or privacy implications.
- Any follow-up work that is intentionally left incomplete.

Keep generated files, local databases and caches out of commits.

## Commit hygiene

Do not commit:

- `.env` files containing secrets.
- API keys, tokens, cookies or passwords.
- `data/wiresploit.sqlite3` or other investigation databases.
- Personal screenshots or investigation evidence.
- Virtual environments.
- Python bytecode and test caches.
- Large generated archives unless specifically required by a release process.

## Code style

The current codebase is intentionally lightweight and does not enforce a large formatter/linter stack yet. Keep changes readable and consistent with nearby code. Avoid unrelated formatting changes in the same pull request.

## Security-sensitive changes

If a change touches authentication, permissions, data handling, external command execution, secrets, file handling or SRM controls, explain the security implications in the pull request and add tests where possible.
