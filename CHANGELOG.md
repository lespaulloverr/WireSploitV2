# Changelog

## 4.0.1 — Patched core

### Fixed

- Validation: Phone number validation now correctly identifies invalid characters before checking digit count.
- Validation: Classification order changed to check domain before username to avoid misclassifying domains as usernames.
- Validation: IPv6 address normalization now expects compressed form as returned by ipaddress module.
- API contracts: Added intermediate assertion to verify first input is stored before adding second.
- API contracts: Tools endpoint no longer expects erroneous "description" field.
- Tooling: Restored original tooling.py functionality including SPEC_BY_ID, web_providers, tool_command, run_subprocess, and parsing functions.
- Tests: All tests now pass.
- Tooling: Added timeout handling to run_subprocess to prevent hanging subprocesses.
- Testing: Fixed CLI tooling subprocess error test to expect RuntimeError on subprocess failure with no output.
- Testing: Fixed timeout test to verify timeout behavior and corrected timeout message.
- Tooling: Improved tool diagnostics for CLI tools to check executable availability in PATH.
- Testing: Verified investigation lifecycle with mocked providers via test_investigation_start_and_poll.

## 4.0.0 — Fresh-slate core

### Added

- New local-first FastAPI application architecture.
- Single SQLite investigation persistence model.
- Investigation creation and multiple target inputs.
- Automatic target classification.
- Background investigation runs and staged identifier discovery.
- Provider isolation and run/job/event tracking.
- Findings and provenance storage.
- Evidence record storage.
- Public-source native and web providers.
- Optional external-tool registry with diagnostics.
- Explicit SRM authorization state.
- Windows CMD and PowerShell launchers.
- Core automated tests.

### Not yet complete

- Full evidence capture and screenshots.
- User-facing JSON/CSV/HTML/PDF exports.
- Visual maps and relationship graph.
- File/image upload investigation workflow.
- Tool installation/repair/import/disable management.
- Three-day temporary history expiry.
- Complete notes/editing workflow.
- Full resource-mode implementation.
- Installer/setup wizard.
- Built-in AI/Ollama layer.