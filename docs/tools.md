# Tooling Model

WireSploit treats external tools as optional integrations rather than hard dependencies of the investigation engine.

## States

A tool can be represented by catalogue information and then diagnosed against the current machine. Typical states include:

- Installed/Ready
- Available/Not Installed
- Missing Dependency
- Unavailable
- Disabled
- Failed Health Check

The exact diagnostic result is authoritative for the current environment.

## Why this matters

A public GitHub repository will be used on machines with very different configurations. A missing executable must not make the core application fail to start.

## Adding a tool

When adding a tool definition, document:

- the tool name and project URL;
- the expected executable/package;
- installation hint;
- diagnostic command;
- supported operating system;
- whether execution is automated or informational;
- any authorization requirements.

Avoid silently downloading or executing third-party software as part of normal startup.

## Installation manager future work

V4 does not yet implement the full install/repair/import workflow. Future work should make those actions explicit, show exactly what will be installed/executed, and record success or failure in diagnostics.
