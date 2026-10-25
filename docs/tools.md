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

V4 supports explicit install/repair actions for a limited allowlist of known providers. It does not implement a general install/repair/import workflow. Any broader workflow should show exactly what will be installed/executed and record success or failure in diagnostics.


## WireSploit 4.0.0 expanded OSINT providers

The Tool Manager separates executable/in-engine **integrations** from external **web resources**. A resource link is not represented as installed software and results from an external web page are not automatically captured as investigation evidence. The current app exposes both lists through `/api/tools` and `/api/catalog`.

New passive enrichment providers include Shodan InternetDB (historical public IP observations), IPWho.is (approximate IP location and ASN context), RIPEstat (routing prefix / ASN), Cert Spotter (Certificate Transparency history), NIST NVD exact-CVE lookup, and the CISA Known Exploited Vulnerabilities catalogue. These do not actively scan the target. Data can be incomplete or stale and should be corroborated. IP-based enrichment rejects non-public IP addresses.

Optional authenticated providers are available for urlscan.io search, VirusTotal reputation and AbuseIPDB. They require `URLSCAN_API_KEY`, `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY`, respectively. GreyNoise Community supports limited unauthenticated lookups; `GREYNOISE_API_KEY` is optional. No credentials are shipped with WireSploit, displayed by diagnostics, or sent to unrelated providers. Create a local `.env` from `.env.example`; `.env` is ignored by version control. urlscan integration searches existing results only; it does not submit URLs for scanning. VirusTotal integration performs metadata/reputation lookups only; it does not upload files.

When an integration has a predefined supported installation workflow, Tool Manager presents an explicit Install / Repair action. WireSploit does not run arbitrary shell commands supplied through the UI. Third-party tools not covered by the repair workflow remain external/manual integrations and must be installed from their official project instructions.
