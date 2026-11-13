# WireSploit 4.0.0 — OSINT Expansion and Test Report

## What changed

This update builds on the supplied WireSploit archive and leaves GitHub contribution/workflow scaffolding untouched.

### Ten new in-engine provider integrations

- **Shodan InternetDB** — passive, previously collected public IP context (ports, hostnames, CPEs, tags and CVE references); this endpoint does not scan a target. Its data is snapshot-based and can be stale.
- **IPWho.is** — approximate public IP geolocation and ASN/connection context.
- **RIPEstat Network Info** — routing prefix and announcing ASN context.
- **Cert Spotter** — Certificate Transparency history and observed certificate names.
- **urlscan.io Search** — searches existing scan records only; the integration does not submit or scan URLs.
- **VirusTotal Reputation** — domain/IP reputation metadata only; it does not upload files.
- **AbuseIPDB** — public-IP abuse-report context.
- **GreyNoise Community** — IP context, including limited unauthenticated lookups where available; an API key is optional.
- **NIST NVD CVE Lookup** — exact CVE-ID lookup, including description, CVSS and references.
- **CISA Known Exploited Vulnerabilities** — exact CVE checks against CISA's KEV feed, cached locally in memory for six hours.

The investigation engine now recognises CVE identifiers inside existing finding evidence and queues those IDs for NVD/KEV enrichment. Public-IP adapters reject non-global/private IP inputs before making requests.

### Tool Manager and configuration

- The Tool Manager now separates **Integrated providers** from **Web resources** so external websites are not presented as installed/runnable software.
- The API currently returns **104 Tool Manager entries** and **157 curated external resources**. Not every listed third-party CLI is bundled or installed; diagnostics remain the source of its availability status.
- Added local `.env` loading for API keys while preserving already-set environment variables.
- Diagnostics describe missing provider credentials without exposing their values.
- Added a guarded repair endpoint: only tools with a predefined supported repair workflow can be repaired by the app.
- Hardened ZIP extraction used by supported installer workflows against path-traversal members.
- Updated tool documentation and `.env.example` with optional API-key settings.

## Validation results

All checks below passed in the build environment used for this update.

| Check | Result |
|---|---|
| Python bytecode compilation (`python -m compileall -q .`) | Passed |
| JavaScript syntax (`node --check web/app.js`) | Passed |
| Automated test suite (`python -m pytest -q -p no:cacheprovider`) | **23 passed** |
| Local Uvicorn smoke test — homepage | HTTP 200 |
| Local Uvicorn smoke test — `/api/health` | `ok: true`, reports 104 providers |
| Local Uvicorn smoke test — `/api/tools` | 104 entries returned |
| Local Uvicorn smoke test — `/api/catalog` | 157 resources returned; all marked `external-resource` |
| Registry consistency | 104 unique tool IDs; no duplicates; automated web providers have provider implementations |
| Safety/regression tests | Include private-IP rejection, API-key secrecy, non-repairable tool guard, ZIP path traversal rejection, provider response parsing, and CVE discovery/enrichment |

Provider tests use mocked HTTP responses to make tests repeatable and avoid using real targets or consuming external API quotas. **This is not a live-endpoint certification.** Third-party services, API quotas, provider schemas, Windows-specific behaviour, and optional third-party binary installations may differ in use. The local server smoke test ran on Linux, not on Windows 11.

## Setup notes

WireSploit's core runs without API keys. Copy `.env.example` to `.env` and add your own credentials only for the services you choose to use. Do not share the resulting `.env` file. `URLSCAN_API_KEY`, `VIRUSTOTAL_API_KEY`, and `ABUSEIPDB_API_KEY` enable their respective integrations; `GREYNOISE_API_KEY` is optional.

Results from public intelligence sources may be incomplete or stale. Review source links and corroborate important conclusions. Only investigate systems and data you are authorised to assess.

## Official API references

- [Shodan InternetDB documentation](https://book.shodan.io/developer-apis/internetdb/)
- [GreyNoise Community API](https://docs.greynoise.io/docs/using-the-greynoise-community-api)
- [urlscan.io API documentation](https://docs.urlscan.io/apis/urlscan-openapi/search/searchdatasource)
- [Cert Spotter API](https://sslmate.com/certspotter/api/)
- [NIST NVD API documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
