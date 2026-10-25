# WireSploit v4.0.1 — Fixes applied

## Authorization and request security
- Added Origin/Referer checks to state-changing API routes.
- Added API routes to create, list, and delete explicit authorized scopes.
- Added scope-gated security snapshot and limited-probe routes.
- Enforced scope checks inside the security helpers, not only at the route boundary.
- Added public-address validation and disabled automatic redirect following for user-targeted HTTP checks; each redirect destination is revalidated.
- Domain TLS enrichment is no longer enabled merely by the investigation checkbox; it also requires a matching saved scope.

## Investigation engine
- Preserved the user's selected input type rather than reclassifying it during execution.
- Re-queues original user inputs on a later run while retaining discovered identifiers and historical findings.
- Applies a 200-job safety cap and deduplicates provider/category work per identifier.
- Threads the authorization flag through technical lookups and gates deep-only providers.
- Avoids sending IP targets to place-name geolocation providers.

## Native providers and UI
- Nominatim geolocation handles non-200 responses and malformed bodies safely and validates coordinate ranges.
- Fixed run polling to handle navigation and transient API failures.
- Completed runs display 100%; errors use a distinct progress-bar state.
- Fixed JavaScript syntax errors in the findings/run rendering and investigation tab functions.

## Dependencies and launchers
- Added Hachoir to the automatic pip repair map.
- Added `requirements-optional.txt` for PDF and OCR helpers.
- Windows launchers create the virtual environment only when needed and wait for the health endpoint before opening the browser.

## Validation
- 28 automated tests passed.
- Python compilation passed for all Python files.
- `node --check web/app.js` passed.
- Live third-party provider behaviour and Windows 11 end-to-end startup were not tested in this environment.

## Remaining limitation
The provider error/status refactor proposed in the earlier dossier has not been converted into a shared `ProviderResult` contract across every web adapter. Some provider failures can still be represented as empty results rather than a structured distinction between no-match, rate-limit, and service error. DNS validation also cannot completely eliminate DNS-rebinding races without pinning the resolved address at the HTTP transport layer.
