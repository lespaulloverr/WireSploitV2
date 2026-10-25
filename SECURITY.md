# Security Policy

## Supported version

The current development target is WireSploit 4.0.x.

## Reporting a vulnerability

Please do not publish an exploitable vulnerability with reproduction details in a public issue.

If the GitHub repository has private security reporting enabled, use GitHub's **Security / Report a vulnerability** mechanism. Otherwise, contact the repository owner privately using the contact method listed on the repository profile.

Include:

- A short description of the issue.
- The affected version or commit.
- Reproduction steps that are safe to share privately.
- The impact you believe it could have.
- Any suggested mitigation, if known.

Do not include real credentials, personal investigation data or other private information.

## Secrets accidentally committed

If an API key, password, token, private key or similar secret is committed:

1. Revoke or rotate the secret immediately.
2. Remove it from the working tree.
3. Check Git history and repository forks/caches as appropriate.
4. Report the incident privately rather than posting the secret in an issue.

Removing a secret from the latest commit does not necessarily remove it from Git history.

## Scope Authorization & Subdomain Inheritance

WireSploit uses a scope-based authorization model. Before performing any active assessment (security snapshot, port probe, screenshot capture), the target must be within an authorized scope saved in the system.

### Scope Types

| Type | Description | Example |
|------|-------------|---------|
| `domain` | A domain name (e.g., `example.com`) | `example.com` |
| `url` | A full URL with scheme | `https://example.com/path` |
| `ip` | A single IP address | `192.0.2.1` |
| `cidr` | A CIDR range | `192.0.2.0/24` |

### Subdomain Inheritance

**When a `domain` scope is authorized, all subdomains are implicitly authorized.**

For example, if you add `example.com` as an authorized scope:
- `example.com` ✓ authorized
- `www.example.com` ✓ authorized (subdomain)
- `api.example.com` ✓ authorized (subdomain)
- `sub.sub.example.com` ✓ authorized (nested subdomain)
- `other.com` ✗ NOT authorized

This behavior applies **only** to `domain` type scopes. `url` type scopes require an exact host match.

### Wildcard Syntax (Explicit Opt-In)

Starting from v4.0.1, explicit wildcard syntax is supported for clarity:
- `*.example.com` — equivalent to `example.com` (authorizes domain and all subdomains)
- The wildcard is normalized to the base domain internally

**Recommendation:** Use explicit wildcard syntax (`*.example.com`) in the UI to make subdomain coverage clear. The system treats both `example.com` and `*.example.com` identically.

### UI Indication

In the Tool Manager scope list, scopes with subdomain coverage are indicated with a **subdomain badge** (e.g., `example.com 🌐` or `*.example.com`) to make implicit coverage visible.

### Security Considerations

- Subdomain inheritance is a **convenience feature** for authorized assessments.
- Only add domain scopes you explicitly control or have written permission to test.
- For granular control (e.g., authorize `api.example.com` but NOT `www.example.com`), use individual `url` scopes or specific subdomain `domain` scopes.
- CIDR scopes use IP network containment (not subdomain logic).

### API Endpoints Requiring Authorization

The following endpoints require the target to be in an authorized scope:
- `POST /api/security/snapshot` — Web security assessment
- `POST /api/security/probe` — Limited port probe
- `POST /api/screenshot` — Browser screenshot capture

### Configuration

Authorized scopes are stored in `data/authorized_scopes.json`. The file is created automatically when the first scope is added via the UI or API.
