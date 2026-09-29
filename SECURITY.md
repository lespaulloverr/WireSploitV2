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
