# ADR 0026: Authelia Forward Auth

## Status

Accepted

## Context

Devbox previously used HTTP Basic Auth (via Caddy's `basic_auth` directive) to protect services on provisioned servers. This had several limitations:

1. **Single hardcoded user**: Only one `devbox` user with a generated password
2. **Tokens in URLs**: Service links used `https://user:pass@host/` format, which modern browsers increasingly block or strip
3. **No multi-user support**: Could not provision multiple user accounts
4. **No session persistence**: Every request required re-authentication

Additionally, wildcard DNS services (sslip.io, nip.io, traefik.me) are on the **Public Suffix List (PSL)**, which means browsers treat each subdomain as a separate site and refuse to share cookies across them. This prevents a single Authelia login from covering all service subdomains (e.g., `terminal.1-2-3-4.sslip.io` and `code.1-2-3-4.sslip.io`).

## Decision

Replace HTTP Basic Auth with **Authelia file-based forward auth**:

1. **Forward auth via Caddy**: Caddy delegates authentication to a local Authelia instance using `forward_auth`
2. **`dev.` subdomain prefix**: For wildcard DNS services, add a `dev.` prefix to create a common parent domain (e.g., `terminal.dev.1-2-3-4.sslip.io`). This moves the cookie domain one level below the PSL boundary, enabling cross-subdomain session sharing
3. **Pre-provisioned users**: Auth users are configured in the Devbox UI with usernames and passwords. Passwords are hashed client-side using bcryptjs and written into Authelia's file-based user database via cloud-init
4. **Pinned Authelia version**: The Authelia binary version is pinned to ensure reproducible provisioning

## Consequences

### Positive

- **Multi-user support**: Multiple users can be pre-provisioned with individual credentials
- **Session-based auth**: Single login covers all service subdomains for the session duration
- **No tokens in URLs**: Service links are clean URLs; authentication is handled via cookies
- **Better browser compatibility**: No reliance on `user:pass@host` URL format

### Negative

- **New dependency**: bcryptjs added for client-side password hashing
- **Increased complexity**: Authelia binary added to server provisioning
- **Auth user required**: At least one auth user must be configured before creating a server
- **Domain structure change**: Wildcard DNS URLs gain a `dev.` prefix segment, changing existing URL patterns

### Neutral

- **Cloud-init size**: Authelia configuration adds to cloud-init payload but remains within the 32KB limit
