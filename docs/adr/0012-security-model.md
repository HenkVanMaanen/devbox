# ADR 0012: Security Model and Threat Assumptions

## Status

Accepted

## Context

Devbox handles sensitive credentials:

- Hetzner Cloud API tokens (can create/delete servers, incur costs)
- Git credentials (access to repositories)
- SSH keys (server access)
- Service access tokens (access to terminal, dev servers)

The zero-backend architecture means there's no server-side security layer. All security relies on:

1. Browser security
2. HTTPS transport
3. Client-side validation
4. User's machine security

We need a clear threat model to make consistent security decisions.

## Decision

Adopt a **trusted user, trusted machine, untrusted network** threat model:

### In Scope (Protected Against)

- **Network eavesdropping**: All API calls use HTTPS
- **XSS attacks**: Input escaping, CSP headers
- **Injection attacks**: Shell escaping, input validation
- **Prototype pollution**: Explicit checks for dangerous properties
- **Unauthorized API access**: Credentials required for all operations

### Out of Scope (Not Protected Against)

- **Compromised browser**: If the browser is compromised, all bets are off
- **Malicious extensions**: Extensions can read localStorage
- **Physical access**: No protection against someone with machine access
- **Credential theft post-compromise**: If credentials leak, attacker has full access

### Accepted Tradeoffs

| Decision                   | Security Impact                            | UX Benefit                                        |
| -------------------------- | ------------------------------------------ | ------------------------------------------------- |
| Plain text localStorage    | Credentials readable by extensions/malware | No password prompts, persistent config            |
| Tokens in URLs             | Visible in history/logs                    | Simple auth, works with any HTTP client           |
| Credentials in cloud-init  | Visible on server filesystem               | Stateless provisioning, no secrets manager needed |
| `unsafe-inline` for styles | Style injection possible                   | Dynamic styling (theme previews, progress bars)   |

## Consequences

### Positive

- **Simple mental model**: Users understand "keep your machine secure"
- **No false security**: We don't pretend to protect against attacks we can't stop
- **Pragmatic UX**: Security measures don't impede normal usage
- **Appropriate for use case**: Ephemeral dev environments don't need bank-level security

### Negative

- **User responsibility**: Users must maintain machine security
- **No defense in depth**: Single point of failure (browser compromise)
- **Limited enterprise appeal**: May not meet corporate security requirements

### Neutral

- **Clear documentation**: Security model is explicit, users can make informed decisions

## Alternatives Considered

### Encrypted localStorage

Encrypt sensitive data with a user passphrase:

- Adds password prompt on every session
- Key must be derived and stored somewhere
- Complexity without significant benefit given threat model

Rejected because it adds friction without addressing the actual threats (compromised machine would capture the passphrase anyway).

### Backend with Credential Vault

Store credentials on a secure backend:

- Contradicts zero-backend architecture
- Centralizes risk (backend compromise affects all users)
- Adds operational complexity

Rejected per ADR-0001.

### Session-Only Storage (sessionStorage)

Clear credentials when tab closes:

- More secure (shorter exposure window)
- But requires re-entering all config each session
- Very poor UX for the target use case

Rejected because persistence is essential for usability.

### Hardware Security Keys

Require WebAuthn/FIDO2 for sensitive operations:

- Strong authentication
- But doesn't protect stored credentials
- Adds hardware requirement
- Overkill for ephemeral dev environments

Rejected as over-engineering for the threat model.

## Implementation Notes

### Current Security Controls

1. **CSP headers**: Restrict script sources (no `unsafe-inline` for scripts), API endpoints, frame ancestors
2. **Security headers**: `X-Content-Type-Options: nosniff` prevents MIME sniffing
3. **Input escaping**: `escapeHtml()`, `escapeAttr()` for all user content
4. **Shell escaping**: Context-aware escaping for cloud-init
5. **Input validation**: Regex patterns for packages, URLs, identifiers
6. **Prototype pollution checks**: Block `__proto__`, `constructor`, `prototype`
7. **HTTPS only**: CSP `connect-src` restricts to Hetzner API
8. **Clickjacking prevention**: `frame-ancestors 'none'` in CSP

### Future Improvements

1. **Remove `unsafe-inline` for styles**: Would require CSS custom properties for all dynamic values
2. **Optional encryption**: Web Crypto API for sensitive fields (opt-in)
3. **Audit logging**: Local log of sensitive operations (opt-in)

## References

- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
- [CSP Reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [localStorage Security](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage)
