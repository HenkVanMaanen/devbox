# Security Documentation

This document describes the security model, controls, and considerations for Devbox.

## Threat Model

Devbox assumes:

- **Trusted user** on a **trusted machine**
- **Potentially untrusted network** (HTTPS required)
- **Ephemeral servers** (short-lived, deleted after use)

Devbox does NOT protect against:

- Compromised browser or machine
- Malicious browser extensions
- Physical access to the machine
- Targeted attacks against specific users

## Security Architecture

### Zero-Backend Design

```
┌─────────────────┐         HTTPS          ┌─────────────────┐
│     Browser     │◄──────────────────────►│  Hetzner Cloud  │
│                 │                        │      API        │
│  ┌───────────┐  │                        └─────────────────┘
│  │localStorage│  │
│  │ (secrets) │  │
│  └───────────┘  │
└─────────────────┘
```

**Security benefit**: No central server holding user credentials. Each user's secrets stay on their machine.

**Tradeoff**: Relies entirely on browser security. No server-side validation or rate limiting.

## Credential Handling

### Storage

| Credential | Storage Location | Encryption | Justification |
|------------|------------------|------------|---------------|
| Hetzner API token | localStorage | None | User-controlled, trusted machine assumed |
| Git credentials | localStorage | None | Same as above |
| SSH public keys | localStorage | N/A | Public data |
| Access tokens | localStorage | None | Per-server, ephemeral |
| ACME EAB keys | localStorage | None | Optional, user-provided |

**Why no encryption at rest?**

Client-side encryption would require a user-provided password or key. This adds UX friction and the key would need to be stored somewhere (defeating the purpose) or entered each session. Given the trusted-machine assumption, plain localStorage is acceptable.

**Future consideration**: Optional encryption for sensitive fields using Web Crypto API with a user passphrase.

### Transmission

All API calls use HTTPS:

- Hetzner API: `https://api.hetzner.cloud`
- CSP restricts `connect-src` to only allow Hetzner API

Tokens are transmitted in:

- `Authorization: Bearer <token>` header (Hetzner API) ✓ Secure
- URL for Basic Auth (`https://user:pass@host/`) ⚠️ See considerations below

### Tokens in URLs

Service URLs include access tokens for Basic Auth:

```
https://devbox:TOKEN@terminal.example.com/
```

**Exposure vectors:**

| Vector | Risk | Mitigation |
|--------|------|------------|
| Browser history | Low | Ephemeral servers, tokens invalid after deletion |
| Referrer header | Medium | Services are terminal endpoints, unlikely to have external links |
| Server logs | Low | User controls the server |
| Shoulder surfing | Low | Trusted machine assumption |

**Why this approach?**

- OAuth requires fixed callback URLs (incompatible with dynamic subdomains)
- Client certificates have poor UX
- Session cookies require server-side session management
- Basic Auth is simple and works with ephemeral servers

## Cloud-Init Security

### Sensitive Data in User-Data

Cloud-init scripts contain:

- Git credentials (username + token)
- Hetzner API token (for auto-delete)
- Service access tokens

**Where this data lives on the server:**

```
/var/lib/cloud/instance/user-data    # Original cloud-init
/home/dev/.git-credentials           # Git credentials (0600)
/opt/devbox/daemon.mjs               # Contains Hetzner token
```

**Mitigations:**

1. **File permissions**: Sensitive files created with `0600` (owner read/write only)
2. **Ephemeral servers**: Data exists only for server lifetime (typically < 1 day)
3. **User-controlled**: User decides what credentials to include
4. **No persistence**: Servers are deleted, not stopped/restarted

### Shell Injection Prevention

All user input embedded in cloud-init is escaped:

```javascript
// Shell context
function shellEscape(str) {
    return "'" + str.replace(/'/g, "'\"'\"'") + "'";
}

// Git config context
function escapeGitConfig(val) {
    return val.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

// JavaScript string context
function escapeSingleQuotedJS(s) {
    return s.replace(/\\/g, '\\\\').replace(/'/g, "\\'")
            .replace(/\n/g, '\\n').replace(/<\//g, '<\\/');
}
```

## XSS Prevention

### HTML Escaping

All dynamic content is escaped before rendering:

```javascript
export function escapeHtml(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
```

**Usage**: Every user-controlled value (server names, profile names, config values) passes through `escapeHtml()` or `escapeAttr()` before DOM insertion.

### Content Security Policy

```html
<meta http-equiv="Content-Security-Policy" content="
    default-src 'none';
    script-src 'self' 'unsafe-inline';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data:;
    font-src 'self';
    connect-src 'self' https://api.hetzner.cloud;
    base-uri 'self';
    form-action 'self';
">
```

| Directive | Value | Purpose |
|-----------|-------|---------|
| `default-src` | `'none'` | Deny everything by default |
| `script-src` | `'self' 'unsafe-inline'` | Allow own scripts + inline handlers |
| `style-src` | `'self' 'unsafe-inline'` | Allow own styles + Tailwind |
| `connect-src` | `'self' https://api.hetzner.cloud` | Restrict API calls |
| `img-src` | `'self' data:` | Allow images + QR code data URIs |

**Note**: `unsafe-inline` is required for inline event handlers. This could be improved by moving to `addEventListener` and using CSP nonces or hashes.

### Prototype Pollution Prevention

```javascript
export function setNestedValue(obj, path, value) {
    const keys = path.split('.');
    const lastKey = keys.pop();
    const target = keys.reduce((o, k) => {
        if (k === '__proto__' || k === 'constructor' || k === 'prototype') return {};
        if (!o[k]) o[k] = {};
        return o[k];
    }, obj);

    if (lastKey === '__proto__' || lastKey === 'constructor' || lastKey === 'prototype') return;
    target[lastKey] = value;
}
```

## Input Validation

### Package Names

```javascript
if (!/^[a-zA-Z0-9@._:\/+-]+$/.test(value)) {
    // Reject
}
```

### Repository URLs

```javascript
if (!/^(https?:\/\/|git@)[\w.@:\/~-]+$/.test(value)) {
    // Reject
}
```

### Profile IDs

```javascript
let id = name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
```

## Server-Side Security

### Service Authentication

Services on provisioned servers use HTTP Basic Auth:

```
Caddy (reverse proxy)
    │
    ├── basic_auth { devbox BCRYPT_HASH }
    │
    └── reverse_proxy localhost:7681 (ttyd)
```

- Access tokens generated with `crypto.getRandomValues()` (CSPRNG)
- Passwords hashed with bcrypt by Caddy
- Rate limiting handled by Hetzner's infrastructure

### TLS Certificates

Caddy obtains certificates automatically via ACME:

- Default: Let's Encrypt
- Alternatives: ZeroSSL, Buypass, custom CA

**On-demand TLS protection:**

```javascript
function verifyDomain(domain) {
    // Only issue certs for domains matching expected pattern
    // AND where the corresponding port is actively listening
    const expected = new RegExp(`^(\\d+)\\.${baseDomain}$`);
    const match = domain.match(expected);
    if (!match) return false;
    return isPortListening(parseInt(match[1]));
}
```

This prevents certificate issuance for arbitrary subdomains.

## Other Security Considerations

### Clickjacking

**Current**: No protection

**Recommendation**: Add to server response headers:
```
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none';
```

### MIME Sniffing

**Recommendation**: Add header:
```
X-Content-Type-Options: nosniff
```

### Browser Extensions

Browser extensions can read localStorage and intercept requests. This is an accepted risk under the trusted-machine assumption.

**Mitigation for high-security needs**: Use browser profiles or incognito mode without extensions.

### Dependency Supply Chain

npm dependencies could be compromised.

**Mitigations:**
- Minimal dependencies (5 packages)
- Lock file (`pnpm-lock.yaml`) pins versions
- Regular updates and audits

### DNS/Subdomain Security

If using wildcard DNS for services:
- Ensure DNS records are removed when servers are deleted
- Consider using IP-based URLs instead of subdomains for ephemeral servers

## Security Checklist for Users

- [ ] Use HTTPS to access Devbox (especially on untrusted networks)
- [ ] Use a dedicated browser profile for sensitive work
- [ ] Disable unnecessary browser extensions
- [ ] Use Hetzner API tokens with minimal required permissions
- [ ] Delete servers when done (don't just stop them)
- [ ] Rotate Git tokens periodically
- [ ] Clear browser data if using shared/public machines

## Reporting Security Issues

If you discover a security vulnerability, please report it privately rather than opening a public issue.
