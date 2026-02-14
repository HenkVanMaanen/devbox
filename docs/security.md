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

```mermaid
flowchart LR
    subgraph Browser
        App["Devbox SPA"]
        LS["localStorage<br/>(secrets)"]
    end

    App <-->|HTTPS| API["Hetzner Cloud<br/>API"]
```

**Security benefit**: No central server holding user credentials. Each user's secrets stay on their machine.

**Tradeoff**: Relies entirely on browser security. No server-side validation or rate limiting.

## Credential Handling

### Storage

| Credential        | Storage Location | Encryption | Justification                                 |
| ----------------- | ---------------- | ---------- | --------------------------------------------- |
| Hetzner API token | localStorage     | None       | User-controlled, trusted machine assumed      |
| Git credential    | localStorage     | None       | Bootstrap credential for chezmoi/repo cloning |
| SSH public keys   | localStorage     | N/A        | Public data                                   |
| Access tokens     | localStorage     | None       | Per-server, ephemeral                         |
| Age key           | localStorage     | None       | For chezmoi secret decryption                 |
| ACME EAB keys     | localStorage     | None       | Optional, user-provided                       |

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

| Vector           | Risk   | Mitigation                                                       |
| ---------------- | ------ | ---------------------------------------------------------------- |
| Browser history  | Low    | Ephemeral servers, tokens invalid after deletion                 |
| Referrer header  | Medium | Services are terminal endpoints, unlikely to have external links |
| Server logs      | Low    | User controls the server                                         |
| Shoulder surfing | Low    | Trusted machine assumption                                       |

**Why this approach?**

- OAuth requires fixed callback URLs (incompatible with dynamic subdomains)
- Client certificates have poor UX
- Session cookies require server-side session management
- Basic Auth is simple and works with ephemeral servers

## Cloud-Init Security

### Sensitive Data in User-Data

Cloud-init scripts contain:

- Bootstrap git credential (username + token for cloning chezmoi repo)
- Age private key (for chezmoi secret decryption)
- Hetzner API token (for auto-delete daemon)
- Service access tokens

**Where this data lives on the server:**

```
/var/lib/cloud/instance/user-data      # Original cloud-init
/home/dev/.git-credentials             # Git credential (0600)
/home/dev/.config/chezmoi/key.txt      # Age key (0600)
/usr/local/bin/devbox-daemon           # Contains Hetzner token
```

Most sensitive configuration (additional git credentials, API keys, env vars) is managed by chezmoi and decrypted on the server using the age key — not embedded directly in cloud-init.

**Mitigations:**

1. **File permissions**: Sensitive files created with `0600` (owner read/write only)
2. **Ephemeral servers**: Data exists only for server lifetime (typically < 1 day)
3. **User-controlled**: User decides what credentials to include
4. **No persistence**: Servers are deleted, not stopped/restarted
5. **Minimal cloud-init secrets**: Only bootstrap credential in cloud-init; chezmoi handles the rest

### Shell Injection Prevention

All user input embedded in cloud-init is escaped:

```javascript
// Shell context (double-quoted strings)
function shellEscape(s) {
  return s.replace(/[\\"$`!]/g, '\\$&').replace(/\n/g, '');
}

// JavaScript string context (single-quoted)
function escapeSingleQuotedJS(s) {
  return s.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n').replace(/<\//g, '<\\/');
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
<meta
  http-equiv="Content-Security-Policy"
  content="
    default-src 'none';
    script-src 'self';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data:;
    font-src 'self';
    connect-src 'self' https://api.hetzner.cloud;
    base-uri 'self';
    form-action 'self';
    frame-ancestors 'none';
"
/>
```

| Directive         | Value                              | Purpose                                              |
| ----------------- | ---------------------------------- | ---------------------------------------------------- |
| `default-src`     | `'none'`                           | Deny everything by default                           |
| `script-src`      | `'self'`                           | Only allow scripts from same origin (no inline)      |
| `style-src`       | `'self' 'unsafe-inline'`           | Allow own styles + dynamic inline styles             |
| `connect-src`     | `'self' https://api.hetzner.cloud` | Restrict API calls                                   |
| `img-src`         | `'self' data:`                     | Allow images + QR code data URIs                     |
| `frame-ancestors` | `'none'`                           | Prevent clickjacking (cannot be embedded in iframes) |

**Why `unsafe-inline` for styles?**

Dynamic inline styles are required for:

- Theme preview color swatches (dynamic background colors)
- Progress bars (dynamic width percentages)
- Combobox filtering (show/hide via display property)

These cannot use CSS classes because the values are computed at runtime. The security impact is limited because:

1. All user input is escaped before rendering
2. Style injection alone cannot execute JavaScript
3. The threat model assumes a trusted machine

**Additional Security Headers**

```html
<meta http-equiv="X-Content-Type-Options" content="nosniff" />
```

This prevents browsers from MIME-sniffing responses away from the declared content-type.

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

### Chezmoi/Repository URLs

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

```mermaid
flowchart TD
    Caddy["Caddy (reverse proxy)"]
    Caddy -->|"basic_auth { devbox BCRYPT_HASH }"| ttyd["reverse_proxy localhost:7681 (ttyd)"]
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

Protected via CSP `frame-ancestors 'none'` directive.

### MIME Sniffing

Protected via `X-Content-Type-Options: nosniff` header.

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
