# ADR 0009: Caddy as Reverse Proxy

## Status

Accepted

## Context

The development server runs multiple services that need to be accessible via HTTPS:

- ttyd terminal (port 7681)
- Potentially other services (development servers, APIs)

A reverse proxy is needed to:

- Provide HTTPS with valid certificates
- Route requests to appropriate services
- Handle subdomain or path-based routing

Options include:

1. **Caddy**: Modern web server with automatic HTTPS
2. **nginx**: Traditional, widely-used reverse proxy
3. **Traefik**: Cloud-native, Docker-focused reverse proxy
4. **HAProxy**: High-performance load balancer

## Decision

Use Caddy as the reverse proxy for all services.

## Consequences

### Positive

- **Automatic HTTPS**: Obtains and renews Let's Encrypt certificates automatically
- **Minimal configuration**: Simple Caddyfile syntax, often just a few lines
- **Sensible defaults**: Secure by default (TLS 1.2+, HSTS, etc.)
- **Single binary**: Easy to install, no dependencies
- **HTTP/2 and HTTP/3**: Modern protocols supported out of the box
- **WebSocket support**: Works seamlessly with ttyd

### Negative

- **Less familiar**: Smaller community than nginx
- **Fewer tutorials**: Less documentation for edge cases
- **Memory usage**: Slightly higher than nginx for simple configs

### Neutral

- **Performance**: More than sufficient for dev server use case

## Implementation

Caddy is installed and configured via cloud-init:

```yaml
packages:
  - caddy

write_files:
  - path: /etc/caddy/Caddyfile
    content: |
      {
          acme_ca https://acme-v02.api.letsencrypt.org/directory
      }

      terminal.{$DOMAIN} {
          reverse_proxy localhost:7681
      }

runcmd:
  - systemctl enable --now caddy
```

### ACME Provider Configuration

Devbox supports multiple ACME providers:

- **Let's Encrypt** (default): Free, widely trusted
- **ZeroSSL**: Alternative free CA
- **Buypass**: European CA
- **Custom**: For internal CAs or testing

### Subdomain Routing

Each service gets its own subdomain:

- `terminal.example.com` → ttyd
- `dev.example.com` → development server (if configured)

## Alternatives Considered

### nginx

Industry standard reverse proxy:

- More configuration required
- Manual certificate management (or certbot)
- Syntax more verbose

Example equivalent config:

```nginx
server {
    listen 443 ssl http2;
    server_name terminal.example.com;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    location / {
        proxy_pass http://localhost:7681;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

Rejected because Caddy achieves the same with less configuration.

### Traefik

Cloud-native, great for Docker/Kubernetes:

- More complex configuration
- Designed for dynamic service discovery
- Overkill for static service setup

Rejected because we have static, known services.

### No Reverse Proxy

Direct HTTPS on each service:

- Each service needs certificate management
- Multiple ports exposed
- Inconsistent security configuration

Rejected for operational complexity and security reasons.
