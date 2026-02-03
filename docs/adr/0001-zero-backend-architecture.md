# ADR 0001: Zero-Backend Architecture

## Status

Accepted

## Context

Devbox needs to interact with cloud provider APIs (Hetzner Cloud) to provision and manage development servers. The traditional approach would be to build a backend service that:

- Stores user credentials securely
- Makes API calls to cloud providers on behalf of users
- Manages user accounts and sessions

However, this introduces significant complexity and operational burden.

## Decision

Devbox runs entirely in the browser with no backend server. The browser makes API calls directly to Hetzner Cloud using the user's API token.

## Consequences

### Positive

- **Easier deployment**: Static hosting on GitHub Pages, no servers to maintain
- **No credential custody**: Users keep their own API tokens; we never see them
- **No operational burden**: No databases, no backups, no security incidents involving user data
- **Privacy by design**: All user data stays on their machine
- **Cost**: Free to host and operate
- **Simplicity**: Dramatically reduced codebase complexity

### Negative

- **No server-side features**: Cannot implement features that require a backend (webhooks, scheduled tasks, shared state between users)
- **CORS dependency**: Relies on Hetzner's API supporting CORS for browser requests
- **Limited sharing**: Profiles can only be shared via export/import, not by URL

### Neutral

- **User responsibility**: Users must manage their own API tokens securely
- **No audit trail**: No centralized logging of actions (users can check Hetzner console)

## Alternatives Considered

### Traditional Backend (Node.js/Python API)

Would provide more flexibility but adds:
- Server hosting costs
- Security responsibility for user credentials
- Operational complexity (monitoring, updates, backups)
- User account management

Rejected because the added complexity wasn't worth it for the target use case of solo developers.

### Backend-for-Frontend (BFF) Proxy

A minimal backend that just proxies API calls without storing credentials.

Rejected because:
- Still requires hosting infrastructure
- Doesn't provide significant benefits over direct browser calls
- Hetzner's API already supports CORS
