# ADR 0005: localStorage for Data Persistence

## Status

Accepted

## Context

The application needs to persist:

- User credentials (Hetzner API token, Git credentials)
- Global configuration
- Saved profiles
- UI preferences (theme)

With no backend, persistence options are limited to browser storage:

1. **localStorage**: Simple key-value storage, 5-10MB limit
2. **IndexedDB**: Structured database, larger storage limits
3. **Cookies**: Small, sent with requests, not suitable
4. **sessionStorage**: Cleared when tab closes, not suitable

## Decision

Use localStorage for all data persistence with a simple wrapper in `storage.js`.

## Consequences

### Positive

- **Simple API**: Synchronous `getItem`/`setItem`, easy to use
- **Sufficient capacity**: Our data is small (profiles, config), well under 5MB
- **Wide support**: Works in all browsers
- **Persistent**: Survives browser restarts
- **No async complexity**: Synchronous access simplifies code

### Negative

- **No structure**: Everything is serialized JSON strings
- **No querying**: Cannot search or filter without loading everything
- **Per-origin limit**: Shared with other apps on same origin
- **Synchronous I/O**: Could block main thread (negligible for our data sizes)

### Neutral

- **Security considerations**: Sensitive data (API tokens) stored in plain text; acceptable given the app runs locally and users control their browser

## Implementation

`storage.js` provides typed accessors:

```javascript
export function getGlobalConfig() {
  return JSON.parse(localStorage.getItem('globalConfig')) || DEFAULT_GLOBAL_CONFIG;
}

export function setGlobalConfig(config) {
  localStorage.setItem('globalConfig', JSON.stringify(config));
}
```

Storage keys:
- `hetznerToken` — Hetzner API token
- `globalConfig` — Global configuration object
- `profiles` — Array of saved profiles
- `theme` — Current theme name

## Alternatives Considered

### IndexedDB

More powerful database API:
- Better for large/structured data
- Async-only API adds complexity
- Overkill for our simple key-value needs

Rejected because localStorage is simpler and sufficient.

### IndexedDB with Wrapper (Dexie, idb)

Libraries that simplify IndexedDB:
- Still more complex than localStorage
- Additional dependency
- No clear benefit for our use case

Rejected for same reasons.

### Export/Import Only

No automatic persistence, users manually save/load configs:
- Too much friction
- Poor UX for frequent use

Rejected because convenience matters.
