# ADR 0004: Hash-Based Client-Side Routing

## Status

Accepted

## Context

The application has multiple views:

- Dashboard (server list and creation)
- Profiles list
- Profile editor
- Global configuration
- Cloud-init preview
- Credentials

Single-page applications typically handle routing in one of two ways:

1. **Hash-based**: URLs like `index.html#/profiles`
2. **History API (pushState)**: URLs like `/profiles`

## Decision

Use hash-based routing with URLs like `#/profiles`, `#/config`, `#/profile/edit/default`.

## Consequences

### Positive

- **GitHub Pages compatible**: Works without server-side URL rewriting
- **Simple implementation**: Just listen to `hashchange` event
- **No 404 issues**: All requests go to `index.html`, hash is handled client-side
- **Bookmarkable**: Users can bookmark specific views
- **Shareable**: URLs work when shared (unlike some SPA routing)

### Negative

- **Uglier URLs**: Hash fragments look less clean than path-based URLs
- **SEO limitations**: Search engines historically handled hash URLs poorly (not relevant for this app)
- **Fragment conflicts**: Cannot use hash for in-page anchors (not needed)

### Neutral

- **Industry standard**: Hash routing is well-understood and widely used

## Implementation

The router in `state.js`:

```javascript
window.addEventListener('hashchange', () => {
  const route = window.location.hash.slice(1) || '/';
  renderPage(route);
});
```

Routes are simple string matching:

- `#/` or empty → Dashboard
- `#/profiles` → Profiles list
- `#/profile/edit/:id` → Profile editor
- `#/config` → Global config
- `#/cloudinit` → Cloud-init preview
- `#/credentials` → Credentials

## Alternatives Considered

### History API (pushState)

Cleaner URLs like `/profiles`:

- Requires server configuration to rewrite all paths to `index.html`
- GitHub Pages doesn't support this without hacks (404.html redirect)
- More complex implementation

Rejected because GitHub Pages deployment is a priority.

### No Routing (Single View)

Everything on one page with show/hide:

- Simpler implementation
- But loses bookmarkability and browser back/forward
- Poor UX for an app with multiple distinct views

Rejected because the app has clear page boundaries.
