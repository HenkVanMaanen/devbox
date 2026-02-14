# ADR 0024: SWR Caching for Hetzner API Calls

## Status

Accepted

## Context

Every Dashboard visit makes live API calls to Hetzner, showing a loading spinner until responses arrive. Server types, locations, and images are only cached in-memory (lost on page reload). This makes the UI feel slow, especially for data that rarely changes.

Users expect instant feedback when navigating between pages. The existing pattern of fetching fresh data on every page load creates unnecessary latency and visual churn (loading spinners).

## Decision

Implement a Stale-While-Revalidate (SWR) caching pattern using localStorage. The cache serves stale data instantly while silently refreshing from the API in the background.

Key design choices:

1. **Always revalidate**: Every fetch hits the API regardless of cache age. Cache exists only to avoid the loading spinner — there are no staleness thresholds or TTLs.

2. **localStorage persistence**: Cache survives page reloads and browser restarts, providing instant data on cold starts.

3. **Optimistic mutations**: Delete removes the server from UI immediately; create adds the server after it's running. Background refresh syncs with API reality afterward.

4. **Silent refresh**: No loading indicators during background revalidation. If the API fails and cache exists, the error is swallowed.

5. **Token-scoped cache**: Each cache entry stores a hash of the API token. Changing tokens invalidates the cache automatically.

6. **Request deduplication**: In-flight requests are shared via a map, preventing duplicate API calls when effects fire multiple times.

### Cache utility (`swr-cache.ts`)

A standalone, pure TypeScript module with no Svelte dependency:

- `swrFetch()` — Serve cached data, then fetch fresh data from API
- `backgroundRefresh()` — Fetch-only (no cache read), used after mutations
- `peekCache()` — Check if valid cache exists (for loading spinner decisions)
- `clearSwrCache()` — Remove cache entries (used on token change)

### What is NOT cached

- SSH keys: Only fetched during server creation (mutation path), not a read path
- Server actions (create, delete, rebuild): These are mutations, not reads

## Consequences

### Positive

- **Instant page loads**: Cached data appears immediately, no spinner on warm visits
- **Optimistic UI**: Deletes and creates feel instantaneous
- **Resilient**: API failures don't break the UI when cache exists
- **Simple**: ~80 lines of code, no external dependencies, easily testable
- **Token-safe**: Cache auto-invalidates when switching Hetzner accounts

### Negative

- **Stale data window**: Between cache serve and API response, UI shows potentially outdated data
- **Cross-tab blindness**: Mutations in one tab aren't visible in another until next navigation
- **Re-renders on identical data**: Background refresh triggers Svelte re-renders even when data hasn't changed (could add shallow-equal check as optimization)
- **localStorage limits**: ~5MB browser limit, though Hetzner API responses are well under this

## Alternatives Considered

### Service Worker cache

Full request-level caching via Service Worker:

- More powerful (intercepts all fetches)
- But significantly more complex to implement and debug
- Overkill for 4 API endpoints

Rejected: too much complexity for the benefit.

### In-memory only (no localStorage)

Cache in module-level variables, lost on reload:

- Simpler implementation
- But no benefit on page reload (still shows spinner)

Rejected: localStorage persistence is the main UX win.

### Time-based staleness (TTL)

Skip API call if cache is fresh enough:

- Reduces API calls
- But adds complexity (what's the right TTL?) and risks showing truly stale data

Rejected: always revalidating is simpler and ensures data freshness.
