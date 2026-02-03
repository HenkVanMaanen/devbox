# ADR 0015: Node.js Native Test Runner

## Status

Accepted

## Context

The project needs a testing solution for:

- Unit tests for JavaScript modules
- Mocking browser APIs (localStorage, fetch)
- Running in CI/CD pipeline

Options considered:

1. **Node.js native test runner**: Built into Node.js 18+
2. **Jest**: Popular, full-featured test framework
3. **Vitest**: Vite-native, Jest-compatible
4. **Mocha + Chai**: Classic combination
5. **Playwright/Puppeteer**: Browser-based E2E testing

## Decision

Use the Node.js native test runner (`node:test` module).

## Consequences

### Positive

- **Zero dependencies**: Built into Node.js, no npm packages needed
- **Fast startup**: No framework initialization overhead
- **Simple API**: Familiar `describe`/`it` pattern
- **Native assertions**: `node:assert` works well
- **Stable**: Part of Node.js LTS, won't break unexpectedly
- **ESM support**: Native ES module support

### Negative

- **Fewer features**: No snapshot testing, limited mocking utilities
- **Less ecosystem**: Fewer plugins and integrations
- **Manual mocking**: Need to write own mocks for browser APIs
- **Basic reporting**: Default output is minimal

### Neutral

- **Sufficient for our needs**: Unit tests don't require advanced features

## Implementation

```javascript
// tests/example.test.mjs
import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert';

describe('myFunction', () => {
    beforeEach(() => {
        // Setup
    });

    it('does something', () => {
        assert.equal(actual, expected);
    });
});
```

Run tests:
```bash
node --test 'tests/*.test.mjs'
```

### Browser API Mocking

```javascript
// Mock localStorage
globalThis.localStorage = {
    store: {},
    getItem(key) { return this.store[key] || null; },
    setItem(key, value) { this.store[key] = value; },
    removeItem(key) { delete this.store[key]; },
    clear() { this.store = {}; }
};
```

## Alternatives Considered

### Jest

Most popular test framework:
- Rich features (snapshots, mocking, coverage)
- But heavy dependency tree
- Slower startup
- ESM support historically problematic

Rejected because we don't need advanced features and want minimal dependencies.

### Vitest

Modern, fast, Jest-compatible:
- Great DX with Vite integration
- But we don't use Vite
- Additional dependency

Rejected because we don't use Vite.

### Playwright

Browser-based E2E testing:
- Tests real browser behavior
- But slower, more complex setup
- Overkill for unit testing logic

Used selectively for E2E, but not primary test runner.
