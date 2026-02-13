import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert';

// Mock localStorage before importing the module
const store = {};
globalThis.localStorage = {
  getItem(key) { return store[key] ?? null; },
  setItem(key, value) { store[key] = value; },
  removeItem(key) { delete store[key]; },
  clear() { for (const k of Object.keys(store)) delete store[k]; },
  get length() { return Object.keys(store).length; },
  key(i) { return Object.keys(store)[i] ?? null; },
};

// Suppress console.warn noise from SWR cache error handling
console.warn = () => {};

import {
  swrFetch,
  backgroundRefresh,
  peekCache,
  clearSwrCache,
  CACHE_KEYS,
} from '../src/lib/utils/swr-cache.ts';

describe('CACHE_KEYS', () => {
  it('exports expected cache key constants', () => {
    assert.equal(CACHE_KEYS.servers, 'devbox_cache_servers');
    assert.equal(CACHE_KEYS.serverTypes, 'devbox_cache_server_types');
    assert.equal(CACHE_KEYS.locations, 'devbox_cache_locations');
    assert.equal(CACHE_KEYS.images, 'devbox_cache_images');
  });
});

describe('swrFetch', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('cold start: fetches from API, caches result, calls onData once', async () => {
    const apiData = [{ id: 1, name: 'server-1' }];
    const calls = [];

    await swrFetch({
      key: CACHE_KEYS.servers,
      token: 'test-token',
      fetcher: () => Promise.resolve(apiData),
      onData: (data) => calls.push(data),
    });

    assert.equal(calls.length, 1);
    assert.deepStrictEqual(calls[0], apiData);

    // Verify data is cached
    const cached = JSON.parse(localStorage.getItem(CACHE_KEYS.servers));
    assert.deepStrictEqual(cached.data, apiData);
  });

  it('warm start: calls onData with cached data, then again with fresh data', async () => {
    const cachedData = [{ id: 1, name: 'old-server' }];
    const freshData = [{ id: 1, name: 'new-server' }];
    const token = 'test-token';

    // Pre-populate cache by doing a cold fetch
    await swrFetch({
      key: CACHE_KEYS.servers,
      token,
      fetcher: () => Promise.resolve(cachedData),
      onData: () => {},
    });

    // Now fetch with warm cache
    const calls = [];
    await swrFetch({
      key: CACHE_KEYS.servers,
      token,
      fetcher: () => Promise.resolve(freshData),
      onData: (data) => calls.push(JSON.parse(JSON.stringify(data))),
    });

    assert.equal(calls.length, 2);
    assert.deepStrictEqual(calls[0], cachedData);
    assert.deepStrictEqual(calls[1], freshData);
  });

  it('token change: cached data from different token is ignored', async () => {
    const oldData = [{ id: 1 }];
    const newData = [{ id: 2 }];

    // Cache with token A
    await swrFetch({
      key: CACHE_KEYS.servers,
      token: 'token-A',
      fetcher: () => Promise.resolve(oldData),
      onData: () => {},
    });

    // Fetch with token B — should not serve cached data
    const calls = [];
    await swrFetch({
      key: CACHE_KEYS.servers,
      token: 'token-B',
      fetcher: () => Promise.resolve(newData),
      onData: (data) => calls.push(data),
    });

    assert.equal(calls.length, 1);
    assert.deepStrictEqual(calls[0], newData);
  });

  it('cache hit + API failure: cached data stays, error swallowed', async () => {
    const cachedData = [{ id: 1 }];
    const token = 'test-token';

    // Pre-populate cache
    await swrFetch({
      key: CACHE_KEYS.servers,
      token,
      fetcher: () => Promise.resolve(cachedData),
      onData: () => {},
    });

    // Fetch with failing API — should not throw
    const calls = [];
    await swrFetch({
      key: CACHE_KEYS.servers,
      token,
      fetcher: () => Promise.reject(new Error('API down')),
      onData: (data) => calls.push(data),
    });

    // Called once with cached data, no second call since API failed
    assert.equal(calls.length, 1);
    assert.deepStrictEqual(calls[0], cachedData);
  });

  it('no cache + API failure: error propagates to caller', async () => {
    await assert.rejects(
      () => swrFetch({
        key: CACHE_KEYS.servers,
        token: 'test-token',
        fetcher: () => Promise.reject(new Error('API down')),
        onData: () => {},
      }),
      { message: 'API down' }
    );
  });

  it('deduplication: concurrent calls to same key share one fetch', async () => {
    let fetchCount = 0;
    const apiData = [{ id: 1 }];

    const fetcher = () => {
      fetchCount++;
      return new Promise((resolve) => setTimeout(() => resolve(apiData), 10));
    };

    // Launch two concurrent fetches for the same key
    await Promise.all([
      swrFetch({
        key: CACHE_KEYS.servers,
        token: 'test-token',
        fetcher,
        onData: () => {},
      }),
      swrFetch({
        key: CACHE_KEYS.servers,
        token: 'test-token',
        fetcher,
        onData: () => {},
      }),
    ]);

    assert.equal(fetchCount, 1);
  });
});

describe('backgroundRefresh', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('fetches from network, updates cache, calls onData', async () => {
    const freshData = [{ id: 1 }];
    const calls = [];

    await backgroundRefresh({
      key: CACHE_KEYS.servers,
      token: 'test-token',
      fetcher: () => Promise.resolve(freshData),
      onData: (data) => calls.push(data),
    });

    assert.equal(calls.length, 1);
    assert.deepStrictEqual(calls[0], freshData);

    // Verify cache was updated
    const cached = JSON.parse(localStorage.getItem(CACHE_KEYS.servers));
    assert.deepStrictEqual(cached.data, freshData);
  });

  it('never throws on API failure', async () => {
    const calls = [];

    // Should not throw
    await backgroundRefresh({
      key: CACHE_KEYS.servers,
      token: 'test-token',
      fetcher: () => Promise.reject(new Error('API down')),
      onData: (data) => calls.push(data),
    });

    assert.equal(calls.length, 0);
  });

  it('does not serve cached data (skips cache read)', async () => {
    const oldData = [{ id: 1, name: 'old' }];
    const freshData = [{ id: 1, name: 'fresh' }];
    const token = 'test-token';

    // Pre-populate cache
    await swrFetch({
      key: CACHE_KEYS.servers,
      token,
      fetcher: () => Promise.resolve(oldData),
      onData: () => {},
    });

    // backgroundRefresh should only call onData with fresh data, not cached
    const calls = [];
    await backgroundRefresh({
      key: CACHE_KEYS.servers,
      token,
      fetcher: () => Promise.resolve(freshData),
      onData: (data) => calls.push(JSON.parse(JSON.stringify(data))),
    });

    assert.equal(calls.length, 1);
    assert.deepStrictEqual(calls[0], freshData);
  });
});

describe('peekCache', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('returns false when no cache exists', () => {
    assert.equal(peekCache(CACHE_KEYS.servers, 'test-token'), false);
  });

  it('returns true for valid cache', async () => {
    const token = 'test-token';
    await swrFetch({
      key: CACHE_KEYS.servers,
      token,
      fetcher: () => Promise.resolve([{ id: 1 }]),
      onData: () => {},
    });

    assert.equal(peekCache(CACHE_KEYS.servers, token), true);
  });

  it('returns false for cache with wrong token', async () => {
    await swrFetch({
      key: CACHE_KEYS.servers,
      token: 'token-A',
      fetcher: () => Promise.resolve([{ id: 1 }]),
      onData: () => {},
    });

    assert.equal(peekCache(CACHE_KEYS.servers, 'token-B'), false);
  });
});

describe('clearSwrCache', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('removes specific cache keys', async () => {
    // Populate two cache entries
    await swrFetch({
      key: CACHE_KEYS.servers,
      token: 'tok',
      fetcher: () => Promise.resolve([]),
      onData: () => {},
    });
    await swrFetch({
      key: CACHE_KEYS.serverTypes,
      token: 'tok',
      fetcher: () => Promise.resolve([]),
      onData: () => {},
    });

    assert.notEqual(localStorage.getItem(CACHE_KEYS.servers), null);
    assert.notEqual(localStorage.getItem(CACHE_KEYS.serverTypes), null);

    clearSwrCache([CACHE_KEYS.servers]);

    assert.equal(localStorage.getItem(CACHE_KEYS.servers), null);
    assert.notEqual(localStorage.getItem(CACHE_KEYS.serverTypes), null);
  });

  it('removes all cache keys when called without arguments', async () => {
    for (const key of Object.values(CACHE_KEYS)) {
      await swrFetch({
        key,
        token: 'tok',
        fetcher: () => Promise.resolve([]),
        onData: () => {},
      });
    }

    clearSwrCache();

    for (const key of Object.values(CACHE_KEYS)) {
      assert.equal(localStorage.getItem(key), null);
    }
  });
});
