import { beforeEach, describe, expect, it, vi } from 'vitest';

import { swrFetch, backgroundRefresh, peekCache, clearSwrCache, CACHE_KEYS } from '$lib/utils/swr-cache';

// Suppress console.warn noise from SWR cache error handling
vi.spyOn(console, 'warn').mockImplementation(() => {});

describe('CACHE_KEYS', () => {
  it('exports expected cache key constants', () => {
    expect(CACHE_KEYS.servers).toBe('devbox_cache_servers');
    expect(CACHE_KEYS.serverTypes).toBe('devbox_cache_server_types');
    expect(CACHE_KEYS.locations).toBe('devbox_cache_locations');
    expect(CACHE_KEYS.images).toBe('devbox_cache_images');
  });
});

describe('swrFetch', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('cold start: fetches from API, caches result, calls onData once', async () => {
    const apiData = [{ id: 1, name: 'server-1' }];
    const calls: unknown[] = [];

    await swrFetch({
      key: CACHE_KEYS.servers,
      token: 'test-token',
      fetcher: () => Promise.resolve(apiData),
      onData: (data) => calls.push(data),
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual(apiData);

    // Verify data is cached
    const cached = JSON.parse(localStorage.getItem(CACHE_KEYS.servers) ?? '{}');
    expect(cached.data).toEqual(apiData);
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
    const calls: unknown[] = [];
    await swrFetch({
      key: CACHE_KEYS.servers,
      token,
      fetcher: () => Promise.resolve(freshData),
      onData: (data) => calls.push(JSON.parse(JSON.stringify(data))),
    });

    expect(calls).toHaveLength(2);
    expect(calls[0]).toEqual(cachedData);
    expect(calls[1]).toEqual(freshData);
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
    const calls: unknown[] = [];
    await swrFetch({
      key: CACHE_KEYS.servers,
      token: 'token-B',
      fetcher: () => Promise.resolve(newData),
      onData: (data) => calls.push(data),
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual(newData);
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
    const calls: unknown[] = [];
    await swrFetch({
      key: CACHE_KEYS.servers,
      token,
      fetcher: () => Promise.reject(new Error('API down')),
      onData: (data) => calls.push(data),
    });

    // Called once with cached data, no second call since API failed
    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual(cachedData);
  });

  it('no cache + API failure: error propagates to caller', async () => {
    await expect(
      swrFetch({
        key: CACHE_KEYS.servers,
        token: 'test-token',
        fetcher: () => Promise.reject(new Error('API down')),
        onData: () => {},
      }),
    ).rejects.toThrow('API down');
  });

  it('deduplication: concurrent calls to same key share one fetch', async () => {
    let fetchCount = 0;
    const apiData = [{ id: 1 }];

    const fetcher = () => {
      fetchCount++;
      return new Promise<typeof apiData>((resolve) => setTimeout(() => resolve(apiData), 10));
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

    expect(fetchCount).toBe(1);
  });
});

describe('backgroundRefresh', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('fetches from network, updates cache, calls onData', async () => {
    const freshData = [{ id: 1 }];
    const calls: unknown[] = [];

    await backgroundRefresh({
      key: CACHE_KEYS.servers,
      token: 'test-token',
      fetcher: () => Promise.resolve(freshData),
      onData: (data) => calls.push(data),
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual(freshData);

    // Verify cache was updated
    const cached = JSON.parse(localStorage.getItem(CACHE_KEYS.servers) ?? '{}');
    expect(cached.data).toEqual(freshData);
  });

  it('never throws on API failure', async () => {
    const calls: unknown[] = [];

    // Should not throw
    await backgroundRefresh({
      key: CACHE_KEYS.servers,
      token: 'test-token',
      fetcher: () => Promise.reject(new Error('API down')),
      onData: (data) => calls.push(data),
    });

    expect(calls).toHaveLength(0);
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
    const calls: unknown[] = [];
    await backgroundRefresh({
      key: CACHE_KEYS.servers,
      token,
      fetcher: () => Promise.resolve(freshData),
      onData: (data) => calls.push(JSON.parse(JSON.stringify(data))),
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual(freshData);
  });
});

describe('peekCache', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('returns false when no cache exists', () => {
    expect(peekCache(CACHE_KEYS.servers, 'test-token')).toBe(false);
  });

  it('returns true for valid cache', async () => {
    const token = 'test-token';
    await swrFetch({
      key: CACHE_KEYS.servers,
      token,
      fetcher: () => Promise.resolve([{ id: 1 }]),
      onData: () => {},
    });

    expect(peekCache(CACHE_KEYS.servers, token)).toBe(true);
  });

  it('returns false for cache with wrong token', async () => {
    await swrFetch({
      key: CACHE_KEYS.servers,
      token: 'token-A',
      fetcher: () => Promise.resolve([{ id: 1 }]),
      onData: () => {},
    });

    expect(peekCache(CACHE_KEYS.servers, 'token-B')).toBe(false);
  });
});

describe('hashToken / deduplicatedFetch internals', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('different tokens produce different cache entries (kills hash arithmetic mutants)', async () => {
    const dataA = { source: 'A' };
    const dataB = { source: 'B' };
    const token1 = 'abc';
    const token2 = 'xyz';

    // Cache with token1
    await swrFetch({
      key: CACHE_KEYS.servers,
      token: token1,
      fetcher: () => Promise.resolve(dataA),
      onData: () => {},
    });

    // Cache with different key but token2
    await swrFetch({
      key: CACHE_KEYS.images,
      token: token2,
      fetcher: () => Promise.resolve(dataB),
      onData: () => {},
    });

    // Verify token1 cache only works with token1
    expect(peekCache(CACHE_KEYS.servers, token1)).toBe(true);
    expect(peekCache(CACHE_KEYS.servers, token2)).toBe(false);

    // Verify token2 cache only works with token2
    expect(peekCache(CACHE_KEYS.images, token2)).toBe(true);
    expect(peekCache(CACHE_KEYS.images, token1)).toBe(false);
  });

  it('hash uses every character of the token (kills loop boundary i <= vs i <)', async () => {
    // If the loop boundary was <=, it would access an extra undefined codepoint
    // Two tokens that differ only in the last character must produce different hashes
    const calls1: unknown[] = [];
    const calls2: unknown[] = [];

    await swrFetch({
      key: CACHE_KEYS.servers,
      token: 'abcX',
      fetcher: () => Promise.resolve({ val: 'X' }),
      onData: (d) => calls1.push(d),
    });

    // Fetch with token that differs only in last char
    await swrFetch({
      key: CACHE_KEYS.servers,
      token: 'abcY',
      fetcher: () => Promise.resolve({ val: 'Y' }),
      onData: (d) => calls2.push(d),
    });

    // With 'abcX' cached, fetching with 'abcY' should NOT get cached data
    // So calls2 should have exactly 1 call (fresh only, no cache hit)
    expect(calls2).toHaveLength(1);
    expect(calls2[0]).toEqual({ val: 'Y' });
  });

  it('single-char tokens produce distinct hashes (kills + vs - codepoint)', async () => {
    // Different single chars must hash differently: 'a' vs 'b'
    await swrFetch({
      key: CACHE_KEYS.servers,
      token: 'a',
      fetcher: () => Promise.resolve({ from: 'a' }),
      onData: () => {},
    });

    // 'b' should not see cached data from 'a'
    expect(peekCache(CACHE_KEYS.servers, 'b')).toBe(false);
    expect(peekCache(CACHE_KEYS.servers, 'a')).toBe(true);
  });

  it('deduplicatedFetch key includes token hash (kills empty string mutant)', async () => {
    // If the deduplication key was empty string, all fetches would share the same in-flight promise
    // regardless of the cache key. We test that different keys fetch independently.
    let fetchCountServers = 0;
    let fetchCountImages = 0;

    await Promise.all([
      swrFetch({
        key: CACHE_KEYS.servers,
        token: 'tok',
        fetcher: () => {
          fetchCountServers++;
          return Promise.resolve([1]);
        },
        onData: () => {},
      }),
      swrFetch({
        key: CACHE_KEYS.images,
        token: 'tok',
        fetcher: () => {
          fetchCountImages++;
          return Promise.resolve([2]);
        },
        onData: () => {},
      }),
    ]);

    // Both should have been fetched independently (not deduplicated into one)
    expect(fetchCountServers).toBe(1);
    expect(fetchCountImages).toBe(1);
  });

  it('readCache returns null for invalid JSON (catch block mutant)', () => {
    // Write invalid JSON directly to localStorage
    localStorage.setItem(CACHE_KEYS.servers, 'not-valid-json{{{');

    // peekCache calls readCache internally - should return false (null from catch)
    expect(peekCache(CACHE_KEYS.servers, 'any-token')).toBe(false);
  });

  it('readCache returns null when raw is empty string (kills !raw → false)', () => {
    // Set empty string in localStorage
    localStorage.setItem(CACHE_KEYS.servers, '');

    // peekCache should return false because readCache returns null for empty/falsy raw
    expect(peekCache(CACHE_KEYS.servers, 'any-token')).toBe(false);
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

    expect(localStorage.getItem(CACHE_KEYS.servers)).not.toBeNull();
    expect(localStorage.getItem(CACHE_KEYS.serverTypes)).not.toBeNull();

    clearSwrCache([CACHE_KEYS.servers]);

    expect(localStorage.getItem(CACHE_KEYS.servers)).toBeNull();
    expect(localStorage.getItem(CACHE_KEYS.serverTypes)).not.toBeNull();
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
      expect(localStorage.getItem(key)).toBeNull();
    }
  });
});
