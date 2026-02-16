// SWR (Stale-While-Revalidate) cache utility for Hetzner API calls
// Pure TypeScript, no Svelte dependency — testable in Node.js

export const CACHE_KEYS = {
  images: 'devbox_cache_images',
  locations: 'devbox_cache_locations',
  servers: 'devbox_cache_servers',
  serverTypes: 'devbox_cache_server_types',
} as const;

interface CacheEntry<T> {
  data: T;
  tokenHash: string;
}

// Simple non-cryptographic hash (djb2)
function hashToken(token: string): string {
  let hash = 5381;
  for (let i = 0; i < token.length; i++) {
    hash = Math.trunc((hash << 5) + hash + (token.codePointAt(i) ?? 0));
  }
  return hash.toString(36);
}

// In-flight request deduplication
const inflight = new Map<string, Promise<unknown>>();

export interface SwrFetchOptions<T> {
  fetcher: () => Promise<T>;
  key: string;
  onData: (data: T) => void;
  token: string;
}

export async function backgroundRefresh<T>(opts: SwrFetchOptions<T>): Promise<void> {
  const { fetcher, key, onData, token } = opts;
  const th = hashToken(token);

  try {
    // Stryker disable next-line all
    const fresh = await deduplicatedFetch(`${key}:${th}`, fetcher);
    writeCache(key, fresh, th);
    onData(fresh);
  } catch (error) {
    // Stryker disable all
    console.warn(`SWR background refresh failed for ${key}:`, error);
    // Stryker restore all
  }
}

export function clearSwrCache(keys?: string[]): void {
  const toRemove = keys ?? Object.values(CACHE_KEYS);
  for (const key of toRemove) {
    localStorage.removeItem(key);
  }
}

export function peekCache(key: string, token: string): boolean {
  const th = hashToken(token);
  return readCache(key, th) !== null;
}

export async function swrFetch<T>(opts: SwrFetchOptions<T>): Promise<void> {
  const { fetcher, key, onData, token } = opts;
  const th = hashToken(token);

  const cached = readCache(key, th) as null | T;
  if (cached !== null) {
    onData(cached);
  }

  try {
    // Stryker disable next-line all
    const fresh = await deduplicatedFetch(`${key}:${th}`, fetcher);
    writeCache(key, fresh, th);
    onData(fresh);
  } catch (error) {
    if (cached !== null) {
      // Stryker disable all
      console.warn(`SWR background refresh failed for ${key}:`, error);
      // Stryker restore all
      return;
    }
    throw error;
  }
}

function deduplicatedFetch<T>(key: string, fetcher: () => Promise<T>): Promise<T> {
  const existing = inflight.get(key);
  if (existing) return existing as Promise<T>;

  const promise = fetcher().finally(() => {
    inflight.delete(key);
  });
  inflight.set(key, promise);
  return promise;
}

function readCache(key: string, tokenHash: string): unknown {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    const entry = JSON.parse(raw) as CacheEntry<unknown>;
    if (entry.tokenHash !== tokenHash) return null;
    return entry.data ?? null;
  } catch {
    // Stryker disable all
    return null;
    // Stryker restore all
  }
}

function writeCache(key: string, data: unknown, tokenHash: string): void {
  try {
    const entry: CacheEntry<unknown> = {
      data: structuredClone(data),
      tokenHash,
    };
    localStorage.setItem(key, JSON.stringify(entry));
  } catch (error) {
    // Stryker disable all
    console.warn(`SWR cache write failed for ${key}:`, error);
    // Stryker restore all
  }
}
