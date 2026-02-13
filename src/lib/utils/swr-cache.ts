// SWR (Stale-While-Revalidate) cache utility for Hetzner API calls
// Pure TypeScript, no Svelte dependency — testable in Node.js

export const CACHE_KEYS = {
  servers: 'devbox_cache_servers',
  serverTypes: 'devbox_cache_server_types',
  locations: 'devbox_cache_locations',
  images: 'devbox_cache_images',
} as const;

interface CacheEntry<T> {
  data: T;
  tokenHash: string;
}

// Simple non-cryptographic hash (djb2)
function hashToken(token: string): string {
  let hash = 5381;
  for (let i = 0; i < token.length; i++) {
    hash = ((hash << 5) + hash + token.charCodeAt(i)) | 0;
  }
  return hash.toString(36);
}

// In-flight request deduplication
const inflight = new Map<string, Promise<unknown>>();

function deduplicatedFetch<T>(key: string, fetcher: () => Promise<T>): Promise<T> {
  const existing = inflight.get(key);
  if (existing) return existing as Promise<T>;

  const promise = fetcher().finally(() => {
    inflight.delete(key);
  });
  inflight.set(key, promise);
  return promise;
}

function readCache<T>(key: string, tokenHash: string): T | null {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    const entry: CacheEntry<T> = JSON.parse(raw);
    if (entry.tokenHash !== tokenHash) return null;
    return entry.data ?? null;
  } catch {
    return null;
  }
}

function writeCache<T>(key: string, data: T, tokenHash: string): void {
  try {
    const entry: CacheEntry<T> = {
      data: JSON.parse(JSON.stringify(data)),
      tokenHash,
    };
    localStorage.setItem(key, JSON.stringify(entry));
  } catch (e) {
    console.warn(`SWR cache write failed for ${key}:`, e);
  }
}

export interface SwrFetchOptions<T> {
  key: string;
  token: string;
  fetcher: () => Promise<T>;
  onData: (data: T) => void;
}

export async function swrFetch<T>(opts: SwrFetchOptions<T>): Promise<void> {
  const { key, token, fetcher, onData } = opts;
  const th = hashToken(token);

  const cached = readCache<T>(key, th);
  if (cached !== null) {
    onData(cached);
  }

  try {
    const fresh = await deduplicatedFetch(`${key}:${th}`, fetcher);
    writeCache(key, fresh, th);
    onData(fresh);
  } catch (e) {
    if (cached !== null) {
      console.warn(`SWR background refresh failed for ${key}:`, e);
      return;
    }
    throw e;
  }
}

export async function backgroundRefresh<T>(opts: SwrFetchOptions<T>): Promise<void> {
  const { key, token, fetcher, onData } = opts;
  const th = hashToken(token);

  try {
    const fresh = await deduplicatedFetch(`${key}:${th}`, fetcher);
    writeCache(key, fresh, th);
    onData(fresh);
  } catch (e) {
    console.warn(`SWR background refresh failed for ${key}:`, e);
  }
}

export function peekCache(key: string, token: string): boolean {
  const th = hashToken(token);
  return readCache(key, th) !== null;
}

export function clearSwrCache(keys?: string[]): void {
  const toRemove = keys ?? Object.values(CACHE_KEYS);
  for (const key of toRemove) {
    localStorage.removeItem(key);
  }
}
