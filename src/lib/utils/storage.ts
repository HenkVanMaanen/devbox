// localStorage persistence utilities

// Generate UUID with fallback for browsers without crypto.randomUUID
export function uuid(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  // Fallback using crypto.getRandomValues
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- indices 6,8 are always valid in 16-byte array
  bytes[6] = (bytes[6]! & 0x0f) | 0x40; // Version 4
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  bytes[8] = (bytes[8]! & 0x3f) | 0x80; // Variant 1
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

const STORAGE_KEYS = {
  config: 'devbox_config',
  defaultProfile: 'devbox_default_profile',
  hetznerToken: 'devbox_hetzner_token',
  profiles: 'devbox_profiles',
  serverTokens: 'devbox_server_tokens',
  theme: 'devbox_theme',
} as const;

export function clearAll(): void {
  Object.values(STORAGE_KEYS).forEach((key) => {
    localStorage.removeItem(key);
  });
  // Also clear SWR cache entries
  const keysToRemove: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key?.startsWith('devbox_cache_')) {
      keysToRemove.push(key);
    }
  }
  keysToRemove.forEach((key) => {
    localStorage.removeItem(key);
  });
}

// Deep clone utility - uses JSON for compatibility with Svelte 5 reactive proxies
export function clone<T>(value: T): T {
  return structuredClone(value);
}

// Deep merge two objects
export function deepMerge<T>(target: T, source: Partial<T>): T {
  const result = clone(target) as Record<string, unknown>;
  const sourceObj = source as Record<string, unknown>;

  for (const key of Object.keys(sourceObj)) {
    const sourceValue = sourceObj[key];
    const targetValue = result[key];

    result[key] =
      sourceValue !== null &&
      typeof sourceValue === 'object' &&
      !Array.isArray(sourceValue) &&
      targetValue !== null &&
      typeof targetValue === 'object' &&
      !Array.isArray(targetValue)
        ? deepMerge(targetValue as Record<string, unknown>, sourceValue as Record<string, unknown>)
        : clone(sourceValue);
  }

  return result as T;
}

// Get nested value from object by dot-notation path
export function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const keys = path.split('.');
  let current: unknown = obj;

  for (const key of keys) {
    if (current === null || current === undefined || typeof current !== 'object') {
      return undefined;
    }
    current = (current as Record<string, unknown>)[key];
  }

  return current;
}

// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-parameters -- T is used for caller-side type safety
export function load<T>(key: keyof typeof STORAGE_KEYS): null | T {
  try {
    const data = localStorage.getItem(STORAGE_KEYS[key]);
    return data ? (JSON.parse(data) as T) : null;
  } catch {
    return null;
  }
}

export function remove(key: keyof typeof STORAGE_KEYS): void {
  localStorage.removeItem(STORAGE_KEYS[key]);
}

export function save(key: keyof typeof STORAGE_KEYS, value: unknown): void {
  try {
    localStorage.setItem(STORAGE_KEYS[key], JSON.stringify(value));
  } catch (error) {
    console.error(`Failed to save ${key}:`, error);
  }
}

// Set nested value in object by dot-notation path
export function setNestedValue(obj: Record<string, unknown>, path: string, value: unknown): void {
  const keys = path.split('.');
  let current = obj;

  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i];
    if (key === undefined) continue;
    if (!(key in current) || typeof current[key] !== 'object') {
      current[key] = {};
    }
    current = current[key] as Record<string, unknown>;
  }

  const lastKey = keys.at(-1);
  if (lastKey !== undefined) {
    current[lastKey] = value;
  }
}
