// localStorage persistence utilities

import type { ZodType } from 'zod';

import { isSafeObjectPath, parseObjectPath } from '$lib/utils/path-safety';

export function uuid(): string {
  return crypto.randomUUID();
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

export function clone<T>(value: T): T {
  // Use JSON round-trip instead of structuredClone because Svelte 5's
  // $state creates Proxy objects that structuredClone cannot handle
  // eslint-disable-next-line unicorn/prefer-structured-clone -- structuredClone fails on Svelte 5 proxies
  return JSON.parse(JSON.stringify(value)) as T;
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
  if (!isSafeObjectPath(path)) {
    return undefined;
  }

  const keys = parseObjectPath(path);
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

export function loadValidated<T>(key: keyof typeof STORAGE_KEYS, schema: ZodType<T>): null | T {
  try {
    const data = localStorage.getItem(STORAGE_KEYS[key]);
    if (!data) return null;
    const result = schema.safeParse(JSON.parse(data));
    return result.success ? result.data : null;
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
    // Stryker disable all
    console.error(`Failed to save ${key}:`, error);
    // Stryker restore all
  }
}

// Set nested value in object by dot-notation path
export function setNestedValue(obj: Record<string, unknown>, path: string, value: unknown): void {
  if (!isSafeObjectPath(path)) {
    return;
  }

  const keys = parseObjectPath(path);
  let current = obj;

  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i];
    if (key === undefined) continue;
    const next = current[key];
    if (next === null || typeof next !== 'object' || Array.isArray(next)) {
      current[key] = {};
    }
    current = current[key] as Record<string, unknown>;
  }

  const lastKey = keys.at(-1);
  if (lastKey !== undefined) {
    current[lastKey] = value;
  }
}
