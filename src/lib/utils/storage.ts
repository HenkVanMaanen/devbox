// localStorage persistence utilities

const STORAGE_KEYS = {
  config: 'devbox_config',
  profiles: 'devbox_profiles',
  defaultProfile: 'devbox_default_profile',
  hetznerToken: 'devbox_hetzner_token',
  serverTokens: 'devbox_server_tokens',
  theme: 'devbox_theme',
} as const;

export function load<T>(key: keyof typeof STORAGE_KEYS): T | null {
  try {
    const data = localStorage.getItem(STORAGE_KEYS[key]);
    return data ? JSON.parse(data) : null;
  } catch {
    return null;
  }
}

export function save<T>(key: keyof typeof STORAGE_KEYS, value: T): void {
  try {
    localStorage.setItem(STORAGE_KEYS[key], JSON.stringify(value));
  } catch (e) {
    console.error(`Failed to save ${key}:`, e);
  }
}

export function remove(key: keyof typeof STORAGE_KEYS): void {
  localStorage.removeItem(STORAGE_KEYS[key]);
}

export function clearAll(): void {
  Object.values(STORAGE_KEYS).forEach(key => localStorage.removeItem(key));
}

// Deep clone utility using structuredClone
export function clone<T>(value: T): T {
  return structuredClone(value);
}

// Get nested value from object by dot-notation path
export function getNestedValue<T>(obj: Record<string, unknown>, path: string): T | undefined {
  const keys = path.split('.');
  let current: unknown = obj;

  for (const key of keys) {
    if (current === null || current === undefined || typeof current !== 'object') {
      return undefined;
    }
    current = (current as Record<string, unknown>)[key];
  }

  return current as T;
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

  const lastKey = keys[keys.length - 1];
  if (lastKey !== undefined) {
    current[lastKey] = value;
  }
}

// Deep merge two objects
export function deepMerge<T>(target: T, source: Partial<T>): T {
  const result = clone(target) as Record<string, unknown>;
  const sourceObj = source as Record<string, unknown>;

  for (const key of Object.keys(sourceObj)) {
    const sourceValue = sourceObj[key];
    const targetValue = result[key];

    if (
      sourceValue !== null &&
      typeof sourceValue === 'object' &&
      !Array.isArray(sourceValue) &&
      targetValue !== null &&
      typeof targetValue === 'object' &&
      !Array.isArray(targetValue)
    ) {
      result[key] = deepMerge(
        targetValue as Record<string, unknown>,
        sourceValue as Record<string, unknown>
      );
    } else {
      result[key] = clone(sourceValue);
    }
  }

  return result as T;
}
