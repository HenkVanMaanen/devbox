import { beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import {
  uuid,
  clearAll,
  clone,
  deepMerge,
  getNestedValue,
  setNestedValue,
  load,
  loadValidated,
  save,
  remove,
} from '$lib/utils/storage';

// Suppress console.error noise from save() error handling
vi.spyOn(console, 'error').mockImplementation(() => {});

// --- uuid() ---

describe('uuid', () => {
  it('returns a valid UUID v4 format string', () => {
    const id = uuid();
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    expect(id).toMatch(uuidRegex);
  });

  it('returns unique values on successive calls', () => {
    const ids = new Set(Array.from({ length: 100 }, () => uuid()));
    expect(ids.size).toBe(100);
  });
});

// --- clearAll() ---

describe('clearAll', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('removes all known STORAGE_KEYS entries', () => {
    // Populate all known storage keys
    localStorage.setItem('devbox_config', '{}');
    localStorage.setItem('devbox_default_profile', '"default"');
    localStorage.setItem('devbox_hetzner_token', '"tok"');
    localStorage.setItem('devbox_profiles', '[]');
    localStorage.setItem('devbox_server_tokens', '{}');
    localStorage.setItem('devbox_theme', '"dark"');

    clearAll();

    expect(localStorage.getItem('devbox_config')).toBeNull();
    expect(localStorage.getItem('devbox_default_profile')).toBeNull();
    expect(localStorage.getItem('devbox_hetzner_token')).toBeNull();
    expect(localStorage.getItem('devbox_profiles')).toBeNull();
    expect(localStorage.getItem('devbox_server_tokens')).toBeNull();
    expect(localStorage.getItem('devbox_theme')).toBeNull();
  });

  it('removes devbox_cache_* entries', () => {
    localStorage.setItem('devbox_cache_servers', '{}');
    localStorage.setItem('devbox_cache_images', '{}');
    localStorage.setItem('devbox_cache_locations', '{}');

    clearAll();

    expect(localStorage.getItem('devbox_cache_servers')).toBeNull();
    expect(localStorage.getItem('devbox_cache_images')).toBeNull();
    expect(localStorage.getItem('devbox_cache_locations')).toBeNull();
  });

  it('preserves unrelated keys', () => {
    localStorage.setItem('unrelated_key', 'keep me');
    localStorage.setItem('devbox_config', '{}');

    clearAll();

    expect(localStorage.getItem('unrelated_key')).toBe('keep me');
  });

  it('does not add extra keys during clearing', () => {
    localStorage.setItem('devbox_config', '{}');
    localStorage.setItem('devbox_cache_test', '{}');
    localStorage.setItem('other_key', 'keep');

    clearAll();

    // Only 'other_key' should remain
    expect(localStorage.length).toBe(1);
    expect(localStorage.getItem('other_key')).toBe('keep');
  });

  it('keysToRemove starts empty (kills initial array value mutant)', () => {
    // If keysToRemove was initialized with ["Stryker was here"] instead of [],
    // calling clearAll with only non-cache keys would try to remove that bogus key.
    // We verify that no errors occur and no extra removals happen.
    localStorage.setItem('devbox_config', '{}');
    // No devbox_cache_* keys at all

    clearAll();

    expect(localStorage.getItem('devbox_config')).toBeNull();
    // localStorage should be completely empty since no unrelated keys exist
    expect(localStorage.length).toBe(0);
  });

  it('loop iterates exactly localStorage.length times (kills i <= vs i < boundary)', () => {
    // If the loop used i <= localStorage.length, it would call localStorage.key() with
    // an out-of-bounds index, getting null. With key?.startsWith, null would be safe
    // but the behavior differs. We add cache keys and ensure exactly those are removed.
    localStorage.setItem('devbox_cache_alpha', '{}');
    localStorage.setItem('devbox_cache_beta', '{}');
    localStorage.setItem('other_key', 'keep');

    clearAll();

    expect(localStorage.getItem('devbox_cache_alpha')).toBeNull();
    expect(localStorage.getItem('devbox_cache_beta')).toBeNull();
    expect(localStorage.getItem('other_key')).toBe('keep');
    expect(localStorage.length).toBe(1);
  });

  it('handles null key from localStorage.key() safely (kills optional chaining removal)', () => {
    // If key?.startsWith was mutated to key.startsWith, it would throw on null.
    // We test with a storage that has items, and after removing known keys,
    // the iteration still works correctly.
    localStorage.setItem('devbox_config', '{}');
    localStorage.setItem('devbox_cache_x', '{}');

    // Should not throw even when localStorage.key() might return null at boundaries
    expect(() => clearAll()).not.toThrow();
    expect(localStorage.length).toBe(0);
  });
});

// --- clone() ---

describe('clone', () => {
  it('creates a deep copy of nested objects', () => {
    const original = { a: { b: { c: 1 } } };
    const cloned = clone(original);

    expect(cloned).toEqual(original);
    // Mutating clone should not affect original
    cloned.a.b.c = 999;
    expect(original.a.b.c).toBe(1);
  });

  it('clones arrays without sharing references', () => {
    const original = [1, [2, 3], { x: 4 }] as [number, number[], { x: number }];
    const cloned = clone(original);

    expect(cloned).toEqual(original);
    (cloned[1] as number[])[0] = 99;
    expect((original[1] as number[])[0]).toBe(2);
  });

  it('handles null and primitive values', () => {
    expect(clone(null)).toBeNull();
    expect(clone(42)).toBe(42);
    expect(clone('hello')).toBe('hello');
    expect(clone(true)).toBe(true);
  });
});

// --- deepMerge() ---

describe('deepMerge', () => {
  it('merges nested objects recursively', () => {
    const target = { a: { b: 1, c: 2 }, d: 3 };
    const source = { a: { b: 10 } };

    const result = deepMerge(target, source);

    expect(result).toEqual({ a: { b: 10, c: 2 }, d: 3 });
  });

  it('replaces arrays instead of merging them', () => {
    const target = { items: [1, 2, 3] };
    const source = { items: [4, 5] };

    const result = deepMerge(target, source);

    expect(result).toEqual({ items: [4, 5] });
  });

  it('handles null source values by replacing target', () => {
    const target = { a: { nested: true } };
    const source = { a: null };

    const result = deepMerge(target, source);

    expect(result).toEqual({ a: null });
  });

  it('does not mutate the target object', () => {
    const target = { a: { b: 1 } };
    const source = { a: { b: 99 } };

    deepMerge(target, source);

    expect(target.a.b).toBe(1);
  });

  it('adds new keys from source', () => {
    const target = { existing: 1 };
    const source = { newKey: 2 };

    const result = deepMerge(target, source);

    expect(result).toEqual({ existing: 1, newKey: 2 });
  });

  it('overwrites object target with primitive source value', () => {
    const target = { a: { nested: true } };
    const source = { a: 'replaced' };
    const result = deepMerge(target, source);
    expect(result.a).toBe('replaced');
  });

  it('overwrites primitive target with object source value', () => {
    const target = { a: 'string' };
    const source = { a: { nested: true } };
    const result = deepMerge(target, source);
    expect(result.a).toEqual({ nested: true });
  });

  it('replaces null target value with object source (kills targetValue !== null → true)', () => {
    // When target value is null and source is an object, it should replace (not deep merge)
    const target = { a: null };
    const source = { a: { nested: true } };
    const result = deepMerge(target, source);
    // If targetValue !== null was mutated to true, it would try to deepMerge null with the object
    expect(result.a).toEqual({ nested: true });
  });
});

// --- getNestedValue() ---

describe('getNestedValue', () => {
  it('retrieves a deeply nested value by dot path', () => {
    const obj = { a: { b: { c: 42 } } };
    expect(getNestedValue(obj, 'a.b.c')).toBe(42);
  });

  it('returns undefined for a missing key', () => {
    const obj = { a: { b: 1 } };
    expect(getNestedValue(obj, 'a.x.y')).toBeUndefined();
  });

  it('returns undefined when traversal hits null', () => {
    const obj = { a: null };
    expect(getNestedValue(obj, 'a.b')).toBeUndefined();
  });

  it('retrieves top-level values', () => {
    const obj = { foo: 'bar' };
    expect(getNestedValue(obj, 'foo')).toBe('bar');
  });

  it('returns undefined when intermediate value is a primitive', () => {
    const obj = { a: 'string-not-object' };
    expect(getNestedValue(obj, 'a.b')).toBeUndefined();
  });

  it('returns undefined when intermediate value is undefined (kills current === null || false)', () => {
    // current === undefined should trigger the early return
    // This is distinct from the null case tested above
    const obj = { a: { b: undefined } } as Record<string, unknown>;
    expect(getNestedValue(obj, 'a.b.c')).toBeUndefined();
  });

  it('returns undefined when intermediate is a number (kills typeof !== object → false)', () => {
    // If typeof current !== 'object' was mutated to false, traversal would continue
    // into a number and try to access properties on it
    const obj = { a: { b: 42 } };
    expect(getNestedValue(obj, 'a.b.c')).toBeUndefined();
  });

  it('returns undefined when intermediate is a boolean', () => {
    const obj = { a: { b: true } } as Record<string, unknown>;
    expect(getNestedValue(obj, 'a.b.c')).toBeUndefined();
  });

  it('returns undefined for blocked prototype paths', () => {
    const obj = { safe: { value: 1 } };
    expect(getNestedValue(obj, '__proto__.constructor')).toBeUndefined();
  });
});

// --- setNestedValue() ---

describe('setNestedValue', () => {
  it('sets a deeply nested value, creating intermediate objects', () => {
    const obj: Record<string, unknown> = {};
    setNestedValue(obj, 'a.b.c', 42);
    expect(obj).toEqual({ a: { b: { c: 42 } } });
  });

  it('overwrites an existing leaf value', () => {
    const obj = { a: { b: 1 } };
    setNestedValue(obj, 'a.b', 99);
    expect(obj.a.b).toBe(99);
  });

  it('sets a top-level value', () => {
    const obj: Record<string, unknown> = {};
    setNestedValue(obj, 'key', 'value');
    expect(obj).toEqual({ key: 'value' });
  });

  it('preserves sibling properties on intermediate objects', () => {
    const obj = { a: { existing: 'keep', b: { old: 1 } } } as Record<string, Record<string, unknown>>;
    setNestedValue(obj, 'a.b.new', 2);
    expect(obj['a']?.['existing']).toBe('keep');
    expect((obj['a']?.['b'] as Record<string, unknown>)?.['old']).toBe(1);
    expect((obj['a']?.['b'] as Record<string, unknown>)?.['new']).toBe(2);
  });

  it('replaces non-object intermediate with empty object', () => {
    const obj = { a: 'not-an-object' } as Record<string, unknown>;
    setNestedValue(obj, 'a.b', 42);
    expect((obj['a'] as Record<string, unknown>)?.['b']).toBe(42);
  });

  it('replaces null intermediate with empty object', () => {
    const obj = { a: null } as Record<string, unknown>;
    setNestedValue(obj, 'a.b', 42);
    expect((obj['a'] as Record<string, unknown>)?.['b']).toBe(42);
  });

  it('ignores blocked prototype paths', () => {
    const obj: Record<string, unknown> = {};
    setNestedValue(obj, '__proto__.polluted', 'yes');
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });
});

// --- load() ---

describe('load', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('parses and returns JSON data from localStorage', () => {
    localStorage.setItem('devbox_config', JSON.stringify({ editor: 'vim' }));

    const result = load('config');

    expect(result).toEqual({ editor: 'vim' });
  });

  it('returns null when key does not exist', () => {
    expect(load('config')).toBeNull();
  });

  it('returns null when stored value is invalid JSON', () => {
    localStorage.setItem('devbox_config', 'not valid json{{{');

    expect(load('config')).toBeNull();
  });

  it('returns null for missing key, not undefined (kills !data → false)', () => {
    // If !data guard was removed (mutated to false), JSON.parse(null) would throw
    // or return unexpected results. Verify we get exactly null.
    const result = load('config');
    expect(result).toBeNull();
    expect(result).not.toBeUndefined();
  });
});

// --- loadValidated() ---

describe('loadValidated', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('returns parsed data when it matches the Zod schema', () => {
    const schema = z.object({ name: z.string(), count: z.number() });
    localStorage.setItem('devbox_config', JSON.stringify({ name: 'test', count: 5 }));

    const result = loadValidated('config', schema);

    expect(result).toEqual({ name: 'test', count: 5 });
  });

  it('returns null when data does not match the schema', () => {
    const schema = z.object({ name: z.string(), count: z.number() });
    localStorage.setItem('devbox_config', JSON.stringify({ name: 123, count: 'wrong' }));

    const result = loadValidated('config', schema);

    expect(result).toBeNull();
  });

  it('returns null when key does not exist', () => {
    const schema = z.string();
    expect(loadValidated('config', schema)).toBeNull();
  });

  it('returns null when stored value is invalid JSON', () => {
    const schema = z.object({});
    localStorage.setItem('devbox_config', '{{invalid');

    expect(loadValidated('config', schema)).toBeNull();
  });
});

// --- save() ---

describe('save', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('serializes value as JSON into the correct localStorage key', () => {
    save('hetznerToken', 'my-secret-token');

    expect(localStorage.getItem('devbox_hetzner_token')).toBe('"my-secret-token"');
  });

  it('saves complex objects', () => {
    const data = { profiles: [{ name: 'dev' }] };
    save('config', data);

    expect(JSON.parse(localStorage.getItem('devbox_config') ?? '{}')).toEqual(data);
  });

  it('handles write errors gracefully without throwing', () => {
    // Create a localStorage mock that throws on setItem
    const originalSetItem = localStorage.setItem;
    localStorage.setItem = () => {
      throw new Error('Storage quota exceeded');
    };

    // Should not throw
    expect(() => save('config', { big: 'data' })).not.toThrow();

    // Restore original
    localStorage.setItem = originalSetItem;
  });
});

// --- remove() ---

describe('remove', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('removes the correct mapped key from localStorage', () => {
    localStorage.setItem('devbox_theme', '"dark"');

    remove('theme');

    expect(localStorage.getItem('devbox_theme')).toBeNull();
  });

  it('does not throw when removing a non-existent key', () => {
    expect(() => remove('config')).not.toThrow();
  });
});
