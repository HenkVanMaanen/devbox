import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert';

// Mock localStorage before importing the module
const store = {};
globalThis.localStorage = {
  getItem(key) {
    return store[key] ?? null;
  },
  setItem(key, value) {
    store[key] = value;
  },
  removeItem(key) {
    delete store[key];
  },
  clear() {
    for (const k of Object.keys(store)) delete store[k];
  },
  get length() {
    return Object.keys(store).length;
  },
  key(i) {
    return Object.keys(store)[i] ?? null;
  },
};

// Suppress console.error noise from save() error handling
const originalConsoleError = console.error;
console.error = () => {};

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
} from '../src/lib/utils/storage.ts';
import { z } from 'zod';

// --- uuid() ---

describe('uuid', () => {
  it('returns a valid UUID v4 format string', () => {
    const id = uuid();
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    assert.match(id, uuidRegex);
  });

  it('returns unique values on successive calls', () => {
    const ids = new Set(Array.from({ length: 100 }, () => uuid()));
    assert.equal(ids.size, 100);
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

    assert.strictEqual(localStorage.getItem('devbox_config'), null);
    assert.strictEqual(localStorage.getItem('devbox_default_profile'), null);
    assert.strictEqual(localStorage.getItem('devbox_hetzner_token'), null);
    assert.strictEqual(localStorage.getItem('devbox_profiles'), null);
    assert.strictEqual(localStorage.getItem('devbox_server_tokens'), null);
    assert.strictEqual(localStorage.getItem('devbox_theme'), null);
  });

  it('removes devbox_cache_* entries', () => {
    localStorage.setItem('devbox_cache_servers', '{}');
    localStorage.setItem('devbox_cache_images', '{}');
    localStorage.setItem('devbox_cache_locations', '{}');

    clearAll();

    assert.strictEqual(localStorage.getItem('devbox_cache_servers'), null);
    assert.strictEqual(localStorage.getItem('devbox_cache_images'), null);
    assert.strictEqual(localStorage.getItem('devbox_cache_locations'), null);
  });

  it('preserves unrelated keys', () => {
    localStorage.setItem('unrelated_key', 'keep me');
    localStorage.setItem('devbox_config', '{}');

    clearAll();

    assert.equal(localStorage.getItem('unrelated_key'), 'keep me');
  });

  it('does not add extra keys during clearing', () => {
    localStorage.setItem('devbox_config', '{}');
    localStorage.setItem('devbox_cache_test', '{}');
    localStorage.setItem('other_key', 'keep');

    clearAll();

    // Only 'other_key' should remain
    assert.strictEqual(localStorage.length, 1);
    assert.strictEqual(localStorage.getItem('other_key'), 'keep');
  });
});

// --- clone() ---

describe('clone', () => {
  it('creates a deep copy of nested objects', () => {
    const original = { a: { b: { c: 1 } } };
    const cloned = clone(original);

    assert.deepStrictEqual(cloned, original);
    // Mutating clone should not affect original
    cloned.a.b.c = 999;
    assert.equal(original.a.b.c, 1);
  });

  it('clones arrays without sharing references', () => {
    const original = [1, [2, 3], { x: 4 }];
    const cloned = clone(original);

    assert.deepStrictEqual(cloned, original);
    cloned[1][0] = 99;
    assert.equal(original[1][0], 2);
  });

  it('handles null and primitive values', () => {
    assert.equal(clone(null), null);
    assert.equal(clone(42), 42);
    assert.equal(clone('hello'), 'hello');
    assert.equal(clone(true), true);
  });
});

// --- deepMerge() ---

describe('deepMerge', () => {
  it('merges nested objects recursively', () => {
    const target = { a: { b: 1, c: 2 }, d: 3 };
    const source = { a: { b: 10 } };

    const result = deepMerge(target, source);

    assert.deepStrictEqual(result, { a: { b: 10, c: 2 }, d: 3 });
  });

  it('replaces arrays instead of merging them', () => {
    const target = { items: [1, 2, 3] };
    const source = { items: [4, 5] };

    const result = deepMerge(target, source);

    assert.deepStrictEqual(result, { items: [4, 5] });
  });

  it('handles null source values by replacing target', () => {
    const target = { a: { nested: true } };
    const source = { a: null };

    const result = deepMerge(target, source);

    assert.deepStrictEqual(result, { a: null });
  });

  it('does not mutate the target object', () => {
    const target = { a: { b: 1 } };
    const source = { a: { b: 99 } };

    deepMerge(target, source);

    assert.equal(target.a.b, 1);
  });

  it('adds new keys from source', () => {
    const target = { existing: 1 };
    const source = { newKey: 2 };

    const result = deepMerge(target, source);

    assert.deepStrictEqual(result, { existing: 1, newKey: 2 });
  });

  it('overwrites object target with primitive source value', () => {
    const target = { a: { nested: true } };
    const source = { a: 'replaced' };
    const result = deepMerge(target, source);
    assert.strictEqual(result.a, 'replaced');
  });

  it('overwrites primitive target with object source value', () => {
    const target = { a: 'string' };
    const source = { a: { nested: true } };
    const result = deepMerge(target, source);
    assert.deepStrictEqual(result.a, { nested: true });
  });
});

// --- getNestedValue() ---

describe('getNestedValue', () => {
  it('retrieves a deeply nested value by dot path', () => {
    const obj = { a: { b: { c: 42 } } };
    assert.equal(getNestedValue(obj, 'a.b.c'), 42);
  });

  it('returns undefined for a missing key', () => {
    const obj = { a: { b: 1 } };
    assert.equal(getNestedValue(obj, 'a.x.y'), undefined);
  });

  it('returns undefined when traversal hits null', () => {
    const obj = { a: null };
    assert.equal(getNestedValue(obj, 'a.b'), undefined);
  });

  it('retrieves top-level values', () => {
    const obj = { foo: 'bar' };
    assert.equal(getNestedValue(obj, 'foo'), 'bar');
  });

  it('returns undefined when intermediate value is a primitive', () => {
    const obj = { a: 'string-not-object' };
    assert.strictEqual(getNestedValue(obj, 'a.b'), undefined);
  });
});

// --- setNestedValue() ---

describe('setNestedValue', () => {
  it('sets a deeply nested value, creating intermediate objects', () => {
    const obj = {};
    setNestedValue(obj, 'a.b.c', 42);
    assert.deepStrictEqual(obj, { a: { b: { c: 42 } } });
  });

  it('overwrites an existing leaf value', () => {
    const obj = { a: { b: 1 } };
    setNestedValue(obj, 'a.b', 99);
    assert.equal(obj.a.b, 99);
  });

  it('sets a top-level value', () => {
    const obj = {};
    setNestedValue(obj, 'key', 'value');
    assert.deepStrictEqual(obj, { key: 'value' });
  });

  it('preserves sibling properties on intermediate objects', () => {
    const obj = { a: { existing: 'keep', b: { old: 1 } } };
    setNestedValue(obj, 'a.b.new', 2);
    assert.strictEqual(obj.a.existing, 'keep');
    assert.strictEqual(obj.a.b.old, 1);
    assert.strictEqual(obj.a.b.new, 2);
  });

  it('replaces non-object intermediate with empty object', () => {
    const obj = { a: 'not-an-object' };
    setNestedValue(obj, 'a.b', 42);
    assert.strictEqual(obj.a.b, 42);
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

    assert.deepStrictEqual(result, { editor: 'vim' });
  });

  it('returns null when key does not exist', () => {
    assert.strictEqual(load('config'), null);
  });

  it('returns null when stored value is invalid JSON', () => {
    localStorage.setItem('devbox_config', 'not valid json{{{');

    assert.strictEqual(load('config'), null);
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

    assert.deepStrictEqual(result, { name: 'test', count: 5 });
  });

  it('returns null when data does not match the schema', () => {
    const schema = z.object({ name: z.string(), count: z.number() });
    localStorage.setItem('devbox_config', JSON.stringify({ name: 123, count: 'wrong' }));

    const result = loadValidated('config', schema);

    assert.strictEqual(result, null);
  });

  it('returns null when key does not exist', () => {
    const schema = z.string();
    assert.strictEqual(loadValidated('config', schema), null);
  });

  it('returns null when stored value is invalid JSON', () => {
    const schema = z.object({});
    localStorage.setItem('devbox_config', '{{invalid');

    assert.strictEqual(loadValidated('config', schema), null);
  });
});

// --- save() ---

describe('save', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('serializes value as JSON into the correct localStorage key', () => {
    save('hetznerToken', 'my-secret-token');

    assert.equal(localStorage.getItem('devbox_hetzner_token'), '"my-secret-token"');
  });

  it('saves complex objects', () => {
    const data = { profiles: [{ name: 'dev' }] };
    save('config', data);

    assert.deepStrictEqual(JSON.parse(localStorage.getItem('devbox_config')), data);
  });

  it('handles write errors gracefully without throwing', () => {
    // Create a localStorage mock that throws on setItem
    const originalSetItem = localStorage.setItem;
    localStorage.setItem = () => {
      throw new Error('Storage quota exceeded');
    };

    // Should not throw
    assert.doesNotThrow(() => save('config', { big: 'data' }));

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

    assert.strictEqual(localStorage.getItem('devbox_theme'), null);
  });

  it('does not throw when removing a non-existent key', () => {
    assert.doesNotThrow(() => remove('config'));
  });
});
