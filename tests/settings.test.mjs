import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// Mock DOM and localStorage
class MockLocalStorage {
    constructor() { this.store = {}; }
    getItem(key) { return this.store[key] ?? null; }
    setItem(key, value) { this.store[key] = String(value); }
    removeItem(key) { delete this.store[key]; }
    clear() { this.store = {}; }
}
globalThis.localStorage = new MockLocalStorage();
globalThis.window = { matchMedia: () => ({ matches: true, addEventListener: () => {} }) };
globalThis.document = {
    documentElement: { style: { setProperty: () => {} }, classList: { add: () => {}, remove: () => {} } },
    querySelector: () => null,
    createElement: () => ({ name: '' }),
    head: { appendChild: () => {} },
    querySelectorAll: () => [],
    addEventListener: () => {},
    body: { contains: () => true }
};

const { getNestedValue, setNestedValue } = await import('../web/js/storage.js');
const { SETTINGS_SECTIONS, getFieldOptions, formatGlobalValue } = await import('../web/js/settings.js');

describe('settings.js', () => {
    describe('SETTINGS_SECTIONS', () => {
        it('has sections defined', () => {
            assert.ok(SETTINGS_SECTIONS.length >= 7);
        });

        it('each section has required fields', () => {
            for (const section of SETTINGS_SECTIONS) {
                assert.ok(section.id, `Section missing id`);
                assert.ok(section.title, `Section ${section.id} missing title`);
                assert.ok(Array.isArray(section.fields), `Section ${section.id} fields not array`);
            }
        });

        it('each field has path and label', () => {
            for (const section of SETTINGS_SECTIONS) {
                for (const field of section.fields) {
                    assert.ok(field.path, `Field missing path in section ${section.id}`);
                    assert.ok(field.label, `Field ${field.path} missing label`);
                    assert.ok(field.type, `Field ${field.path} missing type`);
                }
            }
        });

        it('no duplicate field paths', () => {
            const paths = SETTINGS_SECTIONS.flatMap(s => s.fields.map(f => f.path));
            const unique = new Set(paths);
            assert.equal(paths.length, unique.size, `Duplicate field paths found: ${paths.filter((p, i) => paths.indexOf(p) !== i)}`);
        });

        it('select fields have options or optionsKey', () => {
            for (const section of SETTINGS_SECTIONS) {
                for (const field of section.fields) {
                    if (field.type === 'select') {
                        assert.ok(field.options || field.optionsKey,
                            `Select field ${field.path} missing options/optionsKey`);
                    }
                }
            }
        });

        it('multiselect fields have optionsKey', () => {
            for (const section of SETTINGS_SECTIONS) {
                for (const field of section.fields) {
                    if (field.type === 'multiselect') {
                        assert.ok(field.optionsKey,
                            `Multiselect field ${field.path} missing optionsKey`);
                    }
                }
            }
        });

        it('showWhen references valid paths', () => {
            const allPaths = new Set(SETTINGS_SECTIONS.flatMap(s => s.fields.map(f => f.path)));
            for (const section of SETTINGS_SECTIONS) {
                for (const field of section.fields) {
                    if (field.showWhen) {
                        assert.ok(allPaths.has(field.showWhen.path),
                            `Field ${field.path} showWhen references invalid path: ${field.showWhen.path}`);
                    }
                }
            }
        });
    });

    describe('getNestedValue', () => {
        it('gets top-level value', () => {
            assert.equal(getNestedValue({ a: 1 }, 'a'), 1);
        });

        it('gets nested value', () => {
            assert.equal(getNestedValue({ a: { b: { c: 3 } } }, 'a.b.c'), 3);
        });

        it('returns undefined for missing path', () => {
            assert.equal(getNestedValue({ a: 1 }, 'b'), undefined);
        });

        it('returns undefined for deep missing path', () => {
            assert.equal(getNestedValue({ a: { b: 1 } }, 'a.c.d'), undefined);
        });

        it('handles array values', () => {
            assert.deepEqual(getNestedValue({ a: [1, 2, 3] }, 'a'), [1, 2, 3]);
        });
    });

    describe('setNestedValue', () => {
        it('sets top-level value', () => {
            const obj = {};
            setNestedValue(obj, 'a', 1);
            assert.equal(obj.a, 1);
        });

        it('sets nested value', () => {
            const obj = { a: {} };
            setNestedValue(obj, 'a.b', 2);
            assert.equal(obj.a.b, 2);
        });

        it('creates intermediate objects', () => {
            const obj = {};
            setNestedValue(obj, 'a.b.c', 3);
            assert.equal(obj.a.b.c, 3);
        });

        it('overwrites existing value', () => {
            const obj = { a: { b: 1 } };
            setNestedValue(obj, 'a.b', 2);
            assert.equal(obj.a.b, 2);
        });
    });

    describe('formatGlobalValue', () => {
        it('formats arrays', () => {
            assert.equal(formatGlobalValue(['a', 'b', 'c']), 'a, b, c');
        });

        it('truncates long arrays', () => {
            const result = formatGlobalValue(['a', 'b', 'c', 'd']);
            assert.ok(result.includes('...'));
        });

        it('formats empty array', () => {
            assert.equal(formatGlobalValue([]), '(empty)');
        });

        it('formats true', () => {
            assert.equal(formatGlobalValue(true), 'Yes');
        });

        it('formats false', () => {
            assert.equal(formatGlobalValue(false), 'No');
        });

        it('formats empty string', () => {
            assert.equal(formatGlobalValue(''), '(empty)');
        });

        it('formats null', () => {
            assert.equal(formatGlobalValue(null), '(empty)');
        });

        it('formats string value', () => {
            assert.equal(formatGlobalValue('hello'), 'hello');
        });

        it('escapes HTML in strings', () => {
            assert.equal(formatGlobalValue('<script>'), '&lt;script&gt;');
        });
    });

    describe('getFieldOptions', () => {
        it('returns apt packages', () => {
            const options = getFieldOptions('aptPackages', {});
            assert.ok(options.length > 50);
            assert.ok(options[0].value);
            assert.ok(options[0].label);
        });

        it('returns mise tools with versions', () => {
            const options = getFieldOptions('miseTools', {});
            assert.ok(options.length > 10);
            assert.ok(options[0].value.includes('@'));
        });

        it('returns empty array for unknown key', () => {
            assert.deepEqual(getFieldOptions('unknown', {}), []);
        });
    });
});
