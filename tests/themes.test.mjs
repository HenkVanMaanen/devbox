import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// Mock DOM APIs
globalThis.window = { matchMedia: (q) => ({ matches: q.includes('dark'), addEventListener: () => {} }) };
globalThis.document = {
    documentElement: {
        style: { properties: {}, setProperty(k, v) { this.properties[k] = v; } },
        classList: { classes: new Set(), add(c) { this.classes.add(c); }, remove(c) { this.classes.delete(c); }, has(c) { return this.classes.has(c); } }
    },
    querySelector: () => null,
    createElement: (tag) => ({ name: '', content: '' }),
    head: { appendChild: () => {} }
};

const { THEMES, THEME_FAMILIES, getTheme, applyTheme, getSystemPreference, getDefaultTheme, generateThemeCSS } = await import('../web/js/themes.js');

describe('themes.js', () => {
    describe('THEMES', () => {
        it('has themes defined', () => {
            assert.ok(THEMES.length >= 10);
        });

        it('each theme has required fields', () => {
            for (const theme of THEMES) {
                assert.ok(theme.id, `Theme missing id`);
                assert.ok(theme.name, `Theme ${theme.id} missing name`);
                assert.ok(['dark', 'light'].includes(theme.mode), `Theme ${theme.id} has invalid mode`);
                assert.ok(theme.colors, `Theme ${theme.id} missing colors`);
            }
        });

        it('no duplicate theme IDs', () => {
            const ids = THEMES.map(t => t.id);
            const unique = new Set(ids);
            assert.equal(ids.length, unique.size);
        });

        it('each theme has all required color keys', () => {
            const requiredColors = [
                'background', 'foreground', 'card', 'cardForeground',
                'muted', 'mutedForeground', 'mutedHover', 'border',
                'input', 'primary', 'primaryHover', 'primaryForeground',
                'focus', 'destructive', 'destructiveHover', 'destructiveForeground',
                'success', 'successForeground', 'warning', 'warningForeground', 'placeholder'
            ];
            for (const theme of THEMES) {
                for (const key of requiredColors) {
                    assert.ok(theme.colors[key],
                        `Theme ${theme.id} missing color: ${key}`);
                }
            }
        });

        it('all colors are valid hex values', () => {
            const hexPattern = /^#[0-9a-fA-F]{6}$/;
            for (const theme of THEMES) {
                for (const [key, value] of Object.entries(theme.colors)) {
                    assert.ok(hexPattern.test(value),
                        `Theme ${theme.id} color ${key} invalid: ${value}`);
                }
            }
        });

        it('has equal number of dark and light themes', () => {
            const dark = THEMES.filter(t => t.mode === 'dark');
            const light = THEMES.filter(t => t.mode === 'light');
            assert.equal(dark.length, light.length);
        });
    });

    describe('THEME_FAMILIES', () => {
        it('has families defined', () => {
            assert.ok(THEME_FAMILIES.length >= 5);
        });

        it('each family references valid theme IDs', () => {
            const validIds = new Set(THEMES.map(t => t.id));
            for (const family of THEME_FAMILIES) {
                for (const themeId of family.themes) {
                    assert.ok(validIds.has(themeId),
                        `Family ${family.name} references invalid theme: ${themeId}`);
                }
            }
        });

        it('each family has exactly 2 themes (dark + light)', () => {
            for (const family of THEME_FAMILIES) {
                assert.equal(family.themes.length, 2,
                    `Family ${family.name} should have 2 themes`);
            }
        });

        it('all themes belong to a family', () => {
            const familyThemes = new Set(THEME_FAMILIES.flatMap(f => f.themes));
            for (const theme of THEMES) {
                assert.ok(familyThemes.has(theme.id),
                    `Theme ${theme.id} not in any family`);
            }
        });
    });

    describe('getTheme', () => {
        it('returns theme by ID', () => {
            const theme = getTheme('default-dark');
            assert.equal(theme.id, 'default-dark');
            assert.equal(theme.mode, 'dark');
        });

        it('returns undefined for invalid ID', () => {
            assert.equal(getTheme('nonexistent'), undefined);
        });

        it('returns all themes by their IDs', () => {
            for (const theme of THEMES) {
                const found = getTheme(theme.id);
                assert.equal(found.id, theme.id);
            }
        });
    });

    describe('applyTheme', () => {
        it('sets CSS custom properties', () => {
            const doc = globalThis.document.documentElement;
            doc.style.properties = {};
            applyTheme('default-dark');
            assert.equal(doc.style.properties['--color-background'], '#0a0a0b');
            assert.equal(doc.style.properties['--color-foreground'], '#f5f5f5');
            assert.equal(doc.style.properties['--color-primary'], '#60a5fa');
        });

        it('adds dark class for dark themes', () => {
            const doc = globalThis.document.documentElement;
            doc.classList.classes = new Set();
            applyTheme('default-dark');
            assert.ok(doc.classList.has('dark'));
        });

        it('removes dark class for light themes', () => {
            const doc = globalThis.document.documentElement;
            doc.classList.classes = new Set(['dark']);
            applyTheme('default-light');
            assert.ok(!doc.classList.has('dark'));
        });

        it('does nothing for invalid theme ID', () => {
            const doc = globalThis.document.documentElement;
            doc.style.properties = {};
            applyTheme('nonexistent');
            assert.deepEqual(doc.style.properties, {});
        });

        it('converts camelCase to kebab-case for CSS vars', () => {
            const doc = globalThis.document.documentElement;
            doc.style.properties = {};
            applyTheme('default-dark');
            assert.ok('--color-card-foreground' in doc.style.properties);
            assert.ok('--color-muted-foreground' in doc.style.properties);
            assert.ok('--color-primary-hover' in doc.style.properties);
        });
    });

    describe('getSystemPreference', () => {
        it('returns dark when prefers-color-scheme is dark', () => {
            assert.equal(getSystemPreference(), 'dark');
        });

        it('returns light when prefers-color-scheme is light', () => {
            globalThis.window.matchMedia = (q) => ({ matches: false, addEventListener: () => {} });
            assert.equal(getSystemPreference(), 'light');
            // Reset
            globalThis.window.matchMedia = (q) => ({ matches: q.includes('dark'), addEventListener: () => {} });
        });
    });

    describe('getDefaultTheme', () => {
        it('returns default-dark for dark system preference', () => {
            assert.equal(getDefaultTheme(), 'default-dark');
        });

        it('returns default-light for light system preference', () => {
            globalThis.window.matchMedia = () => ({ matches: false, addEventListener: () => {} });
            assert.equal(getDefaultTheme(), 'default-light');
            globalThis.window.matchMedia = (q) => ({ matches: q.includes('dark'), addEventListener: () => {} });
        });
    });

    describe('generateThemeCSS', () => {
        it('generates CSS with custom properties', () => {
            const css = generateThemeCSS('default-dark');
            assert.ok(css.includes(':root{'));
            assert.ok(css.includes('--color-background:#0a0a0b'));
            assert.ok(css.includes('--color-foreground:#f5f5f5'));
        });

        it('returns empty string for invalid theme', () => {
            assert.equal(generateThemeCSS('nonexistent'), '');
        });

        it('uses kebab-case for property names', () => {
            const css = generateThemeCSS('default-dark');
            assert.ok(css.includes('--color-card-foreground'));
            assert.ok(css.includes('--color-muted-foreground'));
            assert.ok(!css.includes('cardForeground'));
        });
    });
});
