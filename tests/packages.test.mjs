import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { APT_PACKAGES, APT_CATEGORIES, APT_CATEGORY_LABELS, MISE_TOOLS, getPackagesByCategory } from '../src/lib/data/packages.ts';

describe('packages.ts', () => {
    describe('APT_PACKAGES', () => {
        it('has packages defined', () => {
            assert.ok(APT_PACKAGES.length > 50);
        });

        it('each package has required fields', () => {
            for (const pkg of APT_PACKAGES) {
                assert.ok(pkg.name, `Package missing name`);
                assert.ok(pkg.category, `Package ${pkg.name} missing category`);
                assert.ok(pkg.description, `Package ${pkg.name} missing description`);
            }
        });

        it('all categories in packages are valid', () => {
            const validCats = new Set(APT_CATEGORIES);
            for (const pkg of APT_PACKAGES) {
                assert.ok(validCats.has(pkg.category),
                    `Package ${pkg.name} has invalid category: ${pkg.category}`);
            }
        });

        it('no duplicate package names', () => {
            const names = APT_PACKAGES.map(p => p.name);
            const unique = new Set(names);
            assert.equal(names.length, unique.size, 'Duplicate package names found');
        });

        it('includes essential packages', () => {
            const names = APT_PACKAGES.map(p => p.name);
            assert.ok(names.includes('git'));
            assert.ok(names.includes('curl'));
            assert.ok(names.includes('build-essential'));
            assert.ok(names.includes('python3'));
            assert.ok(names.includes('vim'));
        });
    });

    describe('APT_CATEGORIES', () => {
        it('has categories defined', () => {
            assert.ok(APT_CATEGORIES.length >= 5);
        });

        it('no duplicate categories', () => {
            const unique = new Set(APT_CATEGORIES);
            assert.equal(APT_CATEGORIES.length, unique.size);
        });

        it('all categories have labels', () => {
            for (const cat of APT_CATEGORIES) {
                assert.ok(APT_CATEGORY_LABELS[cat], `Category ${cat} missing label`);
            }
        });
    });

    describe('MISE_TOOLS', () => {
        it('has tools defined', () => {
            assert.ok(MISE_TOOLS.length >= 5);
        });

        it('each tool has required fields', () => {
            for (const tool of MISE_TOOLS) {
                assert.ok(tool.name, 'Tool missing name');
                assert.ok(Array.isArray(tool.versions), `Tool ${tool.name} versions not array`);
                assert.ok(tool.versions.length > 0, `Tool ${tool.name} has no versions`);
                assert.ok(tool.description, `Tool ${tool.name} missing description`);
            }
        });

        it('no duplicate tool names', () => {
            const names = MISE_TOOLS.map(t => t.name);
            const unique = new Set(names);
            assert.equal(names.length, unique.size);
        });

        it('includes common runtimes', () => {
            const names = MISE_TOOLS.map(t => t.name);
            assert.ok(names.includes('node'));
            assert.ok(names.includes('python'));
            assert.ok(names.includes('go'));
            assert.ok(names.includes('rust'));
        });
    });

    describe('getPackagesByCategory', () => {
        it('returns object with all categories', () => {
            const grouped = getPackagesByCategory();
            for (const cat of APT_CATEGORIES) {
                assert.ok(Array.isArray(grouped[cat]), `Missing category: ${cat}`);
            }
        });

        it('each package appears in correct category', () => {
            const grouped = getPackagesByCategory();
            for (const pkg of APT_PACKAGES) {
                const categoryPackages = grouped[pkg.category];
                assert.ok(categoryPackages.some(p => p.name === pkg.name),
                    `Package ${pkg.name} not in category ${pkg.category}`);
            }
        });

        it('total packages in groups equals total packages', () => {
            const grouped = getPackagesByCategory();
            const total = Object.values(grouped).reduce((sum, arr) => sum + arr.length, 0);
            assert.equal(total, APT_PACKAGES.length);
        });

        it('no empty categories', () => {
            const grouped = getPackagesByCategory();
            for (const cat of APT_CATEGORIES) {
                assert.ok(grouped[cat].length > 0, `Category ${cat} is empty`);
            }
        });
    });
});
