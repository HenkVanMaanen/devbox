import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// Mock localStorage
class MockLocalStorage {
    constructor() { this.store = {}; }
    getItem(key) { return this.store[key] ?? null; }
    setItem(key, value) { this.store[key] = String(value); }
    removeItem(key) { delete this.store[key]; }
    clear() { this.store = {}; }
}

globalThis.localStorage = new MockLocalStorage();
// crypto.getRandomValues is available natively in Node 24

const storage = await import('../web/js/storage.js');

describe('storage.js', () => {
    beforeEach(() => {
        localStorage.clear();
    });

    describe('getGlobalConfig', () => {
        it('returns default config when nothing stored', () => {
            const config = storage.getGlobalConfig();
            assert.equal(config.hetzner.location, 'fsn1');
            assert.equal(config.hetzner.serverType, 'cpx21');
            assert.equal(config.shell.default, 'fish');
            assert.equal(config.autoDelete.enabled, true);
            assert.equal(config.autoDelete.timeoutMinutes, 90);
            assert.deepEqual(config.ssh.keys, []);
            assert.deepEqual(config.git.credentials, []);
        });

        it('merges stored config with defaults', () => {
            localStorage.setItem('devbox:global', JSON.stringify({
                hetzner: { location: 'nbg1' }
            }));
            const config = storage.getGlobalConfig();
            assert.equal(config.hetzner.location, 'nbg1');
            assert.equal(config.hetzner.serverType, 'cpx21'); // default preserved
            assert.equal(config.shell.default, 'fish'); // other sections preserved
        });

        it('handles arrays correctly (no merge, replace)', () => {
            localStorage.setItem('devbox:global', JSON.stringify({
                packages: { apt: ['vim'] }
            }));
            const config = storage.getGlobalConfig();
            assert.deepEqual(config.packages.apt, ['vim']); // replaced, not merged
        });

        it('handles corrupted JSON gracefully', () => {
            localStorage.setItem('devbox:global', 'not valid json{{{');
            const config = storage.getGlobalConfig();
            // Should return defaults instead of crashing
            assert.equal(config.hetzner.location, 'fsn1');
        });
    });

    describe('getProfiles - error handling', () => {
        it('handles corrupted profiles JSON', () => {
            localStorage.setItem('devbox:profiles', 'corrupted');
            const profiles = storage.getProfiles();
            assert.ok(profiles.default); // falls back to defaults
        });
    });

    describe('saveGlobalConfig', () => {
        it('stores config as JSON', () => {
            storage.saveGlobalConfig({ hetzner: { location: 'nbg1' } });
            const stored = JSON.parse(localStorage.getItem('devbox:global'));
            assert.equal(stored.hetzner.location, 'nbg1');
        });
    });

    describe('getProfiles / saveProfiles', () => {
        it('returns default profiles when nothing stored', () => {
            const profiles = storage.getProfiles();
            assert.ok(profiles.default);
            assert.equal(profiles.default.name, 'Default');
        });

        it('round-trips profiles', () => {
            const p = { test: { name: 'Test', overrides: { 'hetzner.location': 'nbg1' } } };
            storage.saveProfiles(p);
            const result = storage.getProfiles();
            assert.deepEqual(result, p);
        });
    });

    describe('createProfile', () => {
        it('creates profile with kebab-case id', () => {
            const id = storage.createProfile('My Test Profile');
            assert.equal(id, 'my-test-profile');
            const profiles = storage.getProfiles();
            assert.equal(profiles[id].name, 'My Test Profile');
            assert.deepEqual(profiles[id].overrides, {});
        });

        it('handles duplicate names with counter', () => {
            storage.createProfile('Test');
            const id2 = storage.createProfile('Test');
            assert.equal(id2, 'test-1');
        });

        it('strips special characters and trims dashes', () => {
            const id = storage.createProfile('Hello World!@#$%');
            assert.equal(id, 'hello-world');
        });

        it('uses fallback id for non-ASCII names', () => {
            const id = storage.createProfile('\u4f60\u597d');
            assert.equal(id, 'profile');
        });
    });

    describe('deleteProfile', () => {
        it('cannot delete default profile', () => {
            const result = storage.deleteProfile('default');
            assert.equal(result, false);
        });

        it('deletes non-default profile', () => {
            storage.createProfile('deleteme');
            const result = storage.deleteProfile('deleteme');
            assert.equal(result, true);
            assert.equal(storage.getProfile('deleteme'), null);
        });

        it('resets default profile name if deleted profile was default', () => {
            const id = storage.createProfile('temp');
            storage.setDefaultProfileId(id);
            storage.deleteProfile(id);
            assert.equal(storage.getDefaultProfileId(), 'default');
        });

        it('returns false for non-existent profile', () => {
            assert.equal(storage.deleteProfile('nonexistent'), false);
        });
    });

    describe('duplicateProfile', () => {
        it('duplicates profile overrides', () => {
            storage.createProfile('source');
            storage.saveProfile('source', { name: 'Source', overrides: { 'hetzner.location': 'nbg1' } });
            const newId = storage.duplicateProfile('source', 'Copy');
            const newProfile = storage.getProfile(newId);
            assert.equal(newProfile.overrides['hetzner.location'], 'nbg1');
        });

        it('returns null for non-existent source', () => {
            assert.equal(storage.duplicateProfile('nonexistent', 'Copy'), null);
        });

        it('deep copies overrides (no reference sharing)', () => {
            storage.saveProfile('src', { name: 'Src', overrides: { nested: { a: 1 } } });
            const newId = storage.duplicateProfile('src', 'Dst');
            const src = storage.getProfile('src');
            const dst = storage.getProfile(newId);
            dst.overrides.nested.a = 99;
            // Original should not be affected
            assert.equal(src.overrides.nested.a, 1);
        });
    });

    describe('getConfigForProfile', () => {
        it('generates access token', () => {
            const config = storage.getConfigForProfile('default');
            assert.ok(config.services.accessToken);
            assert.equal(config.services.accessToken.length, 32); // 16 bytes = 32 hex chars
        });

        it('generates fresh token each call', () => {
            const c1 = storage.getConfigForProfile('default');
            const c2 = storage.getConfigForProfile('default');
            assert.notEqual(c1.services.accessToken, c2.services.accessToken);
        });

        it('applies profile overrides', () => {
            storage.saveProfile('custom', {
                name: 'Custom',
                overrides: { 'hetzner.location': 'hel1', 'autoDelete.timeoutMinutes': 30 }
            });
            const config = storage.getConfigForProfile('custom');
            assert.equal(config.hetzner.location, 'hel1');
            assert.equal(config.autoDelete.timeoutMinutes, 30);
        });

        it('returns global config for non-existent profile', () => {
            const config = storage.getConfigForProfile('nonexistent');
            assert.equal(config.hetzner.location, 'fsn1');
        });
    });

    describe('Hetzner token', () => {
        it('get/save Hetzner token', () => {
            assert.equal(storage.getHetznerToken(), '');
            storage.saveHetznerToken('mytoken');
            assert.equal(storage.getHetznerToken(), 'mytoken');
        });

        it('removes token when saved as empty', () => {
            storage.saveHetznerToken('mytoken');
            storage.saveHetznerToken('');
            assert.equal(storage.getHetznerToken(), '');
        });
    });

    describe('theme', () => {
        it('defaults to system', () => {
            assert.equal(storage.getTheme(), 'system');
        });

        it('saves and retrieves theme', () => {
            storage.saveTheme('nord-dark');
            assert.equal(storage.getTheme(), 'nord-dark');
        });

        it('removes storage when set to system', () => {
            storage.saveTheme('nord-dark');
            storage.saveTheme('system');
            assert.equal(localStorage.getItem('devbox:theme'), null);
        });
    });

    describe('exportAll / importAll', () => {
        it('round-trips all data', () => {
            storage.saveHetznerToken('token123');
            storage.saveTheme('dracula-dark');
            storage.saveGlobalConfig({
                hetzner: { location: 'nbg1' },
                ssh: { keys: [{ name: 'work', pubKey: 'ssh-ed25519 AAAA' }] },
                git: { userName: '', userEmail: '', credentials: [{ host: 'github.com', username: 'user', token: 'pass' }] }
            });

            const exported = storage.exportAll();
            localStorage.clear();

            storage.importAll(exported);
            assert.equal(storage.getHetznerToken(), 'token123');
            assert.equal(storage.getTheme(), 'dracula-dark');
            const config = storage.getGlobalConfig();
            assert.equal(config.ssh.keys[0].pubKey, 'ssh-ed25519 AAAA');
            assert.equal(config.ssh.keys[0].name, 'work');
            assert.equal(config.git.credentials[0].host, 'github.com');
        });

        it('handles partial import', () => {
            storage.importAll({ hetznerToken: 'abc' });
            assert.equal(storage.getHetznerToken(), 'abc');
        });
    });

    describe('clearAll', () => {
        it('removes all keys', () => {
            storage.saveHetznerToken('token');
            storage.saveTheme('nord-dark');
            storage.clearAll();
            assert.equal(storage.getHetznerToken(), '');
            assert.equal(storage.getTheme(), 'system');
        });
    });

    describe('default profile id', () => {
        it('defaults to "default"', () => {
            assert.equal(storage.getDefaultProfileId(), 'default');
        });

        it('can be changed', () => {
            storage.setDefaultProfileId('custom');
            assert.equal(storage.getDefaultProfileId(), 'custom');
        });
    });

    describe('server tokens', () => {
        it('returns empty object by default', () => {
            assert.deepEqual(storage.getServerTokens(), {});
        });

        it('saves and retrieves a token', () => {
            storage.saveServerToken('devbox-abc', 'token123');
            assert.equal(storage.getServerToken('devbox-abc'), 'token123');
        });

        it('returns null for unknown server', () => {
            assert.equal(storage.getServerToken('unknown'), null);
        });

        it('removes a token', () => {
            storage.saveServerToken('devbox-xyz', 'tokenxyz');
            storage.removeServerToken('devbox-xyz');
            assert.equal(storage.getServerToken('devbox-xyz'), null);
        });

        it('clearAll removes server tokens', () => {
            storage.saveServerToken('devbox-test', 'tok');
            storage.clearAll();
            assert.deepEqual(storage.getServerTokens(), {});
        });
    });
});
