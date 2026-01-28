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

// Mock DOM
let mockElements = {};
let toastMessages = [];
globalThis.document = {
    getElementById: (id) => mockElements[id] || null,
    querySelectorAll: () => [],
    querySelector: () => null,
    documentElement: { style: { setProperty: () => {} }, classList: { add: () => {}, remove: () => {} } },
    createElement: () => ({ name: '' }),
    head: { appendChild: () => {} },
    addEventListener: () => {},
    body: { contains: () => true }
};
globalThis.window = {
    matchMedia: () => ({ matches: true, addEventListener: () => {} }),
    devbox: {}
};

const { state, setState, setRenderCallback } = await import('../web/js/state.js');
const storage = await import('../web/js/storage.js');
const {
    addCustomPackage, addCustomPackageToProfile, toggleComboboxValue,
    addListItem, removeListItem,
    addGitCredentialToConfig, removeGitCredentialFromConfig,
    addGitCredentialToProfile, removeGitCredentialFromProfile
} = await import('../web/js/handlers.js');

describe('handlers.js', () => {
    let renderCalled;

    beforeEach(() => {
        localStorage.clear();
        mockElements = {};
        toastMessages = [];
        renderCalled = false;
        setRenderCallback(() => { renderCalled = true; });
    });

    describe('toggleComboboxValue', () => {
        it('adds apt package to global config', () => {
            storage.saveGlobalConfig({ ...storage.getGlobalConfig(), packages: { apt: ['git'], mise: [] } });
            toggleComboboxValue('packages-apt', 'curl', true);
            const config = storage.getGlobalConfig();
            assert.ok(config.packages.apt.includes('curl'));
        });

        it('removes apt package from global config', () => {
            storage.saveGlobalConfig({ ...storage.getGlobalConfig(), packages: { apt: ['git', 'curl'], mise: [] } });
            toggleComboboxValue('packages-apt', 'curl', false);
            const config = storage.getGlobalConfig();
            assert.ok(!config.packages.apt.includes('curl'));
        });

        it('toggles mise tool with version switching', () => {
            storage.saveGlobalConfig({ ...storage.getGlobalConfig(), packages: { apt: [], mise: ['node@20'] } });
            toggleComboboxValue('packages-mise', 'node@22');
            const config = storage.getGlobalConfig();
            assert.ok(config.packages.mise.includes('node@22'));
            assert.ok(!config.packages.mise.includes('node@20'));
        });

        it('handles profile combobox for overrides', () => {
            const profileId = storage.createProfile('test');
            storage.saveProfile(profileId, { name: 'test', overrides: { 'packages.apt': ['git'] } });
            Object.assign(state, { editingProfileId: profileId });
            toggleComboboxValue('profile-packages-apt', 'curl', true);
            const profile = storage.getProfile(profileId);
            assert.ok(profile.overrides['packages.apt'].includes('curl'));
        });
    });

    describe('addCustomPackage', () => {
        it('does nothing with empty input', () => {
            mockElements = { customAptPackage: { value: '' } };
            addCustomPackage('apt');
            // No crash, no change
            const config = storage.getGlobalConfig();
            assert.ok(!config.packages.apt.includes(''));
        });

        it('rejects invalid package names', () => {
            mockElements = { customAptPackage: { value: 'bad;name' } };
            addCustomPackage('apt');
            const config = storage.getGlobalConfig();
            assert.ok(!config.packages.apt.includes('bad;name'));
        });

        it('adds valid apt package', () => {
            mockElements = { customAptPackage: { value: 'nginx' } };
            addCustomPackage('apt');
            const config = storage.getGlobalConfig();
            assert.ok(config.packages.apt.includes('nginx'));
        });

        it('adds mise tool with @latest suffix', () => {
            mockElements = { customMiseTool: { value: 'elixir' } };
            addCustomPackage('mise');
            const config = storage.getGlobalConfig();
            assert.ok(config.packages.mise.includes('elixir@latest'));
        });

        it('preserves mise tool version if specified', () => {
            mockElements = { customMiseTool: { value: 'elixir@1.16' } };
            addCustomPackage('mise');
            const config = storage.getGlobalConfig();
            assert.ok(config.packages.mise.includes('elixir@1.16'));
        });
    });

    describe('addCustomPackageToProfile', () => {
        it('adds package to profile overrides', () => {
            const profileId = storage.createProfile('test-profile');
            storage.saveProfile(profileId, { name: 'test-profile', overrides: {} });
            Object.assign(state, { editingProfileId: profileId });
            mockElements = { 'profile-customAptPackage': { value: 'vim' } };
            addCustomPackageToProfile('apt');
            const profile = storage.getProfile(profileId);
            assert.ok(profile.overrides['packages.apt'].includes('vim'));
        });

        it('does nothing with invalid profile', () => {
            Object.assign(state, { editingProfileId: 'nonexistent' });
            mockElements = { 'profile-customAptPackage': { value: 'vim' } };
            // Should not throw
            addCustomPackageToProfile('apt');
        });

        it('appends @latest to mise tool without version', () => {
            const profileId = storage.createProfile('mise-test');
            storage.saveProfile(profileId, { name: 'mise-test', overrides: {} });
            Object.assign(state, { editingProfileId: profileId });
            mockElements = { 'profile-customMiseTool': { value: 'ruby' } };
            addCustomPackageToProfile('mise');
            const profile = storage.getProfile(profileId);
            assert.ok(profile.overrides['packages.mise'].includes('ruby@latest'));
        });
    });

    describe('addListItem / removeListItem', () => {
        it('adds repo to global config', () => {
            mockElements = { 'repos-input': { value: 'https://github.com/user/repo.git' } };
            addListItem('repos');
            const config = storage.getGlobalConfig();
            assert.ok(config.repos.includes('https://github.com/user/repo.git'));
        });

        it('rejects invalid repo URL', () => {
            localStorage.clear();
            mockElements = { 'repos-input': { value: 'not a url' } };
            addListItem('repos');
            const config = storage.getGlobalConfig();
            assert.ok(!config.repos.includes('not a url'));
        });

        it('removes item by index', () => {
            const config = storage.getGlobalConfig();
            config.repos = ['https://github.com/a/b.git', 'https://github.com/c/d.git'];
            storage.saveGlobalConfig(config);
            removeListItem('repos', 0);
            const updated = storage.getGlobalConfig();
            assert.equal(updated.repos.length, 1);
            assert.equal(updated.repos[0], 'https://github.com/c/d.git');
        });
    });

    describe('git credential handlers', () => {
        describe('addGitCredentialToConfig', () => {
            it('does nothing with empty fields', () => {
                mockElements = {
                    'git-credentials-host': { value: '' },
                    'git-credentials-username': { value: 'user' },
                    'git-credentials-token': { value: 'token' }
                };
                addGitCredentialToConfig();
                const config = storage.getGlobalConfig();
                assert.deepEqual(config.git.credentials, []);
            });

            it('adds git credential to global config', () => {
                mockElements = {
                    'git-credentials-host': { value: 'github.com' },
                    'git-credentials-username': { value: 'myuser' },
                    'git-credentials-token': { value: 'ghp_token123' }
                };
                addGitCredentialToConfig();
                const config = storage.getGlobalConfig();
                assert.equal(config.git.credentials.length, 1);
                assert.equal(config.git.credentials[0].host, 'github.com');
                assert.equal(config.git.credentials[0].username, 'myuser');
            });

            it('replaces existing credential for same host', () => {
                const config = storage.getGlobalConfig();
                config.git.credentials = [{ host: 'github.com', username: 'old', token: 'old' }];
                storage.saveGlobalConfig(config);

                mockElements = {
                    'git-credentials-host': { value: 'github.com' },
                    'git-credentials-username': { value: 'newuser' },
                    'git-credentials-token': { value: 'newtoken' }
                };
                addGitCredentialToConfig();
                const updated = storage.getGlobalConfig();
                assert.equal(updated.git.credentials.length, 1);
                assert.equal(updated.git.credentials[0].username, 'newuser');
            });

            it('adds git credential with optional name and email', () => {
                mockElements = {
                    'git-credentials-host': { value: 'github.com' },
                    'git-credentials-username': { value: 'myuser' },
                    'git-credentials-token': { value: 'ghp_token123' },
                    'git-credentials-name': { value: 'Work Name' },
                    'git-credentials-email': { value: 'work@example.com' }
                };
                addGitCredentialToConfig();
                const config = storage.getGlobalConfig();
                assert.equal(config.git.credentials.length, 1);
                assert.equal(config.git.credentials[0].name, 'Work Name');
                assert.equal(config.git.credentials[0].email, 'work@example.com');
            });

            it('adds git credential without optional name/email', () => {
                mockElements = {
                    'git-credentials-host': { value: 'bitbucket.org' },
                    'git-credentials-username': { value: 'user' },
                    'git-credentials-token': { value: 'tok' },
                    'git-credentials-name': { value: '' },
                    'git-credentials-email': { value: '' }
                };
                addGitCredentialToConfig();
                const config = storage.getGlobalConfig();
                // Find the credential we just added
                const cred = config.git.credentials.find(c => c.host === 'bitbucket.org');
                assert.ok(cred, 'credential should exist');
                assert.ok(!Object.hasOwn(cred, 'name'), 'name should not be set');
                assert.ok(!Object.hasOwn(cred, 'email'), 'email should not be set');
            });
        });

        describe('removeGitCredentialFromConfig', () => {
            it('removes credential by index', () => {
                const config = storage.getGlobalConfig();
                config.git.credentials = [
                    { host: 'github.com', username: 'u1', token: 't1' },
                    { host: 'gitlab.com', username: 'u2', token: 't2' }
                ];
                storage.saveGlobalConfig(config);

                removeGitCredentialFromConfig(0);
                const updated = storage.getGlobalConfig();
                assert.equal(updated.git.credentials.length, 1);
                assert.equal(updated.git.credentials[0].host, 'gitlab.com');
            });

            it('does nothing for invalid index', () => {
                const config = storage.getGlobalConfig();
                config.git.credentials = [{ host: 'github.com', username: 'u', token: 't' }];
                storage.saveGlobalConfig(config);

                removeGitCredentialFromConfig(5);
                const updated = storage.getGlobalConfig();
                assert.equal(updated.git.credentials.length, 1);
            });
        });

        describe('addGitCredentialToProfile', () => {
            it('adds credential to profile overrides', () => {
                const profileId = storage.createProfile('git-test');
                storage.saveProfile(profileId, { name: 'git-test', overrides: {} });
                Object.assign(state, { editingProfileId: profileId });

                mockElements = {
                    'profile-git-credentials-host': { value: 'github.com' },
                    'profile-git-credentials-username': { value: 'profuser' },
                    'profile-git-credentials-token': { value: 'proftoken' }
                };
                addGitCredentialToProfile();
                const profile = storage.getProfile(profileId);
                assert.ok(Object.hasOwn(profile.overrides, 'git.credentials'));
                assert.equal(profile.overrides['git.credentials'].length, 1);
                assert.equal(profile.overrides['git.credentials'][0].host, 'github.com');
            });

            it('copies global credentials before first override add', () => {
                const config = storage.getGlobalConfig();
                config.git.credentials = [{ host: 'existing.com', username: 'e', token: 't' }];
                storage.saveGlobalConfig(config);

                const profileId = storage.createProfile('copy-test');
                storage.saveProfile(profileId, { name: 'copy-test', overrides: {} });
                Object.assign(state, { editingProfileId: profileId });

                mockElements = {
                    'profile-git-credentials-host': { value: 'newhost.com' },
                    'profile-git-credentials-username': { value: 'new' },
                    'profile-git-credentials-token': { value: 'new' }
                };
                addGitCredentialToProfile();
                const profile = storage.getProfile(profileId);
                assert.equal(profile.overrides['git.credentials'].length, 2);
            });
        });

        describe('removeGitCredentialFromProfile', () => {
            it('removes credential from profile override', () => {
                const profileId = storage.createProfile('remove-test');
                storage.saveProfile(profileId, {
                    name: 'remove-test',
                    overrides: {
                        'git.credentials': [
                            { host: 'a.com', username: 'a', token: 'a' },
                            { host: 'b.com', username: 'b', token: 'b' }
                        ]
                    }
                });
                Object.assign(state, { editingProfileId: profileId });

                removeGitCredentialFromProfile(0);
                const profile = storage.getProfile(profileId);
                assert.equal(profile.overrides['git.credentials'].length, 1);
                assert.equal(profile.overrides['git.credentials'][0].host, 'b.com');
            });
        });
    });
});
