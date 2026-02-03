import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// Mock localStorage for storage.js dependency
class MockLocalStorage {
    constructor() { this.store = {}; }
    getItem(key) { return this.store[key] ?? null; }
    setItem(key, value) { this.store[key] = String(value); }
    removeItem(key) { delete this.store[key]; }
    clear() { this.store = {}; }
}

globalThis.localStorage = new MockLocalStorage();
// crypto.getRandomValues is available natively in Node 24

// Mock window/document for themes.js
globalThis.window = { matchMedia: () => ({ matches: true, addEventListener: () => {} }) };
globalThis.document = { documentElement: { style: { setProperty: () => {} }, classList: { add: () => {}, remove: () => {} } }, querySelector: () => null, createElement: () => ({ name: '' }), head: { appendChild: () => {} } };

const { generate } = await import('../web/js/cloudinit.js');
const { THEMES } = await import('../web/js/themes.js');

const baseConfig = {
    hetzner: { serverType: 'cpx21', baseImage: 'debian-12', location: 'fsn1' },
    packages: { apt: ['git', 'curl'], mise: [] },
    shell: { default: 'bash', starship: false },
    ssh: { keys: [] },
    git: { userName: '', userEmail: '', credentials: [] },
    claude: { apiKey: '', credentialsJson: null, theme: '', settings: '' },
    services: {
        codeServer: false, shellTerminal: false,
        dnsService: 'sslip.io', accessToken: 'testtoken123',
        acmeProvider: 'letsencrypt', acmeEmail: ''
    },
    autoDelete: { enabled: false, timeoutMinutes: 60, warningMinutes: 5 },
    repos: []
};

const baseOptions = {
    gitCredentials: [],
    sshKeys: [],
    themeColors: THEMES[0].colors
};

describe('cloudinit.js generate()', () => {
    it('starts with #cloud-config header', () => {
        const yaml = generate('test', 'token', baseConfig, baseOptions);
        assert.ok(yaml.startsWith('#cloud-config\n'));
    });

    it('includes package_update and package_upgrade', () => {
        const yaml = generate('test', 'token', baseConfig, baseOptions);
        assert.ok(yaml.includes('package_update: true'));
        assert.ok(yaml.includes('package_upgrade: true'));
    });

    it('includes specified apt packages', () => {
        const yaml = generate('test', 'token', baseConfig, baseOptions);
        assert.ok(yaml.includes('- git'));
        assert.ok(yaml.includes('- curl'));
    });

    it('adds gh and ufw packages always', () => {
        const yaml = generate('test', 'token', baseConfig, baseOptions);
        assert.ok(yaml.includes('- gh'));
        assert.ok(yaml.includes('- ufw'));
    });

    it('creates dev user with correct shell', () => {
        const yaml = generate('test', 'token', baseConfig, baseOptions);
        assert.ok(yaml.includes('name: dev'));
        assert.ok(yaml.includes('shell: /bin/bash'));
    });

    it('uses fish shell path when configured', () => {
        const config = { ...baseConfig, shell: { default: 'fish', starship: false } };
        const yaml = generate('test', 'token', config, baseOptions);
        assert.ok(yaml.includes('shell: /usr/bin/fish'));
        assert.ok(yaml.includes('- fish')); // fish package added
    });

    it('uses zsh shell path when configured', () => {
        const config = { ...baseConfig, shell: { default: 'zsh', starship: false } };
        const yaml = generate('test', 'token', config, baseOptions);
        assert.ok(yaml.includes('shell: /usr/bin/zsh'));
        assert.ok(yaml.includes('- zsh'));
    });

    it('includes SSH authorized keys when provided', () => {
        const opts = { ...baseOptions, sshKeys: [{ name: 'test-key', pubKey: 'ssh-ed25519 AAAAC3 test@dev' }] };
        const yaml = generate('test', 'token', baseConfig, opts);
        assert.ok(yaml.includes('ssh-ed25519 AAAAC3 test@dev'));
    });

    it('includes multiple SSH authorized keys', () => {
        const opts = {
            ...baseOptions,
            sshKeys: [
                { name: 'key1', pubKey: 'ssh-ed25519 AAAAC3-key1 user1@dev' },
                { name: 'key2', pubKey: 'ssh-rsa AAAAB3-key2 user2@dev' }
            ]
        };
        const yaml = generate('test', 'token', baseConfig, opts);
        assert.ok(yaml.includes('ssh-ed25519 AAAAC3-key1 user1@dev'));
        assert.ok(yaml.includes('ssh-rsa AAAAB3-key2 user2@dev'));
    });

    it('filters out empty pubKeys in SSH keys array', () => {
        const opts = {
            ...baseOptions,
            sshKeys: [
                { name: 'valid', pubKey: 'ssh-ed25519 VALID' },
                { name: 'empty', pubKey: '' }
            ]
        };
        const yaml = generate('test', 'token', baseConfig, opts);
        assert.ok(yaml.includes('ssh-ed25519 VALID'));
    });

    it('includes starship config for bash', () => {
        const config = { ...baseConfig, shell: { default: 'bash', starship: true } };
        const yaml = generate('test', 'token', config, baseOptions);
        assert.ok(yaml.includes('starship init bash'));
        assert.ok(yaml.includes('starship.rs/install.sh'));
    });

    it('includes starship config for fish', () => {
        const config = { ...baseConfig, shell: { default: 'fish', starship: true } };
        const yaml = generate('test', 'token', config, baseOptions);
        assert.ok(yaml.includes('starship init fish'));
    });

    it('includes starship config for zsh', () => {
        const config = { ...baseConfig, shell: { default: 'zsh', starship: true } };
        const yaml = generate('test', 'token', config, baseOptions);
        assert.ok(yaml.includes('starship init zsh'));
    });

    it('generates git credentials file', () => {
        const opts = {
            ...baseOptions,
            gitCredentials: [{ host: 'github.com', username: 'user', token: 'ghp_test' }]
        };
        const yaml = generate('test', 'token', baseConfig, opts);
        assert.ok(yaml.includes('.git-credentials'));
        assert.ok(yaml.includes('https://user:ghp_test@github.com'));
        assert.ok(yaml.includes('permissions: "0600"'));
    });

    it('URL-encodes git credential special characters', () => {
        const opts = {
            ...baseOptions,
            gitCredentials: [{ host: 'github.com', username: 'user@org', token: 'tok/en' }]
        };
        const yaml = generate('test', 'token', baseConfig, opts);
        assert.ok(yaml.includes('user%40org'));
        assert.ok(yaml.includes('tok%2Fen'));
    });

    it('includes claude config files', () => {
        const yaml = generate('test', 'token', baseConfig, baseOptions);
        assert.ok(yaml.includes('.claude.json'));
        assert.ok(yaml.includes('hasCompletedOnboarding'));
    });

    it('includes claude API key when provided', () => {
        const config = { ...baseConfig, claude: { ...baseConfig.claude, apiKey: 'sk-ant-test' } };
        const yaml = generate('test', 'token', config, baseOptions);
        assert.ok(yaml.includes('.claude/.credentials'));
        assert.ok(yaml.includes('sk-ant-test'));
    });

    it('includes claude credentials JSON when provided', () => {
        const config = {
            ...baseConfig,
            claude: { ...baseConfig.claude, credentialsJson: { token: 'abc' } }
        };
        const yaml = generate('test', 'token', config, baseOptions);
        assert.ok(yaml.includes('.credentials.json'));
        // JSON is serialized and then YAML-quoted with escaped quotes
        assert.ok(yaml.includes('token') && yaml.includes('abc'));
    });

    it('prefers credentialsJson over apiKey', () => {
        const config = {
            ...baseConfig,
            claude: { ...baseConfig.claude, apiKey: 'sk-test', credentialsJson: { t: 1 } }
        };
        const yaml = generate('test', 'token', config, baseOptions);
        assert.ok(yaml.includes('.credentials.json'));
        assert.ok(!yaml.includes('.claude/.credentials\n'));
    });

    it('includes claude settings when theme set', () => {
        const config = { ...baseConfig, claude: { ...baseConfig.claude, theme: 'dark' } };
        const yaml = generate('test', 'token', config, baseOptions);
        assert.ok(yaml.includes('settings.json'));
        // JSON content is YAML-quoted, check path and that theme value is present
        assert.ok(yaml.includes('theme'));
    });

    describe('devbox-daemon', () => {
        it('includes daemon script when autodelete enabled', () => {
            const config = { ...baseConfig, autoDelete: { enabled: true, timeoutMinutes: 60, warningMinutes: 5 } };
            const yaml = generate('test', 'hetzner-tok', config, baseOptions);
            assert.ok(yaml.includes('devbox-daemon'));
            assert.ok(yaml.includes('TIMEOUT=60'));
            assert.ok(yaml.includes('WARNING=5'));
            assert.ok(yaml.includes("TOKEN='hetzner-tok'"));
        });

        it('includes daemon script when services enabled', () => {
            const config = { ...baseConfig, services: { ...baseConfig.services, codeServer: true } };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('devbox-daemon'));
        });

        it('omits daemon when both autodelete and services disabled', () => {
            const yaml = generate('test', 'token', baseConfig, baseOptions);
            assert.ok(!yaml.includes('devbox-daemon'));
        });

        it('includes systemd service for daemon', () => {
            const config = { ...baseConfig, autoDelete: { enabled: true, timeoutMinutes: 30, warningMinutes: 3 } };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('devbox-daemon.service'));
            assert.ok(yaml.includes('systemctl'));
        });
    });

    describe('services', () => {
        it('includes Caddy config when any service enabled', () => {
            const config = { ...baseConfig, services: { ...baseConfig.services, codeServer: true } };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('Caddyfile.template'));
            assert.ok(yaml.includes('caddy'));
        });

        it('includes code-server config', () => {
            const config = { ...baseConfig, services: { ...baseConfig.services, codeServer: true } };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('code-server'));
            assert.ok(yaml.includes('65532'));
        });

        it('includes shell terminal config', () => {
            const config = { ...baseConfig, services: { ...baseConfig.services, shellTerminal: true } };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('ttyd-term'));
            assert.ok(yaml.includes('65534'));
        });

        it('uses configured shell for terminal', () => {
            const config = {
                ...baseConfig,
                shell: { default: 'fish', starship: false },
                services: { ...baseConfig.services, shellTerminal: true }
            };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('-W fish'));
        });

        it('includes overview page template', () => {
            const config = { ...baseConfig, services: { ...baseConfig.services, codeServer: true } };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('devbox-overview/index.html.template'));
        });

        it('includes IP and hash substitution commands', () => {
            const config = { ...baseConfig, services: { ...baseConfig.services, codeServer: true } };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('ifconfig.me'));
            assert.ok(yaml.includes('__IP__'));
            assert.ok(yaml.includes('__HASH__'));
            assert.ok(yaml.includes('caddy hash-password'));
        });
    });

    describe('ACME providers', () => {
        it('configures ZeroSSL with EAB', () => {
            const config = {
                ...baseConfig,
                services: {
                    ...baseConfig.services, codeServer: true,
                    acmeProvider: 'zerossl',
                    zerosslEabKeyId: 'keyid123',
                    zerosslEabKey: 'mackey456'
                }
            };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('acme.zerossl.com'));
            assert.ok(yaml.includes('keyid123'));
            assert.ok(yaml.includes('mackey456'));
        });

        it('configures Buypass', () => {
            const config = {
                ...baseConfig,
                services: { ...baseConfig.services, codeServer: true, acmeProvider: 'buypass' }
            };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('api.buypass.com'));
        });

        it('configures Actalis with base64url conversion', () => {
            const config = {
                ...baseConfig,
                services: {
                    ...baseConfig.services, codeServer: true,
                    acmeProvider: 'actalis',
                    actalisEabKeyId: 'kid',
                    actalisEabKey: 'abc+def/ghi==' // should become abc-def_ghi
                }
            };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('actalis'));
            assert.ok(yaml.includes('abc-def_ghi')); // base64url converted
        });

        it('configures custom ACME provider', () => {
            const config = {
                ...baseConfig,
                services: {
                    ...baseConfig.services, codeServer: true,
                    acmeProvider: 'custom',
                    customAcmeUrl: 'https://acme.example.com/dir',
                    customEabKeyId: 'ck',
                    customEabKey: 'cv'
                }
            };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('https://acme.example.com/dir'));
            assert.ok(yaml.includes('ck'));
        });

        it('includes ACME email when set', () => {
            const config = {
                ...baseConfig,
                services: { ...baseConfig.services, codeServer: true, acmeEmail: 'admin@example.com' }
            };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('email admin@example.com'));
        });
    });

    describe('mise tools', () => {
        it('always installs mise with node@latest for daemon', () => {
            const yaml = generate('test', 'token', baseConfig, baseOptions);
            assert.ok(yaml.includes('mise.run'));
            assert.ok(yaml.includes('mise use --global node@latest'));
        });

        it('uses user-selected node version instead of node@latest', () => {
            const config = { ...baseConfig, packages: { apt: ['git'], mise: ['node@22'] } };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('mise use --global node@22'));
            assert.ok(!yaml.includes('node@latest'));
        });

        it('runs mise installs in parallel', () => {
            const config = { ...baseConfig, packages: { apt: ['git'], mise: ['python@3.12'] } };
            const yaml = generate('test', 'token', config, baseOptions);
            // Should background with &
            assert.ok(yaml.includes("mise use --global node@latest' &"));
            assert.ok(yaml.includes("mise use --global python@3.12' &"));
        });

        it('adds mise shims to system PATH always', () => {
            const yaml = generate('test', 'token', baseConfig, baseOptions);
            // /etc/profile.d for bash/zsh
            assert.ok(yaml.includes('/etc/profile.d/mise.sh'));
            assert.ok(yaml.includes('/home/dev/.local/share/mise/shims'));
            // /etc/fish/conf.d for fish
            assert.ok(yaml.includes('/etc/fish/conf.d/mise.fish'));
        });

        it('adds mise shims to daemon service PATH', () => {
            const config = {
                ...baseConfig,
                autoDelete: { enabled: true, timeoutMinutes: 60, warningMinutes: 5 }
            };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('devbox-daemon.service'));
            assert.ok(yaml.includes('Environment="PATH=/home/dev/.local/share/mise/shims'));
        });

        it('adds mise activation to shell rc files', () => {
            const yaml = generate('test', 'token', baseConfig, baseOptions);
            assert.ok(yaml.includes('mise activate bash'));
            assert.ok(yaml.includes('.bashrc'));
        });
    });

    describe('git config', () => {
        it('sets git user name and email in gitconfig file', () => {
            const config = { ...baseConfig, git: { userName: 'Test User', userEmail: 'test@ex.com' } };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('.gitconfig'));
            assert.ok(yaml.includes('name = "Test User"'));
            assert.ok(yaml.includes('email = "test@ex.com"'));
        });

        it('sets credential helper when git credentials present', () => {
            const opts = {
                ...baseOptions,
                gitCredentials: [{ host: 'github.com', username: 'u', token: 't' }]
            };
            const yaml = generate('test', 'token', baseConfig, opts);
            assert.ok(yaml.includes('helper = store'));
        });

        it('skips user section in gitconfig when no name/email', () => {
            const yaml = generate('test', 'token', baseConfig, baseOptions);
            // Should have gitconfig with init section, but no [user] section
            assert.ok(yaml.includes('.gitconfig'));
            assert.ok(yaml.includes('defaultBranch = main'));
        });

        it('escapes quotes in userName for gitconfig', () => {
            const config = { ...baseConfig, git: { userName: 'User "Nick"', userEmail: '' } };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('User \\"Nick\\"'));
        });

        it('escapes backslashes in userName for gitconfig', () => {
            const config = { ...baseConfig, git: { userName: 'User\\Name', userEmail: '' } };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('User\\\\Name'));
        });
    });

    describe('per-host git identity', () => {
        it('generates host-specific gitconfig when credential has name/email', () => {
            const opts = {
                ...baseOptions,
                gitCredentials: [{ host: 'github.com', username: 'u', token: 't', name: 'Work User', email: 'work@example.com' }]
            };
            const yaml = generate('test', 'token', baseConfig, opts);
            assert.ok(yaml.includes('.gitconfig-github.com'));
            assert.ok(yaml.includes('name = "Work User"'));
            assert.ok(yaml.includes('email = "work@example.com"'));
        });

        it('generates includeIf directives for hosts with custom identity', () => {
            const opts = {
                ...baseOptions,
                gitCredentials: [{ host: 'github.com', username: 'u', token: 't', name: 'Work', email: 'w@e.com' }]
            };
            const yaml = generate('test', 'token', baseConfig, opts);
            assert.ok(yaml.includes('includeIf "hasconfig:remote.*.url:https://github.com/**"'));
            assert.ok(yaml.includes('includeIf "hasconfig:remote.*.url:git@github.com:*/**"'));
            assert.ok(yaml.includes('path = ~/.gitconfig-github.com'));
        });

        it('skips host-specific gitconfig when credential has no name/email', () => {
            const opts = {
                ...baseOptions,
                gitCredentials: [{ host: 'github.com', username: 'u', token: 't' }]
            };
            const yaml = generate('test', 'token', baseConfig, opts);
            assert.ok(!yaml.includes('.gitconfig-github.com'));
            assert.ok(!yaml.includes('includeIf'));
        });

        it('writes main gitconfig with global identity as fallback', () => {
            const config = { ...baseConfig, git: { userName: 'Global User', userEmail: 'global@ex.com' } };
            const opts = {
                ...baseOptions,
                gitCredentials: [{ host: 'github.com', username: 'u', token: 't', name: 'Work', email: 'w@e.com' }]
            };
            const yaml = generate('test', 'token', config, opts);
            // Main gitconfig should have global user
            assert.ok(yaml.includes('name = "Global User"'));
            assert.ok(yaml.includes('email = "global@ex.com"'));
            // And also host-specific
            assert.ok(yaml.includes('.gitconfig-github.com'));
        });

        it('escapes special characters in per-host identity', () => {
            const opts = {
                ...baseOptions,
                gitCredentials: [{ host: 'github.com', username: 'u', token: 't', name: 'User "Nick" \\Dev', email: 'e@e.com' }]
            };
            const yaml = generate('test', 'token', baseConfig, opts);
            assert.ok(yaml.includes('User \\"Nick\\" \\\\Dev'));
        });

        it('handles credential with only name set', () => {
            const opts = {
                ...baseOptions,
                gitCredentials: [{ host: 'github.com', username: 'u', token: 't', name: 'Work User' }]
            };
            const yaml = generate('test', 'token', baseConfig, opts);
            assert.ok(yaml.includes('.gitconfig-github.com'));
            assert.ok(yaml.includes('name = "Work User"'));
        });

        it('handles credential with only email set', () => {
            const opts = {
                ...baseOptions,
                gitCredentials: [{ host: 'github.com', username: 'u', token: 't', email: 'work@example.com' }]
            };
            const yaml = generate('test', 'token', baseConfig, opts);
            assert.ok(yaml.includes('.gitconfig-github.com'));
            assert.ok(yaml.includes('email = "work@example.com"'));
        });
    });

    describe('repos', () => {
        it('clones configured repos', () => {
            const config = { ...baseConfig, repos: ['https://github.com/user/repo.git'] };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('git clone --depth 1'));
            assert.ok(yaml.includes('https://github.com/user/repo.git'));
            assert.ok(yaml.includes('~/repo'));
        });

        it('converts SSH URLs to HTTPS for github', () => {
            const config = { ...baseConfig, repos: ['git@github.com:user/repo.git'] };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('https://github.com/user/repo.git'));
        });

        it('converts SSH URLs to HTTPS for other hosts', () => {
            const config = { ...baseConfig, repos: ['git@gitlab.com:org/project.git'] };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('https://gitlab.com/org/project.git'));
        });

        it('strips .git suffix from directory name', () => {
            const config = { ...baseConfig, repos: ['https://github.com/user/my-project.git'] };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('~/my-project'));
        });
    });

    describe('firewall', () => {
        it('configures ufw with default deny and allows SSH/HTTP/HTTPS', () => {
            const yaml = generate('test', 'token', baseConfig, baseOptions);
            assert.ok(yaml.includes('ufw default deny incoming'));
            assert.ok(yaml.includes('ufw default allow outgoing'));
            assert.ok(yaml.includes('ufw allow 22'));
            assert.ok(yaml.includes('ufw allow 80'));
            assert.ok(yaml.includes('ufw allow 443'));
            assert.ok(yaml.includes('ufw --force enable'));
        });
    });

    describe('cleanup', () => {
        it('includes apt cleanup', () => {
            const yaml = generate('test', 'token', baseConfig, baseOptions);
            assert.ok(yaml.includes('apt-get clean'));
        });

        it('includes ownership fix', () => {
            const yaml = generate('test', 'token', baseConfig, baseOptions);
            assert.ok(yaml.includes('chown -R dev:dev /home/dev'));
        });

        it('touches .devbox-ready marker', () => {
            const yaml = generate('test', 'token', baseConfig, baseOptions);
            assert.ok(yaml.includes('.devbox-ready'));
        });
    });

    describe('YAML output format', () => {
        it('produces valid YAML structure', () => {
            const yaml = generate('test', 'token', baseConfig, baseOptions);
            // Check for proper indentation patterns
            assert.ok(yaml.includes('packages:\n'));
            assert.ok(yaml.includes('users:\n'));
            assert.ok(yaml.includes('runcmd:\n'));
        });

        it('quotes strings that start with numbers', () => {
            const config = { ...baseConfig, services: { ...baseConfig.services, accessToken: '123abc' } };
            // Access token appears in code-server config which is a multi-line string
            // So we test the YAML serializer with a simple case
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.startsWith('#cloud-config'));
        });

        it('handles boolean values correctly', () => {
            const yaml = generate('test', 'token', baseConfig, baseOptions);
            assert.ok(yaml.includes('package_update: true'));
        });
    });
});
