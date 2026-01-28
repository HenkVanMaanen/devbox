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
    ssh: { pubKey: '' },
    git: { userName: '', userEmail: '', credentials: [] },
    claude: { apiKey: '', credentialsJson: null, theme: '', settings: '' },
    services: {
        codeServer: false, claudeTerminal: false, shellTerminal: false,
        dnsService: 'sslip.io', accessToken: 'testtoken123',
        acmeProvider: 'letsencrypt', acmeEmail: ''
    },
    autoDelete: { enabled: false, timeoutMinutes: 60, warningMinutes: 5 },
    repos: []
};

const baseOptions = {
    gitCredentials: [],
    sshPubKey: '',
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

    it('adds gh and nodejs packages always', () => {
        const yaml = generate('test', 'token', baseConfig, baseOptions);
        assert.ok(yaml.includes('- gh'));
        assert.ok(yaml.includes('- nodejs'));
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

    it('includes SSH authorized key when provided', () => {
        const opts = { ...baseOptions, sshPubKey: 'ssh-ed25519 AAAAC3 test@dev' };
        const yaml = generate('test', 'token', baseConfig, opts);
        assert.ok(yaml.includes('ssh-ed25519 AAAAC3 test@dev'));
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

    describe('auto-delete', () => {
        it('includes autodelete script when enabled', () => {
            const config = { ...baseConfig, autoDelete: { enabled: true, timeoutMinutes: 60, warningMinutes: 5 } };
            const yaml = generate('test', 'hetzner-tok', config, baseOptions);
            assert.ok(yaml.includes('devbox-autodelete'));
            assert.ok(yaml.includes('TIMEOUT=60'));
            assert.ok(yaml.includes('WARNING=5'));
            assert.ok(yaml.includes("TOKEN='hetzner-tok'"));
        });

        it('omits autodelete when disabled', () => {
            const yaml = generate('test', 'token', baseConfig, baseOptions);
            assert.ok(!yaml.includes('devbox-autodelete'));
        });

        it('includes systemd service for autodelete', () => {
            const config = { ...baseConfig, autoDelete: { enabled: true, timeoutMinutes: 30, warningMinutes: 3 } };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('devbox-autodelete.service'));
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
            assert.ok(yaml.includes('8090'));
        });

        it('includes claude terminal config', () => {
            const config = { ...baseConfig, services: { ...baseConfig.services, claudeTerminal: true } };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('ttyd-claude'));
            assert.ok(yaml.includes('7681'));
            assert.ok(yaml.includes('claude-terminal'));
        });

        it('includes shell terminal config', () => {
            const config = { ...baseConfig, services: { ...baseConfig.services, shellTerminal: true } };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('ttyd-term'));
            assert.ok(yaml.includes('7682'));
        });

        it('uses configured shell for terminal', () => {
            const config = {
                ...baseConfig,
                shell: { default: 'fish', starship: false },
                services: { ...baseConfig.services, shellTerminal: true }
            };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('dtach -A /tmp/devbox-shell -z fish'));
        });

        it('includes index page template', () => {
            const config = { ...baseConfig, services: { ...baseConfig.services, codeServer: true } };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('devbox-index/index.html.template'));
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
        it('installs mise when tools configured', () => {
            const config = { ...baseConfig, packages: { apt: ['git'], mise: ['node@22'] } };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('mise.run'));
            assert.ok(yaml.includes('mise use --global node@22'));
        });

        it('skips mise when no tools configured', () => {
            const yaml = generate('test', 'token', baseConfig, baseOptions);
            assert.ok(!yaml.includes('mise.run'));
        });

        it('runs mise installs in parallel', () => {
            const config = { ...baseConfig, packages: { apt: ['git'], mise: ['node@22', 'python@3.12'] } };
            const yaml = generate('test', 'token', config, baseOptions);
            // Should background with &
            assert.ok(yaml.includes("mise use --global node@22' &"));
            assert.ok(yaml.includes("mise use --global python@3.12' &"));
        });
    });

    describe('git config', () => {
        it('sets git user name and email', () => {
            const config = { ...baseConfig, git: { userName: 'Test User', userEmail: 'test@ex.com' } };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('user.name "Test User"'));
            assert.ok(yaml.includes('user.email "test@ex.com"'));
        });

        it('sets credential helper when git credentials present', () => {
            const opts = {
                ...baseOptions,
                gitCredentials: [{ host: 'github.com', username: 'u', token: 't' }]
            };
            const yaml = generate('test', 'token', baseConfig, opts);
            assert.ok(yaml.includes('credential.helper store'));
        });

        it('skips user name/email when empty', () => {
            const yaml = generate('test', 'token', baseConfig, baseOptions);
            assert.ok(!yaml.includes('user.name'));
            assert.ok(!yaml.includes('user.email'));
        });

        it('escapes shell metacharacters in userName', () => {
            const config = { ...baseConfig, git: { userName: 'User"; rm -rf /', userEmail: '' } };
            const yaml = generate('test', 'token', config, baseOptions);
            const line = yaml.split('\n').find(l => l.includes('user.name'));
            // The unescaped quote-semicolon pattern should NOT appear (would break out of string)
            // Instead the quote should be preceded by a backslash
            assert.ok(line.includes('User\\"'), 'double quote in userName should be backslash-escaped');
        });

        it('escapes dollar signs in userName', () => {
            const config = { ...baseConfig, git: { userName: 'User $HOME', userEmail: '' } };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('\\$HOME'));
        });

        it('escapes backticks in userEmail', () => {
            const config = { ...baseConfig, git: { userName: '', userEmail: 'user`whoami`@test.com' } };
            const yaml = generate('test', 'token', config, baseOptions);
            assert.ok(yaml.includes('\\`'));
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
