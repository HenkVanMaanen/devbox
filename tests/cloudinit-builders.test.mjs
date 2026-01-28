import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { shellEscape, escapeGitConfig, toBase64URL, buildGitCredentials, buildGitConfig, buildHostGitConfig, buildAutodeleteScript, buildCaddyConfig, buildIndexPage } from '../web/js/cloudinit-builders.js';

describe('cloudinit-builders.js', () => {
    describe('shellEscape', () => {
        it('escapes double quotes', () => {
            assert.equal(shellEscape('hello "world"'), 'hello \\"world\\"');
        });

        it('escapes dollar signs', () => {
            assert.equal(shellEscape('$HOME'), '\\$HOME');
        });

        it('escapes backticks', () => {
            assert.equal(shellEscape('`cmd`'), '\\`cmd\\`');
        });

        it('escapes backslashes', () => {
            assert.equal(shellEscape('a\\b'), 'a\\\\b');
        });

        it('escapes exclamation marks', () => {
            assert.equal(shellEscape('hello!'), 'hello\\!');
        });

        it('strips newlines', () => {
            assert.equal(shellEscape('line1\nline2'), 'line1line2');
        });

        it('handles empty string', () => {
            assert.equal(shellEscape(''), '');
        });

        it('handles null/undefined', () => {
            assert.equal(shellEscape(null), '');
            assert.equal(shellEscape(undefined), '');
        });

        it('leaves safe strings unchanged', () => {
            assert.equal(shellEscape('hello world'), 'hello world');
        });
    });

    describe('escapeGitConfig', () => {
        it('escapes backslashes', () => {
            assert.equal(escapeGitConfig('a\\b'), 'a\\\\b');
        });

        it('escapes double quotes', () => {
            assert.equal(escapeGitConfig('hello "world"'), 'hello \\"world\\"');
        });

        it('handles combined escapes', () => {
            assert.equal(escapeGitConfig('path\\to\\"file"'), 'path\\\\to\\\\\\"file\\"');
        });

        it('handles empty string', () => {
            assert.equal(escapeGitConfig(''), '');
        });

        it('handles null/undefined', () => {
            assert.equal(escapeGitConfig(null), '');
            assert.equal(escapeGitConfig(undefined), '');
        });

        it('leaves safe strings unchanged', () => {
            assert.equal(escapeGitConfig('hello world'), 'hello world');
        });
    });

    describe('toBase64URL', () => {
        it('replaces + with -', () => {
            assert.equal(toBase64URL('abc+def'), 'abc-def');
        });

        it('replaces / with _', () => {
            assert.equal(toBase64URL('abc/def'), 'abc_def');
        });

        it('strips trailing =', () => {
            assert.equal(toBase64URL('abc=='), 'abc');
        });

        it('handles combined conversions', () => {
            assert.equal(toBase64URL('a+b/c=='), 'a-b_c');
        });

        it('handles empty string', () => {
            assert.equal(toBase64URL(''), '');
        });

        it('handles null/undefined', () => {
            assert.equal(toBase64URL(null), '');
            assert.equal(toBase64URL(undefined), '');
        });

        it('leaves already-valid base64url unchanged', () => {
            assert.equal(toBase64URL('abc-def_ghi'), 'abc-def_ghi');
        });
    });

    describe('buildGitCredentials', () => {
        it('builds credential URL', () => {
            const result = buildGitCredentials([
                { host: 'github.com', username: 'user', token: 'ghp_abc' }
            ]);
            assert.equal(result, 'https://user:ghp_abc@github.com\n');
        });

        it('URL-encodes special characters in username', () => {
            const result = buildGitCredentials([
                { host: 'github.com', username: 'user@org', token: 'tok' }
            ]);
            assert.ok(result.includes('user%40org'));
        });

        it('URL-encodes special characters in token', () => {
            const result = buildGitCredentials([
                { host: 'github.com', username: 'u', token: 'tok/en+val' }
            ]);
            assert.ok(result.includes('tok%2Fen%2Bval'));
        });

        it('sanitizes host to prevent injection', () => {
            const result = buildGitCredentials([
                { host: 'github.com/evil\npath', username: 'u', token: 't' }
            ]);
            assert.ok(!result.includes('\n' + 'path'));
            assert.ok(result.includes('github.com'));
        });

        it('handles multiple credentials', () => {
            const result = buildGitCredentials([
                { host: 'github.com', username: 'u1', token: 't1' },
                { host: 'gitlab.com', username: 'u2', token: 't2' }
            ]);
            const lines = result.trim().split('\n');
            assert.equal(lines.length, 2);
            assert.ok(lines[0].includes('github.com'));
            assert.ok(lines[1].includes('gitlab.com'));
        });

        it('returns empty string for empty array', () => {
            assert.equal(buildGitCredentials([]), '');
        });

        it('returns empty string for null', () => {
            assert.equal(buildGitCredentials(null), '');
        });
    });

    describe('buildGitConfig', () => {
        it('generates correct structure with all options', () => {
            const config = { git: { userName: 'Test User', userEmail: 'test@example.com' } };
            const creds = [{ host: 'github.com', username: 'u', token: 't', name: 'Work', email: 'w@e.com' }];
            const result = buildGitConfig(config, creds);
            assert.ok(result.includes('[init]'));
            assert.ok(result.includes('defaultBranch = main'));
            assert.ok(result.includes('[user]'));
            assert.ok(result.includes('name = "Test User"'));
            assert.ok(result.includes('email = "test@example.com"'));
            assert.ok(result.includes('[credential]'));
            assert.ok(result.includes('helper = store'));
            assert.ok(result.includes('[includeIf'));
        });

        it('omits [user] section when no global name/email', () => {
            const config = { git: {} };
            const result = buildGitConfig(config, []);
            assert.ok(result.includes('[init]'));
            assert.ok(!result.includes('[user]'));
        });

        it('adds includeIf only for credentials with identity', () => {
            const config = { git: {} };
            const creds = [
                { host: 'github.com', username: 'u', token: 't', name: 'Work' },
                { host: 'gitlab.com', username: 'u2', token: 't2' }
            ];
            const result = buildGitConfig(config, creds);
            assert.ok(result.includes('includeIf'));
            assert.ok(result.includes('github.com'));
            assert.ok(!result.includes('gitlab.com'));
        });

        it('generates includeIf for both HTTPS and SSH URLs', () => {
            const config = { git: {} };
            const creds = [{ host: 'github.com', username: 'u', token: 't', name: 'Work' }];
            const result = buildGitConfig(config, creds);
            assert.ok(result.includes('hasconfig:remote.*.url:https://github.com/**'));
            assert.ok(result.includes('hasconfig:remote.*.url:git@github.com:*/**'));
        });

        it('sanitizes host in includeIf path', () => {
            const config = { git: {} };
            const creds = [{ host: 'evil.com/path', username: 'u', token: 't', name: 'Work' }];
            const result = buildGitConfig(config, creds);
            assert.ok(result.includes('evil.compath'));
            assert.ok(!result.includes('evil.com/path'));
        });
    });

    describe('buildHostGitConfig', () => {
        it('returns null when no name or email', () => {
            assert.equal(buildHostGitConfig({ host: 'h', username: 'u', token: 't' }), null);
        });

        it('handles partial identity (only name)', () => {
            const result = buildHostGitConfig({ host: 'h', username: 'u', token: 't', name: 'Work User' });
            assert.ok(result.includes('[user]'));
            assert.ok(result.includes('name = "Work User"'));
            assert.ok(!result.includes('email'));
        });

        it('handles partial identity (only email)', () => {
            const result = buildHostGitConfig({ host: 'h', username: 'u', token: 't', email: 'work@example.com' });
            assert.ok(result.includes('[user]'));
            assert.ok(result.includes('email = "work@example.com"'));
            assert.ok(!result.includes('name'));
        });

        it('generates full identity when both set', () => {
            const result = buildHostGitConfig({ host: 'h', username: 'u', token: 't', name: 'Work', email: 'w@e.com' });
            assert.ok(result.includes('name = "Work"'));
            assert.ok(result.includes('email = "w@e.com"'));
        });

        it('escapes special characters', () => {
            const result = buildHostGitConfig({ host: 'h', username: 'u', token: 't', name: 'User "Nick" \\Dev', email: 'e@e.com' });
            assert.ok(result.includes('User \\"Nick\\" \\\\Dev'));
        });
    });

    describe('buildAutodeleteScript', () => {
        const config = {
            autoDelete: { timeoutMinutes: 60, warningMinutes: 5 },
            git: { userName: 'Test User' }
        };

        it('includes timeout value', () => {
            const script = buildAutodeleteScript(config, 'token123');
            assert.ok(script.includes('TIMEOUT=60'));
        });

        it('includes warning value', () => {
            const script = buildAutodeleteScript(config, 'token123');
            assert.ok(script.includes('WARNING=5'));
        });

        it('includes escaped token', () => {
            const script = buildAutodeleteScript(config, "tok'en");
            assert.ok(script.includes("TOKEN='tok\\'en'"));
        });

        it('includes git user name', () => {
            const script = buildAutodeleteScript(config, 'token');
            assert.ok(script.includes("USER='Test User'"));
        });

        it('creates HTTP server on port 8081', () => {
            const script = buildAutodeleteScript(config, 'token');
            assert.ok(script.includes('8081'));
        });

        it('has /status endpoint', () => {
            const script = buildAutodeleteScript(config, 'token');
            assert.ok(script.includes("p==='/status'"));
        });

        it('has /keepalive endpoint', () => {
            const script = buildAutodeleteScript(config, 'token');
            assert.ok(script.includes("p==='/keepalive'"));
        });

        it('has /services endpoint', () => {
            const script = buildAutodeleteScript(config, 'token');
            assert.ok(script.includes("p==='/services'"));
        });

        it('includes WIP branch push logic', () => {
            const script = buildAutodeleteScript(config, 'token');
            assert.ok(script.includes('wip'));
            assert.ok(script.includes('git'));
        });

        it('handles empty git user', () => {
            const noUserConfig = { ...config, git: { userName: '' } };
            const script = buildAutodeleteScript(noUserConfig, 'token');
            assert.ok(script.includes("USER=''"));
        });
    });

    describe('buildCaddyConfig', () => {
        const baseConfig = {
            services: {
                dnsService: 'sslip.io',
                accessToken: 'mytoken',
                codeServer: true,
                claudeTerminal: true,
                shellTerminal: true,
                acmeProvider: 'letsencrypt',
                acmeEmail: ''
            }
        };

        it('includes server block for index', () => {
            const caddy = buildCaddyConfig(baseConfig, 'devbox');
            assert.ok(caddy.includes('devbox.__IP__.sslip.io'));
        });

        it('includes code-server block when enabled', () => {
            const caddy = buildCaddyConfig(baseConfig, 'devbox');
            assert.ok(caddy.includes('code.devbox.__IP__.sslip.io'));
            assert.ok(caddy.includes('localhost:8090'));
        });

        it('includes claude block when enabled', () => {
            const caddy = buildCaddyConfig(baseConfig, 'devbox');
            assert.ok(caddy.includes('claude.devbox.__IP__.sslip.io'));
            assert.ok(caddy.includes('localhost:7681'));
        });

        it('includes terminal block when enabled', () => {
            const caddy = buildCaddyConfig(baseConfig, 'devbox');
            assert.ok(caddy.includes('term.devbox.__IP__.sslip.io'));
            assert.ok(caddy.includes('localhost:7682'));
        });

        it('omits disabled services', () => {
            const config = { ...baseConfig, services: { ...baseConfig.services, codeServer: false, claudeTerminal: false, shellTerminal: false } };
            const caddy = buildCaddyConfig(config, 'devbox');
            assert.ok(!caddy.includes('code.devbox'));
            assert.ok(!caddy.includes('claude.devbox'));
            assert.ok(!caddy.includes('term.devbox'));
        });

        it('includes basic_auth with hash placeholder', () => {
            const caddy = buildCaddyConfig(baseConfig, 'devbox');
            assert.ok(caddy.includes('basic_auth'));
            assert.ok(caddy.includes('devbox __HASH__'));
        });

        it('configures ZeroSSL ACME', () => {
            const config = { ...baseConfig, services: { ...baseConfig.services, acmeProvider: 'zerossl', zerosslEabKeyId: 'kid', zerosslEabKey: 'mac' } };
            const caddy = buildCaddyConfig(config, 'devbox');
            assert.ok(caddy.includes('acme.zerossl.com'));
            assert.ok(caddy.includes('key_id kid'));
            assert.ok(caddy.includes('mac_key mac'));
        });

        it('configures Buypass ACME', () => {
            const config = { ...baseConfig, services: { ...baseConfig.services, acmeProvider: 'buypass' } };
            const caddy = buildCaddyConfig(config, 'devbox');
            assert.ok(caddy.includes('api.buypass.com'));
        });

        it('configures Actalis with base64url conversion', () => {
            const config = { ...baseConfig, services: { ...baseConfig.services, acmeProvider: 'actalis', actalisEabKeyId: 'kid', actalisEabKey: 'abc+/==' } };
            const caddy = buildCaddyConfig(config, 'devbox');
            assert.ok(caddy.includes('actalis'));
            assert.ok(caddy.includes('abc-_'));
        });

        it('configures custom ACME', () => {
            const config = { ...baseConfig, services: { ...baseConfig.services, acmeProvider: 'custom', customAcmeUrl: 'https://ca.example.com/dir', customEabKeyId: 'ck', customEabKey: 'cv' } };
            const caddy = buildCaddyConfig(config, 'devbox');
            assert.ok(caddy.includes('https://ca.example.com/dir'));
        });

        it('includes ACME email when set', () => {
            const config = { ...baseConfig, services: { ...baseConfig.services, acmeEmail: 'admin@test.com' } };
            const caddy = buildCaddyConfig(config, 'devbox');
            assert.ok(caddy.includes('email admin@test.com'));
        });

        it('rejects ACME email with spaces', () => {
            const config = { ...baseConfig, services: { ...baseConfig.services, acmeEmail: 'bad email' } };
            const caddy = buildCaddyConfig(config, 'devbox');
            assert.ok(!caddy.includes('email'));
        });

        it('uses custom DNS service', () => {
            const config = { ...baseConfig, services: { ...baseConfig.services, dnsService: 'nip.io' } };
            const caddy = buildCaddyConfig(config, 'devbox');
            assert.ok(caddy.includes('nip.io'));
        });

        it('sanitizes EAB keys with whitespace/braces', () => {
            const config = { ...baseConfig, services: { ...baseConfig.services, acmeProvider: 'zerossl', zerosslEabKeyId: 'key id{evil}', zerosslEabKey: 'mac{inject}key' } };
            const caddy = buildCaddyConfig(config, 'devbox');
            assert.ok(!caddy.includes('{evil}'));
            assert.ok(!caddy.includes('{inject}'));
            assert.ok(caddy.includes('key_id keyidevil'));
            assert.ok(caddy.includes('mac_key macinjectkey'));
        });

        it('sanitizes custom ACME URL', () => {
            const config = { ...baseConfig, services: { ...baseConfig.services, acmeProvider: 'custom', customAcmeUrl: 'https://evil.com/dir}\n{new block' } };
            const caddy = buildCaddyConfig(config, 'devbox');
            assert.ok(!caddy.includes('{new'));
            assert.ok(caddy.includes('https://evil.com/dir'));
        });
    });

    describe('buildIndexPage', () => {
        const config = {
            services: { codeServer: true, claudeTerminal: true, shellTerminal: true, accessToken: 'tok' }
        };
        const colors = {
            background: '#000', foreground: '#fff', card: '#111',
            mutedForeground: '#888', border: '#333', muted: '#222',
            primary: '#00f', success: '#0f0', warning: '#ff0',
            destructive: '#f00', focus: '#ff0'
        };

        it('returns valid HTML', () => {
            const html = buildIndexPage(config, 'devbox', colors);
            assert.ok(html.startsWith('<!DOCTYPE html>'));
            assert.ok(html.includes('</html>'));
        });

        it('includes server name', () => {
            const html = buildIndexPage(config, 'my-server', colors);
            assert.ok(html.includes('my-server'));
        });

        it('uses theme colors', () => {
            const html = buildIndexPage(config, 'devbox', colors);
            assert.ok(html.includes('#000'));
            assert.ok(html.includes('#fff'));
        });

        it('includes auto-shutdown countdown', () => {
            const html = buildIndexPage(config, 'devbox', colors);
            assert.ok(html.includes('Auto-shutdown'));
        });

        it('includes status API polling', () => {
            const html = buildIndexPage(config, 'devbox', colors);
            assert.ok(html.includes('/api/status'));
            assert.ok(html.includes('/api/services'));
        });
    });
});
