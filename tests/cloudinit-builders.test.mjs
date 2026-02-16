import { describe, it } from 'node:test';
import assert from 'node:assert';

import {
  shellEscape,
  toBase64URL,
  buildGitCredentials,
  buildCaddyConfig,
} from '../src/lib/utils/cloudinit-builders.ts';

// Helper to build a minimal GlobalConfig with service overrides
function makeConfig(overrides = {}) {
  return {
    autoDelete: { enabled: true, timeoutMinutes: 60, warningMinutes: 5 },
    chezmoi: { ageKey: '', repoUrl: '' },
    customCloudInit: { mode: 'merge', yaml: '' },
    git: { credential: { host: '', username: '', token: '' } },
    hetzner: { baseImage: 'ubuntu-24.04', location: 'fsn1', serverType: 'cx22' },
    services: {
      accessToken: 'test-token',
      acmeEmail: '',
      acmeProvider: 'letsencrypt',
      actalisEabKey: '',
      actalisEabKeyId: '',
      customAcmeUrl: '',
      customDnsDomain: '',
      customEabKey: '',
      customEabKeyId: '',
      dnsService: 'sslip.io',
      zerosslEabKey: '',
      zerosslEabKeyId: '',
      ...overrides,
    },
    ssh: { keys: [] },
  };
}

describe('shellEscape', () => {
  it('returns empty string for empty input', () => {
    assert.strictEqual(shellEscape(''), '');
  });

  it('escapes double quotes', () => {
    assert.strictEqual(shellEscape('he said "hi"'), 'he said \\"hi\\"');
  });

  it('escapes dollar signs', () => {
    assert.strictEqual(shellEscape('$HOME'), '\\$HOME');
  });

  it('escapes backticks', () => {
    assert.strictEqual(shellEscape('`cmd`'), '\\`cmd\\`');
  });

  it('escapes backslashes', () => {
    assert.strictEqual(shellEscape('a\\b'), 'a\\\\b');
  });

  it('escapes exclamation marks', () => {
    assert.strictEqual(shellEscape('hello!'), 'hello\\!');
  });

  it('removes newlines', () => {
    assert.strictEqual(shellEscape('line1\nline2'), 'line1line2');
  });

  it('prevents command injection via $(...)', () => {
    assert.strictEqual(shellEscape('$(rm -rf /)'), '\\$(rm -rf /)');
  });

  it('escapes all metacharacters in a combined string', () => {
    assert.strictEqual(shellEscape('$HOME\\path "file" `cmd` end!'), '\\$HOME\\\\path \\"file\\" \\`cmd\\` end\\!');
  });
});

describe('toBase64URL', () => {
  it('returns empty string for empty input', () => {
    assert.strictEqual(toBase64URL(''), '');
  });

  it('replaces + with -', () => {
    assert.strictEqual(toBase64URL('a+b'), 'a-b');
  });

  it('replaces / with _', () => {
    assert.strictEqual(toBase64URL('a/b'), 'a_b');
  });

  it('strips trailing = padding', () => {
    assert.strictEqual(toBase64URL('abc=='), 'abc');
  });

  it('handles combined replacements', () => {
    assert.strictEqual(toBase64URL('a+b/c=='), 'a-b_c');
  });
});

describe('buildGitCredentials', () => {
  it('returns credential URL for valid input', () => {
    const result = buildGitCredentials({ host: 'github.com', username: 'user', token: 'tok123' });
    assert.strictEqual(result, 'https://user:tok123@github.com\n');
  });

  it('URI-encodes username and token with special characters', () => {
    const result = buildGitCredentials({ host: 'github.com', username: 'u@ser', token: 'p@ss/word' });
    assert.strictEqual(result, 'https://u%40ser:p%40ss%2Fword@github.com\n');
  });

  it('returns empty string when host is empty', () => {
    assert.strictEqual(buildGitCredentials({ host: '', username: 'user', token: 'tok' }), '');
  });

  it('returns empty string when username is empty', () => {
    assert.strictEqual(buildGitCredentials({ host: 'github.com', username: '', token: 'tok' }), '');
  });

  it('returns empty string when token is empty', () => {
    assert.strictEqual(buildGitCredentials({ host: 'github.com', username: 'user', token: '' }), '');
  });

  it('strips non-hostname characters from host', () => {
    const result = buildGitCredentials({ host: 'git;rm', username: 'user', token: 'tok' });
    assert.strictEqual(result, 'https://user:tok@gitrm\n');
  });

  it('produces a URL ending with newline', () => {
    const result = buildGitCredentials({ host: 'github.com', username: 'user', token: 'tok' });
    assert.ok(result.endsWith('\n'));
    assert.strictEqual(result.split('\n').length, 2); // content + trailing empty
  });
});

describe('buildCaddyConfig', () => {
  it('always includes on_demand_tls block', () => {
    const result = buildCaddyConfig(makeConfig());
    assert.ok(result.includes('on_demand_tls'));
    assert.ok(result.includes('ask http://localhost:65531/verify-domain'));
  });

  it('includes ACME email when provided', () => {
    const result = buildCaddyConfig(makeConfig({ acmeEmail: 'user@example.com' }));
    assert.ok(result.includes('email user@example.com'));
  });

  it('rejects ACME email containing spaces or braces', () => {
    const withSpace = buildCaddyConfig(makeConfig({ acmeEmail: 'user @example.com' }));
    assert.ok(!withSpace.includes('email '));

    const withBrace = buildCaddyConfig(makeConfig({ acmeEmail: 'user{@example.com' }));
    assert.ok(!withBrace.includes('email '));

    const withCloseBrace = buildCaddyConfig(makeConfig({ acmeEmail: 'user}@example.com' }));
    assert.ok(!withCloseBrace.includes('email '));
  });

  it("does not add acme_ca for Let's Encrypt (default provider)", () => {
    const result = buildCaddyConfig(makeConfig({ acmeProvider: 'letsencrypt' }));
    assert.ok(!result.includes('acme_ca'));
  });

  it('includes acme_ca for ZeroSSL', () => {
    const result = buildCaddyConfig(makeConfig({ acmeProvider: 'zerossl' }));
    assert.ok(result.includes('acme_ca https://acme.zerossl.com/v2/DV90'));
  });

  it('includes acme_eab for ZeroSSL when EAB keys provided', () => {
    const result = buildCaddyConfig(
      makeConfig({
        acmeProvider: 'zerossl',
        zerosslEabKeyId: 'zero-key-id',
        zerosslEabKey: 'zero-mac-key',
      }),
    );
    assert.ok(result.includes('acme_eab'));
    assert.ok(result.includes('key_id zero-key-id'));
    assert.ok(result.includes('mac_key zero-mac-key'));
  });

  it('includes acme_eab for Actalis with base64url-converted key', () => {
    const result = buildCaddyConfig(
      makeConfig({
        acmeProvider: 'actalis',
        actalisEabKeyId: 'act-key-id',
        actalisEabKey: 'a+b/c==',
      }),
    );
    assert.ok(result.includes('acme_eab'));
    assert.ok(result.includes('key_id act-key-id'));
    assert.ok(result.includes('mac_key a-b_c'));
  });

  it('includes acme_ca for Buypass', () => {
    const result = buildCaddyConfig(makeConfig({ acmeProvider: 'buypass' }));
    assert.ok(result.includes('acme_ca https://api.buypass.com/acme/directory'));
  });

  it('includes custom ACME URL and optional EAB for custom provider', () => {
    const withoutEab = buildCaddyConfig(
      makeConfig({
        acmeProvider: 'custom',
        customAcmeUrl: 'https://acme.custom.example/dir',
      }),
    );
    assert.ok(withoutEab.includes('acme_ca https://acme.custom.example/dir'));
    assert.ok(!withoutEab.includes('acme_eab'));

    const withEab = buildCaddyConfig(
      makeConfig({
        acmeProvider: 'custom',
        customAcmeUrl: 'https://acme.custom.example/dir',
        customEabKeyId: 'custom-id',
        customEabKey: 'custom-key',
      }),
    );
    assert.ok(withEab.includes('acme_ca https://acme.custom.example/dir'));
    assert.ok(withEab.includes('acme_eab'));
    assert.ok(withEab.includes('key_id custom-id'));
    assert.ok(withEab.includes('mac_key custom-key'));
  });

  it('always includes basic_auth block with __HASH__ placeholder', () => {
    const result = buildCaddyConfig(makeConfig());
    assert.ok(result.includes('basic_auth'));
    assert.ok(result.includes('devbox __HASH__'));
  });
});
