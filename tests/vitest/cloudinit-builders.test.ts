import { describe, expect, it } from 'vitest';

import { shellEscape, toBase64URL, buildGitCredentials, buildCaddyConfig } from '$lib/utils/cloudinit-builders';

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
    expect(shellEscape('')).toBe('');
  });

  it('escapes double quotes', () => {
    expect(shellEscape('he said "hi"')).toBe('he said \\"hi\\"');
  });

  it('escapes dollar signs', () => {
    expect(shellEscape('$HOME')).toBe('\\$HOME');
  });

  it('escapes backticks', () => {
    expect(shellEscape('`cmd`')).toBe('\\`cmd\\`');
  });

  it('escapes backslashes', () => {
    expect(shellEscape('a\\b')).toBe('a\\\\b');
  });

  it('escapes exclamation marks', () => {
    expect(shellEscape('hello!')).toBe('hello\\!');
  });

  it('removes newlines', () => {
    expect(shellEscape('line1\nline2')).toBe('line1line2');
  });

  it('prevents command injection via $(...)', () => {
    expect(shellEscape('$(rm -rf /)')).toBe('\\$(rm -rf /)');
  });

  it('escapes all metacharacters in a combined string', () => {
    expect(shellEscape('$HOME\\path "file" `cmd` end!')).toBe('\\$HOME\\\\path \\"file\\" \\`cmd\\` end\\!');
  });
});

describe('toBase64URL', () => {
  it('returns empty string for empty input', () => {
    expect(toBase64URL('')).toBe('');
  });

  it('replaces + with -', () => {
    expect(toBase64URL('a+b')).toBe('a-b');
  });

  it('replaces / with _', () => {
    expect(toBase64URL('a/b')).toBe('a_b');
  });

  it('strips trailing = padding', () => {
    expect(toBase64URL('abc==')).toBe('abc');
  });

  it('handles combined replacements', () => {
    expect(toBase64URL('a+b/c==')).toBe('a-b_c');
  });
});

describe('buildGitCredentials', () => {
  it('returns credential URL for valid input', () => {
    const result = buildGitCredentials({ host: 'github.com', username: 'user', token: 'tok123' });
    expect(result).toBe('https://user:tok123@github.com\n');
  });

  it('URI-encodes username and token with special characters', () => {
    const result = buildGitCredentials({ host: 'github.com', username: 'u@ser', token: 'p@ss/word' });
    expect(result).toBe('https://u%40ser:p%40ss%2Fword@github.com\n');
  });

  it('returns empty string when host is empty', () => {
    expect(buildGitCredentials({ host: '', username: 'user', token: 'tok' })).toBe('');
  });

  it('returns empty string when username is empty', () => {
    expect(buildGitCredentials({ host: 'github.com', username: '', token: 'tok' })).toBe('');
  });

  it('returns empty string when token is empty', () => {
    expect(buildGitCredentials({ host: 'github.com', username: 'user', token: '' })).toBe('');
  });

  it('strips non-hostname characters from host', () => {
    const result = buildGitCredentials({ host: 'git;rm', username: 'user', token: 'tok' });
    expect(result).toBe('https://user:tok@gitrm\n');
  });

  it('produces a URL ending with newline', () => {
    const result = buildGitCredentials({ host: 'github.com', username: 'user', token: 'tok' });
    expect(result.endsWith('\n')).toBe(true);
    expect(result.split('\n')).toHaveLength(2); // content + trailing empty
  });
});

describe('buildCaddyConfig', () => {
  it('always includes on_demand_tls block', () => {
    const result = buildCaddyConfig(makeConfig());
    expect(result).toContain('on_demand_tls');
    expect(result).toContain('ask http://localhost:65531/verify-domain');
  });

  it('includes ACME email when provided', () => {
    const result = buildCaddyConfig(makeConfig({ acmeEmail: 'user@example.com' }));
    expect(result).toContain('email user@example.com');
  });

  it('rejects ACME email containing spaces or braces', () => {
    const withSpace = buildCaddyConfig(makeConfig({ acmeEmail: 'user @example.com' }));
    expect(withSpace).not.toContain('email ');

    const withBrace = buildCaddyConfig(makeConfig({ acmeEmail: 'user{@example.com' }));
    expect(withBrace).not.toContain('email ');

    const withCloseBrace = buildCaddyConfig(makeConfig({ acmeEmail: 'user}@example.com' }));
    expect(withCloseBrace).not.toContain('email ');
  });

  it("does not add acme_ca for Let's Encrypt (default provider)", () => {
    const result = buildCaddyConfig(makeConfig({ acmeProvider: 'letsencrypt' }));
    expect(result).not.toContain('acme_ca');
  });

  it('includes acme_ca for ZeroSSL', () => {
    const result = buildCaddyConfig(makeConfig({ acmeProvider: 'zerossl' }));
    expect(result).toContain('acme_ca https://acme.zerossl.com/v2/DV90');
  });

  it('includes acme_eab for ZeroSSL when EAB keys provided', () => {
    const result = buildCaddyConfig(
      makeConfig({
        acmeProvider: 'zerossl',
        zerosslEabKeyId: 'zero-key-id',
        zerosslEabKey: 'zero-mac-key',
      }),
    );
    expect(result).toContain('acme_eab');
    expect(result).toContain('key_id zero-key-id');
    expect(result).toContain('mac_key zero-mac-key');
  });

  it('includes acme_eab for Actalis with base64url-converted key', () => {
    const result = buildCaddyConfig(
      makeConfig({
        acmeProvider: 'actalis',
        actalisEabKeyId: 'act-key-id',
        actalisEabKey: 'a+b/c==',
      }),
    );
    expect(result).toContain('acme_eab');
    expect(result).toContain('key_id act-key-id');
    expect(result).toContain('mac_key a-b_c');
  });

  it('includes acme_ca for Buypass', () => {
    const result = buildCaddyConfig(makeConfig({ acmeProvider: 'buypass' }));
    expect(result).toContain('acme_ca https://api.buypass.com/acme/directory');
  });

  it('includes custom ACME URL and optional EAB for custom provider', () => {
    const withoutEab = buildCaddyConfig(
      makeConfig({
        acmeProvider: 'custom',
        customAcmeUrl: 'https://acme.custom.example/dir',
      }),
    );
    expect(withoutEab).toContain('acme_ca https://acme.custom.example/dir');
    expect(withoutEab).not.toContain('acme_eab');

    const withEab = buildCaddyConfig(
      makeConfig({
        acmeProvider: 'custom',
        customAcmeUrl: 'https://acme.custom.example/dir',
        customEabKeyId: 'custom-id',
        customEabKey: 'custom-key',
      }),
    );
    expect(withEab).toContain('acme_ca https://acme.custom.example/dir');
    expect(withEab).toContain('acme_eab');
    expect(withEab).toContain('key_id custom-id');
    expect(withEab).toContain('mac_key custom-key');
  });

  it('always includes basic_auth block with __HASH__ placeholder', () => {
    const result = buildCaddyConfig(makeConfig());
    expect(result).toContain('basic_auth');
    expect(result).toContain('devbox __HASH__');
  });
});
