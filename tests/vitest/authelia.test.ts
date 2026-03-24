import { describe, expect, it } from 'vitest';

import {
  AUTHELIA_VERSION,
  buildAutheliaConfig,
  buildAutheliaUsers,
  getDomainPrefix,
} from '$lib/utils/cloudinit-builders';

import type { GlobalConfig } from '$lib/types';

// Helper to build a minimal GlobalConfig
function makeConfig(overrides: Partial<GlobalConfig> = {}): GlobalConfig {
  return {
    auth: { users: [] },
    autoDelete: { enabled: true, timeoutMinutes: 60, warningMinutes: 5 },
    chezmoi: { ageKey: '', repoUrl: '' },
    customCloudInit: { mode: 'merge', yaml: '' },
    git: { credential: { host: '', username: '', token: '' } },
    hetzner: { baseImage: 'ubuntu-24.04', location: 'fsn1', serverType: 'cx22' },
    services: {
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
    },
    cloudflare: { apiToken: '', hostname: '', zoneId: '' },
    ssh: { hostKey: { privateKey: '', publicKey: '' }, keys: [] },
    ...overrides,
  } as GlobalConfig;
}

describe('AUTHELIA_VERSION', () => {
  it('is defined as a non-empty string', () => {
    expect(typeof AUTHELIA_VERSION).toBe('string');
    expect(AUTHELIA_VERSION.length).toBeGreaterThan(0);
  });
});

describe('getDomainPrefix', () => {
  it('returns "dev." for wildcard DNS services', () => {
    expect(getDomainPrefix('sslip.io')).toBe('dev.');
    expect(getDomainPrefix('nip.io')).toBe('dev.');
    expect(getDomainPrefix('traefik.me')).toBe('dev.');
  });

  it('returns "" for custom DNS', () => {
    expect(getDomainPrefix('custom')).toBe('');
  });
});

describe('buildAutheliaConfig', () => {
  it('returns YAML with expected placeholders', () => {
    const config = makeConfig();
    const yaml = buildAutheliaConfig(config);
    expect(yaml).toContain('__IP__');
    expect(yaml).toContain('__DNS_SERVICE__');
    expect(yaml).toContain('__SESSION_SECRET__');
    expect(yaml).toContain('__ENCRYPTION_KEY__');
  });

  it('sets 16h session expiration and inactivity', () => {
    const config = makeConfig();
    const yaml = buildAutheliaConfig(config);
    expect(yaml).toContain('expiration: 16h');
    expect(yaml).toContain('inactivity: 16h');
  });

  it('uses dev. prefix for wildcard DNS services', () => {
    const config = makeConfig({ services: { ...makeConfig().services, dnsService: 'sslip.io' } });
    const yaml = buildAutheliaConfig(config);
    expect(yaml).toContain('dev.__IP__.__DNS_SERVICE__');
  });

  it('uses no prefix for custom DNS', () => {
    const config = makeConfig({ services: { ...makeConfig().services, dnsService: 'custom' } });
    const yaml = buildAutheliaConfig(config);
    expect(yaml).toContain("domain: '__IP__.__DNS_SERVICE__'");
  });

  it('configures one_factor access control', () => {
    const config = makeConfig();
    const yaml = buildAutheliaConfig(config);
    expect(yaml).toContain('default_policy: one_factor');
  });

  it('configures file-based authentication backend with watch', () => {
    const config = makeConfig();
    const yaml = buildAutheliaConfig(config);
    expect(yaml).toContain('path: /etc/authelia/users.yml');
    expect(yaml).toContain('watch: true');
  });

  it('configures local SQLite storage', () => {
    const config = makeConfig();
    const yaml = buildAutheliaConfig(config);
    expect(yaml).toContain('path: /var/lib/authelia/db.sqlite3');
  });

  it('disables TOTP and WebAuthn', () => {
    const config = makeConfig();
    const yaml = buildAutheliaConfig(config);
    expect(yaml).toContain('totp:');
    expect(yaml).toContain('disable: true');
    expect(yaml).toContain('webauthn:');
  });

  it('listens on localhost:9091', () => {
    const config = makeConfig();
    const yaml = buildAutheliaConfig(config);
    expect(yaml).toContain("address: 'tcp://127.0.0.1:9091/'");
  });
});

describe('buildAutheliaUsers', () => {
  it('generates valid users YAML for a single user', () => {
    const yaml = buildAutheliaUsers([{ username: 'admin', passwordHash: '$argon2id$hash' }]);
    expect(yaml).toContain('users:');
    expect(yaml).toContain('  admin:');
    expect(yaml).toContain("    displayname: 'admin'");
    expect(yaml).toContain('    password: "$argon2id$hash"');
    expect(yaml).toContain("    email: 'admin@devbox.local'");
  });

  it('generates valid users YAML for multiple users', () => {
    const yaml = buildAutheliaUsers([
      { username: 'alice', passwordHash: '$hash1' },
      { username: 'bob', passwordHash: '$hash2' },
    ]);
    expect(yaml).toContain('  alice:');
    expect(yaml).toContain('  bob:');
    expect(yaml).toContain('    password: "$hash1"');
    expect(yaml).toContain('    password: "$hash2"');
  });

  it('handles empty users array', () => {
    const yaml = buildAutheliaUsers([]);
    expect(yaml).toBe('users: {}\n');
  });
});
