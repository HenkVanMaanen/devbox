import { describe, expect, it } from 'vitest';

import { globalConfigSchema, serverSchema, profilesSchema } from '$lib/types';
import { sshPublicKeySchema } from '$lib/utils/validation';

// Minimal valid config matching DEFAULT_CONFIG shape
const validConfig = {
  autoDelete: { enabled: true, timeoutMinutes: 90, warningMinutes: 5 },
  chezmoi: { ageKey: '', repoUrl: '' },
  customCloudInit: { mode: 'merge', yaml: '' },
  git: { credential: { host: 'github.com', token: '', username: '' } },
  hetzner: { baseImage: 'ubuntu-24.04', location: 'fsn1', serverType: 'cx22' },
  services: {
    accessToken: 'abc12345',
    acmeEmail: '',
    acmeProvider: 'zerossl',
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
  ssh: { keys: [{ name: 'test', pubKey: 'ssh-ed25519 AAAA test@dev' }] },
};

describe('globalConfigSchema', () => {
  it('accepts valid config', () => {
    const result = globalConfigSchema.safeParse(validConfig);
    expect(result.success).toBe(true);
  });

  it('rejects config with missing autoDelete', () => {
    const { autoDelete: _, ...partial } = validConfig;
    const result = globalConfigSchema.safeParse(partial);
    expect(result.success).toBe(false);
  });

  it('rejects config with invalid acmeProvider', () => {
    const invalid = {
      ...validConfig,
      services: { ...validConfig.services, acmeProvider: 'invalid' },
    };
    const result = globalConfigSchema.safeParse(invalid);
    expect(result.success).toBe(false);
  });

  it('rejects config with invalid customCloudInit mode', () => {
    const invalid = {
      ...validConfig,
      customCloudInit: { mode: 'append', yaml: '' },
    };
    const result = globalConfigSchema.safeParse(invalid);
    expect(result.success).toBe(false);
  });
});

describe('serverSchema', () => {
  const validServer = {
    created: '2025-01-01T00:00:00Z',
    datacenter: { location: { city: 'Frankfurt', country: 'DE' }, name: 'fsn1-dc14' },
    id: 123,
    labels: { managed: 'devbox' },
    name: 'peppy-penguin',
    public_net: { ipv4: { ip: '1.2.3.4' }, ipv6: { ip: '2001:db8::1' } },
    server_type: { cores: 2, description: 'CX22', disk: 40, memory: 4, name: 'cx22' },
    status: 'running',
  };

  it('accepts valid server', () => {
    const result = serverSchema.safeParse(validServer);
    expect(result.success).toBe(true);
  });

  it('rejects server with invalid status', () => {
    const invalid = { ...validServer, status: 'exploding' };
    const result = serverSchema.safeParse(invalid);
    expect(result.success).toBe(false);
  });

  it('rejects server with missing id', () => {
    const { id: _, ...noId } = validServer;
    const result = serverSchema.safeParse(noId);
    expect(result.success).toBe(false);
  });
});

describe('profilesSchema', () => {
  it('accepts valid profiles record', () => {
    const profiles = {
      'abc-123': { id: 'abc-123', name: 'Dev', overrides: { 'hetzner.serverType': 'cx32' } },
    };
    const result = profilesSchema.safeParse(profiles);
    expect(result.success).toBe(true);
  });

  it('accepts empty profiles', () => {
    const result = profilesSchema.safeParse({});
    expect(result.success).toBe(true);
  });

  it('rejects profile with missing name', () => {
    const invalid = { 'abc-123': { id: 'abc-123', overrides: {} } };
    const result = profilesSchema.safeParse(invalid);
    expect(result.success).toBe(false);
  });
});

describe('sshPublicKeySchema', () => {
  it('accepts valid ed25519 key', () => {
    const result = sshPublicKeySchema.safeParse('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@host');
    expect(result.success).toBe(true);
  });

  it('accepts valid rsa key', () => {
    const result = sshPublicKeySchema.safeParse('ssh-rsa AAAAB3NzaC1yc2EAAAAtest user@host');
    expect(result.success).toBe(true);
  });

  it('rejects empty string', () => {
    const result = sshPublicKeySchema.safeParse('');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toBe('SSH key is required');
  });

  it('rejects private key', () => {
    const result = sshPublicKeySchema.safeParse('-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toContain('private key');
  });

  it('rejects multiple keys', () => {
    const result = sshPublicKeySchema.safeParse('ssh-ed25519 AAAA key1\nssh-ed25519 BBBB key2');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toBe('Please enter only one SSH key');
  });

  it('rejects unrecognized format', () => {
    const result = sshPublicKeySchema.safeParse('not-a-key');
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toContain('Unrecognized');
  });
});
