import { describe, it } from 'node:test';
import assert from 'node:assert';
import { globalConfigSchema, serverSchema, profilesSchema } from '../src/lib/types.ts';
import { sshPublicKeySchema } from '../src/lib/utils/validation.ts';

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
    assert.ok(result.success, 'should accept valid config');
  });

  it('rejects config with missing autoDelete', () => {
    const { autoDelete: _, ...partial } = validConfig;
    const result = globalConfigSchema.safeParse(partial);
    assert.ok(!result.success, 'should reject config missing autoDelete');
  });

  it('rejects config with invalid acmeProvider', () => {
    const invalid = {
      ...validConfig,
      services: { ...validConfig.services, acmeProvider: 'invalid' },
    };
    const result = globalConfigSchema.safeParse(invalid);
    assert.ok(!result.success, 'should reject invalid acmeProvider');
  });

  it('rejects config with invalid customCloudInit mode', () => {
    const invalid = {
      ...validConfig,
      customCloudInit: { mode: 'append', yaml: '' },
    };
    const result = globalConfigSchema.safeParse(invalid);
    assert.ok(!result.success, 'should reject invalid customCloudInit mode');
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
    assert.ok(result.success, 'should accept valid server');
  });

  it('rejects server with invalid status', () => {
    const invalid = { ...validServer, status: 'exploding' };
    const result = serverSchema.safeParse(invalid);
    assert.ok(!result.success, 'should reject invalid status');
  });

  it('rejects server with missing id', () => {
    const { id: _, ...noId } = validServer;
    const result = serverSchema.safeParse(noId);
    assert.ok(!result.success, 'should reject missing id');
  });
});

describe('profilesSchema', () => {
  it('accepts valid profiles record', () => {
    const profiles = {
      'abc-123': { id: 'abc-123', name: 'Dev', overrides: { 'hetzner.serverType': 'cx32' } },
    };
    const result = profilesSchema.safeParse(profiles);
    assert.ok(result.success, 'should accept valid profiles');
  });

  it('accepts empty profiles', () => {
    const result = profilesSchema.safeParse({});
    assert.ok(result.success, 'should accept empty profiles');
  });

  it('rejects profile with missing name', () => {
    const invalid = { 'abc-123': { id: 'abc-123', overrides: {} } };
    const result = profilesSchema.safeParse(invalid);
    assert.ok(!result.success, 'should reject profile missing name');
  });
});

describe('sshPublicKeySchema', () => {
  it('accepts valid ed25519 key', () => {
    const result = sshPublicKeySchema.safeParse('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@host');
    assert.ok(result.success, 'should accept valid ed25519 key');
  });

  it('accepts valid rsa key', () => {
    const result = sshPublicKeySchema.safeParse('ssh-rsa AAAAB3NzaC1yc2EAAAAtest user@host');
    assert.ok(result.success, 'should accept valid rsa key');
  });

  it('rejects empty string', () => {
    const result = sshPublicKeySchema.safeParse('');
    assert.ok(!result.success, 'should reject empty string');
    assert.equal(result.error.issues[0]?.message, 'SSH key is required');
  });

  it('rejects private key', () => {
    const result = sshPublicKeySchema.safeParse('-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----');
    assert.ok(!result.success, 'should reject private key');
    assert.ok(result.error.issues[0]?.message.includes('private key'), 'error should mention private key');
  });

  it('rejects multiple keys', () => {
    const result = sshPublicKeySchema.safeParse('ssh-ed25519 AAAA key1\nssh-ed25519 BBBB key2');
    assert.ok(!result.success, 'should reject multiple keys');
    assert.equal(result.error.issues[0]?.message, 'Please enter only one SSH key');
  });

  it('rejects unrecognized format', () => {
    const result = sshPublicKeySchema.safeParse('not-a-key');
    assert.ok(!result.success, 'should reject unrecognized format');
    assert.ok(result.error.issues[0]?.message.includes('Unrecognized'), 'should say unrecognized');
  });
});
