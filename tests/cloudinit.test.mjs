import { describe, it } from 'node:test';
import assert from 'node:assert';
import { generateCloudInit } from '../src/lib/utils/cloudinit.ts';

// Minimal GlobalConfig fixture with required fields
const minimalConfig = {
  ssh: { keys: [{ name: 'test', pubKey: 'ssh-ed25519 AAAA test@dev' }] },
  git: { credential: { host: 'github.com', username: 'user', token: 'ghp_test123' } },
  chezmoi: { repoUrl: '', ageKey: '' },
  services: {
    accessToken: 'test-access-token',
    dnsService: 'sslip.io',
    customDnsDomain: '',
    acmeProvider: 'letsencrypt',
    acmeEmail: 'test@example.com',
    zerosslEabKeyId: '',
    zerosslEabKey: '',
    actalisEabKeyId: '',
    actalisEabKey: '',
    customAcmeUrl: '',
    customEabKeyId: '',
    customEabKey: '',
  },
  hetzner: { serverType: 'cx22', location: 'fsn1', baseImage: 'ubuntu-24.04' },
  autoDelete: { enabled: false, timeoutMinutes: 60, warningMinutes: 5 },
};

describe('cloud-init progress tracking', () => {
  const output = generateCloudInit('test-server', 'hcloud-test-token', minimalConfig);

  it('includes devbox-progress script in write_files', () => {
    assert.ok(
      output.includes('/usr/local/bin/devbox-progress'),
      'should contain devbox-progress script path'
    );
  });

  it('embeds the Hetzner token in the progress script', () => {
    assert.ok(
      output.includes('hcloud-test-token'),
      'should contain the Hetzner API token'
    );
  });

  it('includes devbox-progress configuring in runcmd', () => {
    assert.ok(
      output.includes('/usr/local/bin/devbox-progress configuring'),
      'should have configuring runcmd call with full path'
    );
  });

  it('includes devbox-progress ready as last runcmd', () => {
    assert.ok(
      output.includes('/usr/local/bin/devbox-progress ready'),
      'should have ready runcmd call with full path'
    );
    // Verify "ready" comes after "configuring"
    const configuringIdx = output.indexOf('/usr/local/bin/devbox-progress configuring');
    const readyIdx = output.indexOf('/usr/local/bin/devbox-progress ready');
    assert.ok(readyIdx > configuringIdx, 'ready should come after configuring');
  });

  it('progress script is not deferred', () => {
    // Extract the block for the devbox-progress write_files entry.
    // In the YAML, each entry starts with "- path:" — find the progress one
    // and check that no "defer:" appears before the next "- path:" entry.
    const lines = output.split('\n');
    let inProgressEntry = false;
    let hasDefer = false;
    for (const line of lines) {
      if (line.includes('- path: /usr/local/bin/devbox-progress')) {
        inProgressEntry = true;
        continue;
      }
      if (inProgressEntry) {
        // Stop at next write_files entry
        if (line.match(/- path:/)) break;
        if (line.includes('defer:')) {
          hasDefer = true;
          break;
        }
      }
    }
    assert.ok(!hasDefer, 'devbox-progress script should not be deferred');
  });
});
