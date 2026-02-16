import { describe, expect, it } from 'vitest';

import { generateCloudInit } from '$lib/utils/cloudinit';

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
  customCloudInit: { yaml: '', mode: 'merge' },
};

describe('cloud-init progress tracking', () => {
  const output = generateCloudInit('test-server', 'hcloud-test-token', minimalConfig);

  it('includes devbox-progress script in write_files', () => {
    expect(output).toContain('/usr/local/bin/devbox-progress');
  });

  it('embeds the Hetzner token in the progress script', () => {
    expect(output).toContain('hcloud-test-token');
  });

  it('includes devbox-progress configuring in runcmd', () => {
    expect(output).toContain('/usr/local/bin/devbox-progress configuring');
  });

  it('includes devbox-progress ready as last runcmd', () => {
    expect(output).toContain('/usr/local/bin/devbox-progress ready');
    // Verify "ready" comes after "configuring"
    const configuringIdx = output.indexOf('/usr/local/bin/devbox-progress configuring');
    const readyIdx = output.indexOf('/usr/local/bin/devbox-progress ready');
    expect(readyIdx).toBeGreaterThan(configuringIdx);
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
    expect(hasDefer).toBe(false);
  });
});
