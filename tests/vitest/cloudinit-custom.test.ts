import { describe, expect, it } from 'vitest';

import { mergeCustomCloudInit, generateCloudInit } from '$lib/utils/cloudinit';

// Minimal base config matching generated cloud-init structure
function makeBaseConfig() {
  return {
    package_update: true,
    package_upgrade: true,
    apt: { sources: {} },
    packages: ['git', 'curl', 'nodejs'],
    users: [{ name: 'dev', shell: '/bin/bash' }],
    write_files: [
      { path: '/usr/local/bin/devbox-progress', permissions: '0755', content: '#!/bin/bash\n' },
      { path: '/usr/local/bin/devbox-daemon', permissions: '0755', content: '#!/bin/bash\n' },
    ],
    runcmd: [
      '/usr/local/bin/devbox-progress configuring',
      'ufw --force enable',
      '/usr/local/bin/devbox-progress ready',
    ],
  };
}

// Minimal GlobalConfig fixture for generateCloudInit tests
const minimalConfig = {
  ssh: { keys: [{ name: 'test', pubKey: 'ssh-ed25519 AAAA test@dev' }] },
  git: { credential: { host: 'github.com', username: 'user', token: 'ghp_test123' } },
  chezmoi: { repoUrl: '', ageKey: '' },
  services: {
    accessToken: 'test-token',
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

describe('mergeCustomCloudInit', () => {
  it('appends user packages and deduplicates', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, 'packages:\n  - python3\n  - git\n  - rust');
    expect(Array.isArray(result.packages)).toBe(true);
    const pkgs = result.packages as string[];
    expect(pkgs).toContain('python3');
    expect(pkgs).toContain('rust');
    expect(pkgs).toContain('git');
    // git should appear only once (deduplicated)
    expect(pkgs.filter((p) => p === 'git')).toHaveLength(1);
  });

  it('inserts user runcmd before "ready" marker', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, 'runcmd:\n  - echo hello\n  - echo world');
    const cmds = result.runcmd as string[];
    const readyIdx = cmds.findIndex((c) => typeof c === 'string' && c.includes('devbox-progress ready'));
    const helloIdx = cmds.findIndex((c) => c === 'echo hello');
    const worldIdx = cmds.findIndex((c) => c === 'echo world');
    expect(helloIdx).toBeGreaterThanOrEqual(0);
    expect(helloIdx).toBeLessThan(readyIdx);
    expect(worldIdx).toBeLessThan(readyIdx);
  });

  it('appends user write_files', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, 'write_files:\n  - path: /etc/custom.conf\n    content: hello');
    const files = result.write_files as { path: string }[];
    expect(files.some((f) => f.path === '/etc/custom.conf')).toBe(true);
  });

  it('skips user write_files with conflicting paths', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(
      base,
      'write_files:\n  - path: /usr/local/bin/devbox-progress\n    content: hacked',
    );
    const files = result.write_files as { content: string; path: string }[];
    // The conflicting entry should be skipped
    const progressFiles = files.filter((f) => f.path === '/usr/local/bin/devbox-progress');
    expect(progressFiles).toHaveLength(1);
    expect(progressFiles[0]?.content).toContain('#!/bin/bash');
  });

  it('ignores blocked keys (users, apt, package_update, package_upgrade)', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(
      base,
      'users:\n  - name: hacker\napt:\n  sources: {}\npackage_update: false\npackage_upgrade: false',
    );
    // users should remain unchanged
    expect(result.users).toEqual(base.users);
    expect(result.apt).toEqual(base.apt);
    expect(result.package_update).toBe(true);
    expect(result.package_upgrade).toBe(true);
  });

  it('passes through extra top-level keys', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(
      base,
      'bootcmd:\n  - echo boot\nsnap:\n  commands:\n    - snap install something',
    );
    expect(Array.isArray(result.bootcmd)).toBe(true);
    expect(result.snap).toBeTruthy();
  });

  it('returns base config unchanged for empty custom YAML', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, '');
    // Empty string parses to null in YAML, so should return base unchanged
    expect(result).toEqual(base);
  });

  it('returns base config unchanged for invalid YAML', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, '{{invalid: yaml:::');
    expect(result).toEqual(base);
  });

  it('returns base config unchanged for non-mapping YAML (scalar)', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, 'just a string');
    expect(result).toEqual(base);
  });

  it('returns base config unchanged for non-mapping YAML (array)', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, '- item1\n- item2');
    expect(result).toEqual(base);
  });

  it('skips non-array packages value gracefully', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, 'packages: not-an-array');
    // Should not crash, packages should remain unchanged
    expect(result.packages).toEqual(base.packages);
  });

  it('skips non-array write_files value gracefully', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, 'write_files: not-an-array');
    expect(result.write_files).toEqual(base.write_files);
  });

  it('skips non-array runcmd value gracefully', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, 'runcmd: not-an-array');
    expect(result.runcmd).toEqual(base.runcmd);
  });

  it('skips write_files entries without a path property', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, 'write_files:\n  - content: no-path-here');
    // Entry without path should be rejected; only base entries remain
    expect(result.write_files).toHaveLength(base.write_files.length);
  });
});

describe('generateCloudInit with custom cloud-init', () => {
  it('returns user YAML in replace mode', () => {
    const config = {
      ...minimalConfig,
      customCloudInit: { yaml: '#cloud-config\npackages:\n  - vim', mode: 'replace' },
    };
    const output = generateCloudInit('test', 'token', config);
    expect(output).toBe('#cloud-config\npackages:\n  - vim');
  });

  it('prepends #cloud-config header in replace mode if missing', () => {
    const config = {
      ...minimalConfig,
      customCloudInit: { yaml: 'packages:\n  - vim', mode: 'replace' },
    };
    const output = generateCloudInit('test', 'token', config);
    expect(output.startsWith('#cloud-config\n')).toBe(true);
    expect(output).toContain('packages:');
  });

  it('generates base config unchanged when custom YAML is empty', () => {
    const config = {
      ...minimalConfig,
      customCloudInit: { yaml: '', mode: 'merge' },
    };
    const output = generateCloudInit('test', 'token', config);
    expect(output.startsWith('#cloud-config')).toBe(true);
    expect(output).toContain('devbox-progress');
  });

  it('merges custom packages in merge mode via generateCloudInit', () => {
    const config = {
      ...minimalConfig,
      customCloudInit: { yaml: 'packages:\n  - python3', mode: 'merge' },
    };
    const output = generateCloudInit('test', 'token', config);
    expect(output).toContain('python3');
    expect(output).toContain('devbox-progress');
  });
});
