import { describe, it } from 'node:test';
import assert from 'node:assert';
import { mergeCustomCloudInit, generateCloudInit } from '../src/lib/utils/cloudinit.ts';

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
    assert.ok(Array.isArray(result.packages));
    const pkgs = result.packages;
    assert.ok(pkgs.includes('python3'), 'should include python3');
    assert.ok(pkgs.includes('rust'), 'should include rust');
    assert.ok(pkgs.includes('git'), 'should include git');
    // git should appear only once (deduplicated)
    assert.equal(pkgs.filter((p) => p === 'git').length, 1, 'git should be deduplicated');
  });

  it('inserts user runcmd before "ready" marker', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, 'runcmd:\n  - echo hello\n  - echo world');
    const cmds = result.runcmd;
    const readyIdx = cmds.findIndex((c) => typeof c === 'string' && c.includes('devbox-progress ready'));
    const helloIdx = cmds.findIndex((c) => c === 'echo hello');
    const worldIdx = cmds.findIndex((c) => c === 'echo world');
    assert.ok(helloIdx >= 0, 'should include user command');
    assert.ok(helloIdx < readyIdx, 'user commands should be before ready');
    assert.ok(worldIdx < readyIdx, 'user commands should be before ready');
  });

  it('appends user write_files', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, 'write_files:\n  - path: /etc/custom.conf\n    content: hello');
    const files = result.write_files;
    assert.ok(
      files.some((f) => f.path === '/etc/custom.conf'),
      'should include custom file',
    );
  });

  it('skips user write_files with conflicting paths', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(
      base,
      'write_files:\n  - path: /usr/local/bin/devbox-progress\n    content: hacked',
    );
    const files = result.write_files;
    // The conflicting entry should be skipped
    const progressFiles = files.filter((f) => f.path === '/usr/local/bin/devbox-progress');
    assert.equal(progressFiles.length, 1, 'should only have original devbox-progress');
    assert.ok(progressFiles[0].content.includes('#!/bin/bash'), 'should keep original content');
  });

  it('ignores blocked keys (users, apt, package_update, package_upgrade)', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(
      base,
      'users:\n  - name: hacker\napt:\n  sources: {}\npackage_update: false\npackage_upgrade: false',
    );
    // users should remain unchanged
    assert.deepStrictEqual(result.users, base.users, 'users should not be modified');
    assert.deepStrictEqual(result.apt, base.apt, 'apt should not be modified');
    assert.equal(result.package_update, true, 'package_update should not be modified');
    assert.equal(result.package_upgrade, true, 'package_upgrade should not be modified');
  });

  it('passes through extra top-level keys', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(
      base,
      'bootcmd:\n  - echo boot\nsnap:\n  commands:\n    - snap install something',
    );
    assert.ok(Array.isArray(result.bootcmd), 'should include bootcmd');
    assert.ok(result.snap, 'should include snap');
  });

  it('returns base config unchanged for empty custom YAML', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, '');
    // Empty string parses to null in YAML, so should return base unchanged
    assert.deepStrictEqual(result, base);
  });

  it('returns base config unchanged for invalid YAML', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, '{{invalid: yaml:::');
    assert.deepStrictEqual(result, base);
  });

  it('returns base config unchanged for non-mapping YAML (scalar)', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, 'just a string');
    assert.deepStrictEqual(result, base);
  });

  it('returns base config unchanged for non-mapping YAML (array)', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, '- item1\n- item2');
    assert.deepStrictEqual(result, base);
  });

  it('skips non-array packages value gracefully', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, 'packages: not-an-array');
    // Should not crash, packages should remain unchanged
    assert.deepStrictEqual(result.packages, base.packages);
  });

  it('skips non-array write_files value gracefully', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, 'write_files: not-an-array');
    assert.deepStrictEqual(result.write_files, base.write_files);
  });

  it('skips non-array runcmd value gracefully', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, 'runcmd: not-an-array');
    assert.deepStrictEqual(result.runcmd, base.runcmd);
  });

  it('skips write_files entries without a path property', () => {
    const base = makeBaseConfig();
    const result = mergeCustomCloudInit(base, 'write_files:\n  - content: no-path-here');
    // Entry without path should be rejected; only base entries remain
    assert.equal(result.write_files.length, base.write_files.length);
  });
});

describe('generateCloudInit with custom cloud-init', () => {
  it('returns user YAML in replace mode', () => {
    const config = {
      ...minimalConfig,
      customCloudInit: { yaml: '#cloud-config\npackages:\n  - vim', mode: 'replace' },
    };
    const output = generateCloudInit('test', 'token', config);
    assert.equal(output, '#cloud-config\npackages:\n  - vim');
  });

  it('prepends #cloud-config header in replace mode if missing', () => {
    const config = {
      ...minimalConfig,
      customCloudInit: { yaml: 'packages:\n  - vim', mode: 'replace' },
    };
    const output = generateCloudInit('test', 'token', config);
    assert.ok(output.startsWith('#cloud-config\n'), 'should prepend header');
    assert.ok(output.includes('packages:'), 'should contain user YAML');
  });

  it('generates base config unchanged when custom YAML is empty', () => {
    const config = {
      ...minimalConfig,
      customCloudInit: { yaml: '', mode: 'merge' },
    };
    const output = generateCloudInit('test', 'token', config);
    assert.ok(output.startsWith('#cloud-config'), 'should have cloud-config header');
    assert.ok(output.includes('devbox-progress'), 'should contain base config');
  });

  it('merges custom packages in merge mode via generateCloudInit', () => {
    const config = {
      ...minimalConfig,
      customCloudInit: { yaml: 'packages:\n  - python3', mode: 'merge' },
    };
    const output = generateCloudInit('test', 'token', config);
    assert.ok(output.includes('python3'), 'should include merged package');
    assert.ok(output.includes('devbox-progress'), 'should still include base config');
  });
});
