import { describe, expect, it } from 'vitest';

import {
  buildCaddyConfig,
  buildDaemonConfig,
  buildDaemonScript,
  buildOverviewConfig,
  buildOverviewPage,
  defaultThemeColors,
} from '$lib/utils/cloudinit-builders';

import type { GlobalConfig } from '$lib/types';

// Helper to build a minimal GlobalConfig
function makeConfig(overrides: Partial<GlobalConfig> = {}): GlobalConfig {
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
    },
    cloudflare: { apiToken: '', hostname: '', zoneId: '' },
    ssh: { hostKey: { privateKey: '', publicKey: '' }, keys: [] },
    ...overrides,
  } as GlobalConfig;
}

describe('buildDaemonScript', () => {
  it('is a valid Node.js script starting with shebang', () => {
    const script = buildDaemonScript();
    expect(script.startsWith('#!/usr/bin/env node')).toBe(true);
  });

  it('reads config from /etc/devbox/config.json', () => {
    const script = buildDaemonScript();
    expect(script).toContain('/etc/devbox/config.json');
  });

  it('contains port scanning logic', () => {
    const script = buildDaemonScript();
    expect(script).toContain('ss -tlnp');
  });

  it('contains HTTP server listening on 65531', () => {
    const script = buildDaemonScript();
    expect(script).toContain('65531');
    expect(script).toContain('127.0.0.1');
  });

  it('contains snapshot logic before deletion', () => {
    const script = buildDaemonScript();
    expect(script).toContain('create_image');
    expect(script).toContain('snapshot');
  });

  it('contains Caddy readiness polling', () => {
    const script = buildDaemonScript();
    expect(script).toContain('localhost:2019');
  });

  it('contains certificate pre-warming logic', () => {
    const script = buildDaemonScript();
    expect(script).toContain('Pre-warming certificate');
  });

  it('contains auto-delete logic', () => {
    const script = buildDaemonScript();
    expect(script).toContain('api.hetzner.cloud');
  });

  it('returns a static string (no config dependency)', () => {
    const a = buildDaemonScript();
    const b = buildDaemonScript();
    expect(a).toBe(b);
  });
});

describe('buildDaemonConfig', () => {
  it('contains timeout and warning values from config', () => {
    const json = buildDaemonConfig(
      makeConfig({ autoDelete: { enabled: true, timeoutMinutes: 90, warningMinutes: 10 } }),
      'tok',
    );
    const parsed = JSON.parse(json);
    expect(parsed.timeout).toBe(90);
    expect(parsed.warning).toBe(10);
  });

  it('contains different timeout values', () => {
    const json = buildDaemonConfig(
      makeConfig({ autoDelete: { enabled: true, timeoutMinutes: 30, warningMinutes: 3 } }),
      'tok',
    );
    const parsed = JSON.parse(json);
    expect(parsed.timeout).toBe(30);
    expect(parsed.warning).toBe(3);
  });

  it('contains Hetzner token', () => {
    const json = buildDaemonConfig(makeConfig(), 'my-secret-token');
    const parsed = JSON.parse(json);
    expect(parsed.token).toBe('my-secret-token');
  });

  it('contains DNS service name', () => {
    const json = buildDaemonConfig(makeConfig(), 'tok');
    const parsed = JSON.parse(json);
    expect(parsed.dnsService).toBe('sslip.io');
  });

  it('uses custom DNS domain when dnsService is custom', () => {
    const config = makeConfig({
      services: {
        ...makeConfig().services,
        dnsService: 'custom',
        customDnsDomain: 'my.custom.domain',
      },
    });
    const json = buildDaemonConfig(config, 'tok');
    const parsed = JSON.parse(json);
    expect(parsed.dnsService).toBe('my.custom.domain');
  });

  it('falls back to sslip.io when custom domain is empty', () => {
    const config = makeConfig({
      services: {
        ...makeConfig().services,
        dnsService: 'custom',
        customDnsDomain: '',
      },
    });
    const json = buildDaemonConfig(config, 'tok');
    const parsed = JSON.parse(json);
    expect(parsed.dnsService).toBe('sslip.io');
  });

  it('produces valid JSON', () => {
    const json = buildDaemonConfig(makeConfig(), 'tok');
    expect(() => JSON.parse(json)).not.toThrow();
  });

  it('safely encodes special characters in token via JSON', () => {
    const json = buildDaemonConfig(makeConfig(), 'token\'with"special');
    const parsed = JSON.parse(json);
    expect(parsed.token).toBe('token\'with"special');
  });
});

describe('buildOverviewPage', () => {
  it('contains server name in title', () => {
    const html = buildOverviewPage('my-server');
    expect(html).toContain('<title>my-server</title>');
  });

  it('contains server name in h1', () => {
    const html = buildOverviewPage('my-server');
    expect(html).toContain('>my-server</h1>');
  });

  it('uses CSS custom properties for theming', () => {
    const html = buildOverviewPage('test');
    expect(html).toContain('var(--bg');
    expect(html).toContain('var(--fg');
  });

  it('contains DOCTYPE declaration', () => {
    const html = buildOverviewPage('test');
    expect(html.toLowerCase()).toContain('<!doctype html>');
  });

  it('contains html, head, body structure', () => {
    const html = buildOverviewPage('test');
    expect(html).toContain('<html');
    expect(html).toContain('<head>');
    expect(html).toContain('<body>');
    expect(html).toContain('</html>');
  });

  it('contains auto-shutdown UI', () => {
    const html = buildOverviewPage('test');
    expect(html).toContain('Auto-shutdown');
    expect(html).toContain('idle shutdown');
  });

  it('loads config.js synchronously in head', () => {
    const html = buildOverviewPage('test');
    expect(html).toContain('<script src="config.js"></script>');
  });

  it('reads access token from window.__DEVBOX', () => {
    const html = buildOverviewPage('test');
    expect(html).toContain('__DEVBOX');
  });

  it('contains services section', () => {
    const html = buildOverviewPage('test');
    expect(html).toContain('services');
  });

  it('contains status and services fetch logic', () => {
    const html = buildOverviewPage('test');
    expect(html).toContain('/api/status');
    expect(html).toContain('/api/services');
  });

  it('replaces all occurrences of __SERVER_NAME__', () => {
    const html = buildOverviewPage('my-server');
    expect(html).not.toContain('__SERVER_NAME__');
  });
});

describe('buildOverviewConfig', () => {
  it('contains theme colors as CSS variable setters', () => {
    const configJs = buildOverviewConfig(makeConfig(), defaultThemeColors);
    expect(configJs).toContain("setProperty('--bg'");
    expect(configJs).toContain("setProperty('--fg'");
    expect(configJs).toContain("setProperty('--card'");
    expect(configJs).toContain("setProperty('--border'");
    expect(configJs).toContain("setProperty('--muted'");
    expect(configJs).toContain("setProperty('--success'");
    expect(configJs).toContain("setProperty('--warning'");
    expect(configJs).toContain("setProperty('--destructive'");
    expect(configJs).toContain("setProperty('--focus'");
  });

  it('contains default theme color values', () => {
    const configJs = buildOverviewConfig(makeConfig(), defaultThemeColors);
    expect(configJs).toContain(defaultThemeColors.background);
    expect(configJs).toContain(defaultThemeColors.foreground);
    expect(configJs).toContain(defaultThemeColors.success);
    expect(configJs).toContain(defaultThemeColors.warning);
    expect(configJs).toContain(defaultThemeColors.destructive);
    expect(configJs).toContain(defaultThemeColors.card);
    expect(configJs).toContain(defaultThemeColors.border);
  });

  it('contains custom theme colors', () => {
    const customColors = {
      ...defaultThemeColors,
      background: '#custom-bg',
      foreground: '#custom-fg',
    };
    const configJs = buildOverviewConfig(makeConfig(), customColors);
    expect(configJs).toContain('#custom-bg');
    expect(configJs).toContain('#custom-fg');
  });

  it('contains access token', () => {
    const config = makeConfig({
      services: { ...makeConfig().services, accessToken: 'my-secret-token' },
    });
    const configJs = buildOverviewConfig(config, defaultThemeColors);
    expect(configJs).toContain('my-secret-token');
  });

  it('escapes special chars in access token', () => {
    const config = makeConfig({
      services: { ...makeConfig().services, accessToken: "tok'en" },
    });
    const configJs = buildOverviewConfig(config, defaultThemeColors);
    expect(configJs).toContain("tok\\'en");
  });

  it('exposes config on window.__DEVBOX', () => {
    const configJs = buildOverviewConfig(makeConfig(), defaultThemeColors);
    expect(configJs).toContain('window.__DEVBOX=c');
  });

  it('is a self-executing function', () => {
    const configJs = buildOverviewConfig(makeConfig(), defaultThemeColors);
    expect(configJs).toContain('(function(){');
    expect(configJs).toContain('})();');
  });
});

describe('escapeSingleQuotedJS (via buildOverviewConfig)', () => {
  it('escapes backslashes', () => {
    const config = makeConfig({
      services: { ...makeConfig().services, accessToken: 'tok\\en' },
    });
    const configJs = buildOverviewConfig(config, defaultThemeColors);
    expect(configJs).toContain('tok\\\\en');
  });

  it('escapes single quotes', () => {
    const config = makeConfig({
      services: { ...makeConfig().services, accessToken: "tok'en" },
    });
    const configJs = buildOverviewConfig(config, defaultThemeColors);
    expect(configJs).toContain("tok\\'en");
  });

  it('escapes newlines', () => {
    const config = makeConfig({
      services: { ...makeConfig().services, accessToken: 'tok\nen' },
    });
    const configJs = buildOverviewConfig(config, defaultThemeColors);
    expect(configJs).toContain('tok\\nen');
  });

  it('escapes </ to prevent script tag injection', () => {
    const config = makeConfig({
      services: { ...makeConfig().services, accessToken: 'tok</script>en' },
    });
    const configJs = buildOverviewConfig(config, defaultThemeColors);
    expect(configJs).toContain('tok<\\/script>en');
  });
});

describe('buildCaddyConfig edge cases', () => {
  it('includes Actalis ACME CA URL', () => {
    const result = buildCaddyConfig(
      makeConfig({
        services: { ...makeConfig().services, acmeProvider: 'actalis' },
      }),
    );
    expect(result).toContain('acme_ca https://acme-api.actalis.com/acme/directory');
  });

  it('does not include EAB when Actalis keys are missing', () => {
    const result = buildCaddyConfig(
      makeConfig({
        services: { ...makeConfig().services, acmeProvider: 'actalis', actalisEabKeyId: '', actalisEabKey: '' },
      }),
    );
    expect(result).not.toContain('acme_eab');
  });

  it('does not include EAB when only one Actalis key is provided', () => {
    const result = buildCaddyConfig(
      makeConfig({
        services: { ...makeConfig().services, acmeProvider: 'actalis', actalisEabKeyId: 'id', actalisEabKey: '' },
      }),
    );
    expect(result).not.toContain('acme_eab');
  });

  it('does not include EAB when ZeroSSL keys are missing', () => {
    const result = buildCaddyConfig(
      makeConfig({
        services: { ...makeConfig().services, acmeProvider: 'zerossl', zerosslEabKeyId: '', zerosslEabKey: '' },
      }),
    );
    expect(result).not.toContain('acme_eab');
  });

  it('does not include EAB when only one ZeroSSL key is provided', () => {
    const result = buildCaddyConfig(
      makeConfig({
        services: { ...makeConfig().services, acmeProvider: 'zerossl', zerosslEabKeyId: 'id', zerosslEabKey: '' },
      }),
    );
    expect(result).not.toContain('acme_eab');
  });

  it('does not include custom ACME URL when URL is empty', () => {
    const result = buildCaddyConfig(
      makeConfig({
        services: { ...makeConfig().services, acmeProvider: 'custom', customAcmeUrl: '' },
      }),
    );
    expect(result).not.toContain('acme_ca');
  });

  it('includes HTTPS redirect on port 80', () => {
    const result = buildCaddyConfig(makeConfig());
    expect(result).toContain(':80');
    expect(result).toContain('redir https://');
  });

  it('includes TLS on_demand block', () => {
    const result = buildCaddyConfig(makeConfig());
    expect(result).toContain('tls {');
    expect(result).toContain('on_demand');
  });

  it('includes service subdomain routing', () => {
    const result = buildCaddyConfig(makeConfig());
    expect(result).toContain('@service');
    expect(result).toContain('reverse_proxy localhost:{re.svchost.1}');
  });

  it('includes fallback 404 handler', () => {
    const result = buildCaddyConfig(makeConfig());
    expect(result).toContain('respond "Not Found" 404');
  });

  it('accepts valid ACME email without spaces', () => {
    const result = buildCaddyConfig(
      makeConfig({
        services: { ...makeConfig().services, acmeEmail: 'valid@example.com' },
      }),
    );
    expect(result).toContain('email valid@example.com');
  });

  it('omits ACME email when empty', () => {
    const result = buildCaddyConfig(
      makeConfig({
        services: { ...makeConfig().services, acmeEmail: '' },
      }),
    );
    expect(result).not.toContain('email ');
  });
});
