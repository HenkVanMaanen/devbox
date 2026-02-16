import { describe, expect, it } from 'vitest';

import {
  buildDaemonScript,
  buildOverviewPage,
  buildCaddyConfig,
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
    ssh: { keys: [] },
    ...overrides,
  } as GlobalConfig;
}

describe('buildDaemonScript', () => {
  it('contains timeout and warning values from config', () => {
    const script = buildDaemonScript(
      makeConfig({ autoDelete: { enabled: true, timeoutMinutes: 90, warningMinutes: 10 } }),
      'tok',
    );
    expect(script).toContain('TIMEOUT=90');
    expect(script).toContain('WARNING=10');
  });

  it('contains different timeout values', () => {
    const script = buildDaemonScript(
      makeConfig({ autoDelete: { enabled: true, timeoutMinutes: 30, warningMinutes: 3 } }),
      'tok',
    );
    expect(script).toContain('TIMEOUT=30');
    expect(script).toContain('WARNING=3');
  });

  it('contains escaped Hetzner token', () => {
    const script = buildDaemonScript(makeConfig(), 'my-secret-token');
    expect(script).toContain('my-secret-token');
  });

  it('escapes special characters in token', () => {
    const script = buildDaemonScript(makeConfig(), "token'with");
    // Single quotes in JS strings should be escaped
    expect(script).toContain("token\\'with");
  });

  it('contains DNS service name', () => {
    const script = buildDaemonScript(makeConfig(), 'tok');
    expect(script).toContain("DNS_SERVICE='sslip.io'");
  });

  it('uses custom DNS domain when dnsService is custom', () => {
    const config = makeConfig({
      services: {
        ...makeConfig().services,
        dnsService: 'custom',
        customDnsDomain: 'my.custom.domain',
      },
    });
    const script = buildDaemonScript(config, 'tok');
    expect(script).toContain('my.custom.domain');
  });

  it('falls back to sslip.io when custom domain is empty', () => {
    const config = makeConfig({
      services: {
        ...makeConfig().services,
        dnsService: 'custom',
        customDnsDomain: '',
      },
    });
    const script = buildDaemonScript(config, 'tok');
    expect(script).toContain("DNS_SERVICE='sslip.io'");
  });

  it('is a valid Node.js script starting with shebang', () => {
    const script = buildDaemonScript(makeConfig(), 'tok');
    expect(script.startsWith('#!/usr/bin/env node')).toBe(true);
  });

  it('contains port scanning logic', () => {
    const script = buildDaemonScript(makeConfig(), 'tok');
    expect(script).toContain('scanPorts');
    expect(script).toContain('ss -tlnp');
  });

  it('contains domain verification logic', () => {
    const script = buildDaemonScript(makeConfig(), 'tok');
    expect(script).toContain('verifyDomain');
  });

  it('contains auto-delete logic', () => {
    const script = buildDaemonScript(makeConfig(), 'tok');
    expect(script).toContain('checkActivityAndMaybeDelete');
    expect(script).toContain('del()');
  });

  it('contains HTTP server listening on 65531', () => {
    const script = buildDaemonScript(makeConfig(), 'tok');
    expect(script).toContain('65531');
    expect(script).toContain("'127.0.0.1'");
  });

  it('contains WIP git commit logic', () => {
    const script = buildDaemonScript(makeConfig(), 'tok');
    expect(script).toContain('wip');
    expect(script).toContain('git -C');
  });
});

describe('buildOverviewPage', () => {
  it('contains server name in title', () => {
    const html = buildOverviewPage(makeConfig(), 'my-server', defaultThemeColors);
    expect(html).toContain('<title>my-server</title>');
  });

  it('contains server name in h1', () => {
    const html = buildOverviewPage(makeConfig(), 'my-server', defaultThemeColors);
    expect(html).toContain('>my-server</h1>');
  });

  it('contains theme colors in CSS', () => {
    const html = buildOverviewPage(makeConfig(), 'test', defaultThemeColors);
    expect(html).toContain(defaultThemeColors.background);
    expect(html).toContain(defaultThemeColors.foreground);
    expect(html).toContain(defaultThemeColors.success);
    expect(html).toContain(defaultThemeColors.warning);
    expect(html).toContain(defaultThemeColors.destructive);
    expect(html).toContain(defaultThemeColors.muted);
    expect(html).toContain(defaultThemeColors.mutedForeground);
    expect(html).toContain(defaultThemeColors.card);
    expect(html).toContain(defaultThemeColors.border);
  });

  it('contains custom theme colors', () => {
    const customColors = {
      ...defaultThemeColors,
      background: '#custom-bg',
      foreground: '#custom-fg',
    };
    const html = buildOverviewPage(makeConfig(), 'test', customColors);
    expect(html).toContain('#custom-bg');
    expect(html).toContain('#custom-fg');
  });

  it('contains escaped access token', () => {
    const config = makeConfig({
      services: { ...makeConfig().services, accessToken: 'my-secret-token' },
    });
    const html = buildOverviewPage(config, 'test', defaultThemeColors);
    expect(html).toContain('my-secret-token');
  });

  it('escapes special chars in access token', () => {
    const config = makeConfig({
      services: { ...makeConfig().services, accessToken: "tok'en" },
    });
    const html = buildOverviewPage(config, 'test', defaultThemeColors);
    expect(html).toContain("tok\\'en");
  });

  it('contains DOCTYPE declaration', () => {
    const html = buildOverviewPage(makeConfig(), 'test', defaultThemeColors);
    expect(html).toContain('<!DOCTYPE html>');
  });

  it('contains html, head, body structure', () => {
    const html = buildOverviewPage(makeConfig(), 'test', defaultThemeColors);
    expect(html).toContain('<html');
    expect(html).toContain('<head>');
    expect(html).toContain('<body>');
    expect(html).toContain('</html>');
  });

  it('contains auto-shutdown UI', () => {
    const html = buildOverviewPage(makeConfig(), 'test', defaultThemeColors);
    expect(html).toContain('Auto-shutdown');
    expect(html).toContain('idle shutdown');
  });

  it('contains services section', () => {
    const html = buildOverviewPage(makeConfig(), 'test', defaultThemeColors);
    expect(html).toContain('services');
  });

  it('contains keepalive and status fetch logic', () => {
    const html = buildOverviewPage(makeConfig(), 'test', defaultThemeColors);
    expect(html).toContain('/api/status');
    expect(html).toContain('/api/services');
  });
});

describe('escapeSingleQuotedJS (via buildDaemonScript)', () => {
  it('escapes backslashes', () => {
    const script = buildDaemonScript(makeConfig(), 'tok\\en');
    expect(script).toContain('tok\\\\en');
  });

  it('escapes single quotes', () => {
    const script = buildDaemonScript(makeConfig(), "tok'en");
    expect(script).toContain("tok\\'en");
  });

  it('escapes newlines', () => {
    const script = buildDaemonScript(makeConfig(), 'tok\nen');
    expect(script).toContain('tok\\nen');
  });

  it('escapes </ to prevent script tag injection', () => {
    const script = buildDaemonScript(makeConfig(), 'tok</script>en');
    expect(script).toContain('tok<\\/script>en');
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
