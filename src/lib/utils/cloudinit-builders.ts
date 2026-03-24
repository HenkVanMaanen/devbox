// Cloud-init builder helpers - Caddyfile, index page, autodelete daemon

import { daemonTemplate } from '@devbox/daemon/template';
import { overviewTemplate } from '@devbox/overview/template';

import type { AuthUser, GitCredential, GlobalConfig } from '$lib/types';

export interface TerminalColors {
  black?: string;
  blue?: string;
  brightBlack?: string;
  brightBlue?: string;
  brightCyan?: string;
  brightGreen?: string;
  brightMagenta?: string;
  brightRed?: string;
  brightWhite?: string;
  brightYellow?: string;
  cyan?: string;
  green?: string;
  magenta?: string;
  red?: string;
  white?: string;
  yellow?: string;
}

export interface ThemeColors {
  [key: string]: string; // Allow extra properties from theme store
  background: string;
  border: string;
  card: string;
  destructive: string;
  focus: string;
  foreground: string;
  muted: string;
  mutedForeground: string;
  primary: string;
  success: string;
  warning: string;
}

export const AUTHELIA_VERSION = '4.39.16';

// Build Authelia configuration.yml template (placeholders replaced at runtime via sed)
export function buildAutheliaConfig(config: GlobalConfig): string {
  const devPrefix = getDomainPrefix(config.services.dnsService);

  return `---
server:
  address: 'tcp://127.0.0.1:9091/'

log:
  level: warn

totp:
  disable: true

webauthn:
  disable: true

identity_validation:
  reset_password:
    jwt_secret: '__SESSION_SECRET__'

authentication_backend:
  file:
    path: /etc/authelia/users.yml

session:
  secret: '__SESSION_SECRET__'
  cookies:
    - domain: '${devPrefix}__IP__.__DNS_SERVICE__'
      authelia_url: 'https://auth.${devPrefix}__IP__.__DNS_SERVICE__'
      default_redirection_url: 'https://${devPrefix}__IP__.__DNS_SERVICE__'
      expiration: 16h
      inactivity: 16h

storage:
  encryption_key: '__ENCRYPTION_KEY__'
  local:
    path: /var/lib/authelia/db.sqlite3

notifier:
  filesystem:
    filename: /var/lib/authelia/notifications.txt

access_control:
  default_policy: one_factor
`;
}

// Build Authelia users.yml from pre-provisioned user list
export function buildAutheliaUsers(users: AuthUser[]): string {
  if (users.length === 0) return 'users: {}\n';

  let yaml = 'users:\n';
  for (const user of users) {
    const name = sanitizeUsername(user.username);
    if (!name) continue;
    yaml += `  ${name}:\n`;
    yaml += `    displayname: '${name}'\n`;
    const hash = user.passwordHash.replaceAll("'", '');
    yaml += `    password: '${hash}'\n`;
    yaml += `    email: '${name}@devbox.local'\n`;
  }
  return yaml;
}

// Build Cloudflare DNS update script (updates A record to point to this server's IP)
export function buildCloudflareDnsScript(apiToken: string, zoneId: string, hostname: string): string {
  return String.raw`#!/bin/bash
set -euo pipefail
CF_TOKEN="${shellEscape(apiToken)}"
CF_ZONE="${shellEscape(zoneId)}"
CF_HOST="${shellEscape(hostname)}"
CF_API="https://api.cloudflare.com/client/v4"
IP=$(curl -s http://169.254.169.254/hetzner/v1/metadata/public-ipv4)
RID=$(curl -s -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json" \
  "$CF_API/zones/$CF_ZONE/dns_records?type=A&name=$CF_HOST" | jq -r '.result[0].id // empty')
DATA="{\"type\":\"A\",\"name\":\"$CF_HOST\",\"content\":\"$IP\",\"ttl\":60,\"proxied\":false}"
if [ -n "$RID" ]; then
  curl -s -X PUT "$CF_API/zones/$CF_ZONE/dns_records/$RID" \
    -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json" --data "$DATA" > /dev/null
else
  curl -s -X POST "$CF_API/zones/$CF_ZONE/dns_records" \
    -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json" --data "$DATA" > /dev/null
fi
`;
}

// Build daemon config JSON (written to /etc/devbox/config.json by cloud-init)
export function buildDaemonConfig(config: GlobalConfig, hetznerToken: string): string {
  const dnsService = resolveDnsService(config);

  return JSON.stringify({
    dnsService,
    timeout: config.autoDelete.timeoutMinutes,
    token: hetznerToken,
    useDevPrefix: config.services.dnsService !== 'custom',
    warning: config.autoDelete.warningMinutes,
  });
}

// Build devbox daemon script (static artifact from @devbox/daemon package)
export function buildDaemonScript(): string {
  return daemonTemplate;
}

// Build git credentials file content
export function buildGitCredentials(credential: GitCredential): string {
  if (credential.host === '' || credential.username === '' || credential.token === '') return '';
  const username = encodeURIComponent(credential.username);
  const token = encodeURIComponent(credential.token);
  // Validate host to prevent injection (only allow valid hostname chars)
  const host = credential.host.replaceAll(/[^a-zA-Z0-9._-]/g, '');
  return `https://${username}:${token}@${host}\n`;
}

// Get domain prefix: 'dev.' for wildcard DNS services (PSL cookie workaround), '' for custom domains
export function getDomainPrefix(dnsService: string): string {
  return dnsService === 'custom' ? '' : 'dev.';
}

// Resolve the effective DNS service domain from config
export function resolveDnsService(config: GlobalConfig): string {
  return config.services.dnsService === 'custom'
    ? config.services.customDnsDomain || 'sslip.io'
    : config.services.dnsService;
}

// Escape shell metacharacters in double-quoted strings
export function shellEscape(s: string): string {
  if (s.length === 0) return '';
  return s.replaceAll(/[\\"$`!]/g, String.raw`\$&`).replaceAll('\n', '');
}

// Convert standard base64 to base64url (for Actalis EAB keys)
export function toBase64URL(s: string): string {
  if (!s) return '';
  return s.replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

// Escape a string for safe embedding in a single-quoted JS string literal
function escapeSingleQuotedJS(s: string): string {
  if (!s) return '';
  return s
    .replaceAll('\\', '\\\\')
    .replaceAll("'", String.raw`\'`)
    .replaceAll('\n', String.raw`\n`)
    .replaceAll('</', String.raw`<\/`);
}

// Sanitize a username for safe embedding in YAML keys and single-quoted values
function sanitizeUsername(s: string): string {
  return s.replaceAll(/[^a-zA-Z0-9_.-]/g, '');
}

// Stryker disable all
// ACME provider configurations
const ACME_PROVIDERS: Record<string, { ca: string; requiresEab?: boolean }> = {
  actalis: { ca: 'https://acme-api.actalis.com/acme/directory', requiresEab: true },
  buypass: { ca: 'https://api.buypass.com/acme/directory' },
  letsencrypt: { ca: 'https://acme-v02.api.letsencrypt.org/directory' },
  'letsencrypt-staging': { ca: 'https://acme-staging-v02.api.letsencrypt.org/directory' },
  zerossl: { ca: 'https://acme.zerossl.com/v2/DV90', requiresEab: true },
};
// Stryker restore all

// Build Caddyfile for services (domain-agnostic, Authelia forward auth)
// Domain patterns use 'dev.' prefix for wildcard DNS (PSL cookie workaround)
export function buildCaddyConfig(config: GlobalConfig): string {
  const devPrefix = getDomainPrefix(config.services.dnsService);

  let caddyfile = '{\n';
  caddyfile += '  on_demand_tls {\n    ask http://localhost:65531/verify-domain\n  }\n';

  if (config.services.acmeEmail && /^[^\s{}]+$/.test(config.services.acmeEmail)) {
    caddyfile += `  email ${config.services.acmeEmail}\n`;
  }

  // ACME provider configuration
  const acmeProvider = config.services.acmeProvider;
  if (acmeProvider === 'custom' && config.services.customAcmeUrl) {
    caddyfile += '  acme_ca ' + config.services.customAcmeUrl + '\n';
    if (config.services.customEabKeyId && config.services.customEabKey) {
      caddyfile += `  acme_eab {\n    key_id ${config.services.customEabKeyId}\n    mac_key ${config.services.customEabKey}\n  }\n`;
    }
  } else if (acmeProvider !== 'letsencrypt') {
    const providerConfig = ACME_PROVIDERS[acmeProvider];
    if (providerConfig) {
      caddyfile += '  acme_ca ' + providerConfig.ca + '\n';
    }
    // EAB for zerossl
    if (acmeProvider === 'zerossl' && config.services.zerosslEabKeyId && config.services.zerosslEabKey) {
      caddyfile += `  acme_eab {\n    key_id ${config.services.zerosslEabKeyId}\n    mac_key ${config.services.zerosslEabKey}\n  }\n`;
    }
    // EAB for actalis
    if (acmeProvider === 'actalis' && config.services.actalisEabKeyId && config.services.actalisEabKey) {
      caddyfile += `  acme_eab {\n    key_id ${config.services.actalisEabKeyId}\n    mac_key ${toBase64URL(config.services.actalisEabKey)}\n  }\n`;
    }
  }

  caddyfile += '}\n\n';

  // Authelia forward auth snippet (reused in base and service handlers)
  const forwardAuth = `    forward_auth localhost:9091 {
      uri /api/authz/forward-auth
      copy_headers Remote-User Remote-Groups
    }
`;

  // HTTP to HTTPS redirect (also needed for ACME HTTP-01 challenge)
  caddyfile += `:80 {
  redir https://{host}{uri} permanent
}

`;

  // Single HTTPS listener - domain-agnostic routing via header matching
  caddyfile += String.raw`:443 {
  tls {
    on_demand
  }

  # Authelia portal: auth.{devPrefix}{ipHex}.{any-suffix} (no forward_auth — would loop)
  @auth header_regexp authhost Host (?i)^auth\.${devPrefix}__IP__\.[a-z0-9.-]+$
  handle @auth {
    reverse_proxy localhost:9091
  }

  # Base domain: {devPrefix}{ipHex}.{any-suffix} - serves overview page
  @base header_regexp basehost Host (?i)^${devPrefix}__IP__\.[a-z0-9.-]+$
  handle @base {
${forwardAuth}
    route /api/* {
      uri strip_prefix /api
      reverse_proxy localhost:65531
    }
    root * /var/www/devbox-overview
    file_server
  }

  # Service subdomain: {port}.{devPrefix}{ipHex}.{any-suffix} - proxies to port
  @service header_regexp svchost Host (?i)^(\d+)\.${devPrefix}__IP__\.[a-z0-9.-]+$
  handle @service {
${forwardAuth}
    reverse_proxy localhost:{re.svchost.1}
  }

  # Fallback: reject unmatched requests
  handle {
    respond "Not Found" 404
  }
}
`;

  return caddyfile;
}

// Build overview config.js (written to /var/www/devbox-overview/config.js by cloud-init)
// Loaded synchronously before paint to set CSS variables — no flash
export function buildOverviewConfig(themeColors: ThemeColors): string {
  const e = escapeSingleQuotedJS;
  const colors = themeColors;
  return `(function(){
var c={colors:{bg:'${e(colors.background)}',fg:'${e(colors.foreground)}',card:'${e(colors.card)}',border:'${e(colors.border)}',muted:'${e(colors.muted)}',mutedFg:'${e(colors.mutedForeground)}',success:'${e(colors.success)}',warning:'${e(colors.warning)}',destructive:'${e(colors.destructive)}',focus:'${e(colors.focus)}'}};
var r=document.documentElement.style;
r.setProperty('--bg',c.colors.bg);r.setProperty('--fg',c.colors.fg);r.setProperty('--card',c.colors.card);r.setProperty('--border',c.colors.border);r.setProperty('--muted',c.colors.muted);r.setProperty('--muted-fg',c.colors.mutedFg);r.setProperty('--success',c.colors.success);r.setProperty('--warning',c.colors.warning);r.setProperty('--destructive',c.colors.destructive);r.setProperty('--focus',c.colors.focus);
window.__DEVBOX=c;
})();`;
}

// Build overview page HTML (static artifact from @devbox/overview package)
// Only __SERVER_NAME__ is replaced — it's structural (title/h1), not config
export function buildOverviewPage(serverName: string): string {
  return overviewTemplate.replaceAll('__SERVER_NAME__', serverName);
}

// Stryker disable all
// Default theme colors (dark theme)
export const defaultThemeColors: ThemeColors = {
  background: '#0d0d0d',
  border: '#333333',
  card: '#171717',
  destructive: '#ef4444',
  focus: 'rgba(99,102,241,0.5)',
  foreground: '#f5f5f5',
  muted: '#262626',
  mutedForeground: '#a3a3a3',
  primary: '#6366f1',
  success: '#22c55e',
  warning: '#f59e0b',
};

export const defaultTerminalColors: TerminalColors = {
  black: '#0d0d0d',
  blue: '#3b82f6',
  brightBlack: '#404040',
  brightBlue: '#60a5fa',
  brightCyan: '#22d3ee',
  brightGreen: '#4ade80',
  brightMagenta: '#c084fc',
  brightRed: '#f87171',
  brightWhite: '#ffffff',
  brightYellow: '#fbbf24',
  cyan: '#06b6d4',
  green: '#22c55e',
  magenta: '#a855f7',
  red: '#ef4444',
  white: '#f5f5f5',
  yellow: '#f59e0b',
};
// Stryker restore all
