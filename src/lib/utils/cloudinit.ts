// Cloud-init user-data generator - using native cloud-init modules

import type { GlobalConfig } from '$lib/types';
import {
  shellEscape,
  buildGitCredentials,
  buildDaemonScript,
  buildCaddyConfig,
  buildOverviewPage,
  defaultThemeColors,
  defaultTerminalColors,
  type ThemeColors,
  type TerminalColors,
} from './cloudinit-builders';
import YAML from 'yaml';

interface CloudInitConfig {
  package_update: boolean;
  package_upgrade: boolean;
  apt: {
    sources: Record<string, { source: string; keyid: string; keyserver: string }>;
  };
  packages: string[];
  users: Array<{
    name: string;
    shell: string;
    groups: string[];
    sudo: string;
    ssh_authorized_keys: string[];
  }>;
  write_files: Array<{
    path: string;
    permissions?: string;
    owner?: string;
    content: string;
    defer?: boolean;
    append?: boolean;
  }>;
  runcmd: Array<string | string[]>;
}

// Main generate function - creates cloud-init user-data with native modules
export function generateCloudInit(
  serverName: string,
  hetznerToken: string,
  config: GlobalConfig,
  options: {
    themeColors?: ThemeColors;
    terminalColors?: TerminalColors;
  } = {}
): string {
  // Handle replace mode: return user YAML directly
  const customYaml = config.customCloudInit?.yaml?.trim() ?? '';
  const customMode = config.customCloudInit?.mode ?? 'merge';

  if (customYaml && customMode === 'replace') {
    return customYaml.startsWith('#cloud-config') ? customYaml : '#cloud-config\n' + customYaml;
  }

  const sshKeys = config.ssh?.keys ?? [];
  const credential = config.git?.credential;

  // Use provided theme colors or defaults
  const themeColors = options.themeColors ?? defaultThemeColors;
  const terminalColors = options.terminalColors ?? defaultTerminalColors;

  // Build cloud-init object
  const cloudInit: CloudInitConfig = {
    package_update: true,
    package_upgrade: true,
    apt: {
      sources: {
        'caddy': {
          source: 'deb [signed-by=$KEY_FILE] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main',
          keyid: '65760C51EDEA2017CEA2CA15155B6D79CA56EA34',
          keyserver: 'keyserver.ubuntu.com',
        },
      },
    },
    packages: ['git', 'curl', 'ufw', 'mosh', 'nodejs', 'debian-keyring', 'debian-archive-keyring', 'apt-transport-https', 'caddy'],
    users: [
      {
        name: 'dev',
        shell: '/bin/bash',
        groups: ['sudo'],
        sudo: 'ALL=(ALL) NOPASSWD:ALL',
        ssh_authorized_keys: sshKeys.map((k) => k.pubKey).filter(Boolean),
      },
    ],
    write_files: [],
    runcmd: [],
  };

  // ========== WRITE_FILES ==========

  // Progress reporting script (must exist before runcmd runs, so no defer)
  cloudInit.write_files.push({
    path: '/usr/local/bin/devbox-progress',
    permissions: '0755',
    content: `#!/bin/bash\nSID=$(curl -s -H "Metadata-Flavor:hetzner" http://169.254.169.254/hetzner/v1/metadata/instance-id)\ncurl -sf -X PUT \\\n  -H "Authorization: Bearer ${shellEscape(hetznerToken)}" \\\n  -H "Content-Type: application/json" \\\n  -d "{\\"labels\\":{\\"managed\\":\\"devbox\\",\\"progress\\":\\"$1\\"}}" \\\n  "https://api.hetzner.cloud/v1/servers/$SID" > /dev/null 2>&1 || true\n`,
  });

  // Git credentials
  const gitCredsContent = credential ? buildGitCredentials(credential) : '';
  if (gitCredsContent) {
    cloudInit.write_files.push({
      path: '/home/dev/.git-credentials',
      owner: 'dev:dev',
      permissions: '0600',
      defer: true,
      content: gitCredsContent,
    });
  }

  // Age key for chezmoi secret decryption
  const ageKey = config.chezmoi?.ageKey?.trim() ?? '';
  if (ageKey) {
    cloudInit.write_files.push({
      path: '/home/dev/.config/chezmoi/key.txt',
      owner: 'dev:dev',
      permissions: '0600',
      defer: true,
      content: ageKey.endsWith('\n') ? ageKey : ageKey + '\n',
    });
  }

  // Minimal gitconfig (chezmoi manages the real one)
  cloudInit.write_files.push({
    path: '/home/dev/.gitconfig',
    owner: 'dev:dev',
    permissions: '0644',
    defer: true,
    content: '[credential]\n    helper = store\n',
  });

  // Devbox daemon (port scanning, Caddy API, autodelete)
  cloudInit.write_files.push({
    path: '/usr/local/bin/devbox-daemon',
    permissions: '0755',
    content: buildDaemonScript(config, hetznerToken),
  });
  cloudInit.write_files.push({
    path: '/etc/systemd/system/devbox-daemon.service',
    permissions: '0644',
    content: `[Unit]\nDescription=Devbox Daemon\nAfter=network.target caddy.service\n[Service]\nType=simple\nUser=dev\nEnvironment="PATH=/usr/local/bin:/usr/bin:/bin"\nExecStart=/usr/bin/env node /usr/local/bin/devbox-daemon\nRestart=always\nRestartSec=10\n[Install]\nWantedBy=multi-user.target\n`,
  });

  // Shell terminal (ttyd)
  {
    const ttydTheme = JSON.stringify({
      background: themeColors.background,
      foreground: themeColors.foreground,
      cursor: themeColors.primary,
      cursorAccent: themeColors.background,
      selectionBackground: themeColors.muted,
      black: terminalColors.black,
      red: terminalColors.red,
      green: terminalColors.green,
      yellow: terminalColors.yellow,
      blue: terminalColors.blue,
      magenta: terminalColors.magenta,
      cyan: terminalColors.cyan,
      white: terminalColors.white,
      brightBlack: terminalColors.brightBlack,
      brightRed: terminalColors.brightRed,
      brightGreen: terminalColors.brightGreen,
      brightYellow: terminalColors.brightYellow,
      brightBlue: terminalColors.brightBlue,
      brightMagenta: terminalColors.brightMagenta,
      brightCyan: terminalColors.brightCyan,
      brightWhite: terminalColors.brightWhite,
    });
    cloudInit.write_files.push({
      path: '/etc/systemd/system/ttyd-term.service',
      permissions: '0644',
      content: `[Unit]\nDescription=Terminal\nAfter=network.target\n[Service]\nType=simple\nUser=dev\nWorkingDirectory=/home/dev\nEnvironment=HOME=/home/dev\nExecStart=/usr/local/bin/ttyd -p 65534 -t fontSize=14 -t smoothScrollDuration=50 -t 'theme=${ttydTheme}' -W bash --login\nRestart=always\nRestartSec=10\n[Install]\nWantedBy=multi-user.target\n`,
    });
  }

  // Caddy config and index page
  cloudInit.write_files.push({
      path: '/etc/caddy/Caddyfile.template',
      permissions: '0644',
      content: buildCaddyConfig(config),
    });
  cloudInit.write_files.push({
    path: '/var/www/devbox-overview/index.html.template',
    permissions: '0644',
    content: buildOverviewPage(config, serverName, themeColors),
  });

  // ========== RUNCMD ==========
  const runcmd: Array<string | string[]> = [];

  // Report progress: packages installed, now configuring
  runcmd.push('/usr/local/bin/devbox-progress configuring');

  // Configure firewall
  runcmd.push(
    'ufw default deny incoming && ufw default allow outgoing && ufw allow 22 && ufw allow 80 && ufw allow 443 && ufw allow 60000:61000/udp && ufw --force enable'
  );

  // Chezmoi install and init (if repoUrl is set and valid)
  const chezmoiUrl = config.chezmoi?.repoUrl?.trim() ?? '';
  if (chezmoiUrl && /^(https?:\/\/|git@)[\w.@:/~-]+$/.test(chezmoiUrl)) {
    runcmd.push('curl -sfL https://get.chezmoi.io | sh -s -- -b /usr/local/bin');
    runcmd.push(`su - dev -c '/usr/local/bin/chezmoi init --apply "${shellEscape(chezmoiUrl)}"' || true`);
  }

  // Install ttyd
  runcmd.push(
    'TTYD_ARCH=$(uname -m | sed "s/aarch64/aarch64/;s/x86_64/x86_64/") && curl -fsSL "https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.${TTYD_ARCH}" -o /usr/local/bin/ttyd && chmod +x /usr/local/bin/ttyd || true'
  );

  // Enable services
  runcmd.push('systemctl daemon-reload && systemctl enable --now devbox-daemon ttyd-term || true');

  // IP/hash substitution and Caddy restart
  runcmd.push('mkdir -p /var/www/devbox-overview');
  runcmd.push('IP=$(ip -4 -o addr show scope global | awk \'{print $4}\' | cut -d/ -f1 | head -1 | awk -F. \'{printf "%02x%02x%02x%02x", $1, $2, $3, $4}\')');
  runcmd.push(`HASH=$(caddy hash-password --plaintext "${shellEscape(config.services.accessToken)}")`);
  runcmd.push('sed -e "s/__IP__/$IP/g" -e "s|__HASH__|$HASH|g" /etc/caddy/Caddyfile.template > /etc/caddy/Caddyfile');
  runcmd.push('sed "s/__IP__/$IP/g" /var/www/devbox-overview/index.html.template > /var/www/devbox-overview/index.html');
  runcmd.push('systemctl restart caddy || true');

  // Cleanup and fix ownership
  runcmd.push('apt-get clean && rm -rf /var/lib/apt/lists/* || true');
  runcmd.push('touch /home/dev/.devbox-ready && chown -R dev:dev /home/dev');

  // Report progress: all done
  runcmd.push('/usr/local/bin/devbox-progress ready');

  cloudInit.runcmd = runcmd;

  // Merge custom cloud-init if provided
  if (customYaml) {
    const merged = mergeCustomCloudInit(cloudInit as unknown as Record<string, unknown>, customYaml);
    return toYAML(merged);
  }

  // Convert to YAML
  return toYAML(cloudInit as unknown as Record<string, unknown>);
}

// Keys that custom cloud-init is not allowed to override
export const BLOCKED_CUSTOM_KEYS = new Set(['users', 'apt', 'package_update', 'package_upgrade']);

// Merge user-provided cloud-init YAML into the generated base config
export function mergeCustomCloudInit(
  baseConfig: Record<string, unknown>,
  customYaml: string
): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = YAML.parse(customYaml);
  } catch {
    return baseConfig;
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return baseConfig;
  }

  const custom = parsed as Record<string, unknown>;
  const result: Record<string, unknown> = { ...baseConfig };

  // Collect generated write_files paths for conflict detection
  const writeFiles = result['write_files'];
  const generatedPaths = new Set(
    (Array.isArray(writeFiles) ? writeFiles : [])
      .map((f: unknown) => (f as Record<string, unknown>)['path'])
  );

  for (const [key, value] of Object.entries(custom)) {
    if (BLOCKED_CUSTOM_KEYS.has(key)) continue;

    if (key === 'packages') {
      if (!Array.isArray(value)) continue;
      const existing = Array.isArray(result['packages']) ? result['packages'] as string[] : [];
      const combined = [...existing, ...value.filter((p): p is string => typeof p === 'string')];
      result['packages'] = [...new Set(combined)];
    } else if (key === 'write_files') {
      if (!Array.isArray(value)) continue;
      const existing = Array.isArray(result['write_files']) ? result['write_files'] as unknown[] : [];
      const newFiles = value.filter((f: unknown) => {
        if (!f || typeof f !== 'object') return false;
        const filePath = (f as Record<string, unknown>)['path'];
        if (typeof filePath !== 'string' || !filePath) return false;
        return !generatedPaths.has(filePath);
      });
      result['write_files'] = [...existing, ...newFiles];
    } else if (key === 'runcmd') {
      if (!Array.isArray(value)) continue;
      const existing = Array.isArray(result['runcmd']) ? result['runcmd'] as unknown[] : [];
      // Insert user commands before the final "devbox-progress ready" entry
      const readyIndex = existing.findIndex(
        (cmd) => typeof cmd === 'string' && cmd.includes('devbox-progress ready')
      );
      if (readyIndex >= 0) {
        result['runcmd'] = [
          ...existing.slice(0, readyIndex),
          ...value,
          ...existing.slice(readyIndex),
        ];
      } else {
        result['runcmd'] = [...existing, ...value];
      }
    } else {
      // Extra top-level keys: pass through
      result[key] = value;
    }
  }

  return result;
}

// Simple YAML serializer for cloud-init
function toYAML(obj: Record<string, unknown>, indent = 0, isRoot = true): string {
  const pad = '  '.repeat(indent);
  let yaml = isRoot ? '#cloud-config\n' : '';

  for (const [key, value] of Object.entries(obj)) {
    if (value === null || value === undefined) continue;

    if (Array.isArray(value)) {
      if (value.length === 0) continue;
      yaml += `${pad}${key}:\n`;
      for (const item of value) {
        if (Array.isArray(item)) {
          // Array item in array (e.g., runcmd shell form: ['bash', '-c', 'script'])
          yaml += `${pad}-\n`;
          for (const sub of item) {
            yaml += `${pad}  - ${formatYAMLValue(sub, indent + 2)}\n`;
          }
        } else if (typeof item === 'object' && item !== null) {
          yaml += `${pad}- `;
          const lines = toYAML(item as unknown as Record<string, unknown>, 0, false)
            .split('\n')
            .filter((l) => l);
          yaml += lines[0] + '\n';
          for (let i = 1; i < lines.length; i++) {
            yaml += `${pad}  ${lines[i]}\n`;
          }
        } else {
          yaml += `${pad}- ${formatYAMLValue(item, indent + 1)}\n`;
        }
      }
    } else if (typeof value === 'object') {
      yaml += `${pad}${key}:\n`;
      yaml += toYAML(value as unknown as Record<string, unknown>, indent + 1, false);
    } else {
      yaml += `${pad}${key}: ${formatYAMLValue(value, indent)}\n`;
    }
  }
  return yaml;
}

function formatYAMLValue(value: unknown, indent = 0): string {
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return String(value);
  if (typeof value === 'string') {
    // Multi-line strings - use block scalar
    if (value.includes('\n')) {
      const pad = '  '.repeat(indent + 1);
      let lines = value.split('\n');
      // Use | (keep) to preserve trailing newline, |- (strip) otherwise
      const chomp = value.endsWith('\n') ? '' : '-';
      // Remove empty trailing element from split
      if (chomp === '' && lines[lines.length - 1] === '') {
        lines = lines.slice(0, -1);
      }
      return `|${chomp}\n` + lines.map((l) => pad + l).join('\n');
    }
    // Strings that need quoting
    if (
      value === '' ||
      /^\s|\s$/.test(value) ||
      value.match(/^[{[\]#&*!|>'"%@`,?~]/) ||
      value.includes(': ') ||
      value.includes(' #') ||
      value.endsWith(':') ||
      /^[-+]?(\d[\d_]*\.?[\d_]*|\.inf|\.nan)$/i.test(value) ||
      /^(true|false|null|yes|no|on|off|~)$/i.test(value)
    ) {
      return JSON.stringify(value);
    }
    return value;
  }
  return String(value);
}
