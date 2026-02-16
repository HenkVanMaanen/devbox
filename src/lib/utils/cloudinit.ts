// Cloud-init user-data generator - using native cloud-init modules

import YAML from 'yaml';

import type { GlobalConfig } from '$lib/types';

import {
  buildCaddyConfig,
  buildDaemonScript,
  buildGitCredentials,
  buildOverviewPage,
  defaultTerminalColors,
  defaultThemeColors,
  shellEscape,
  type TerminalColors,
  type ThemeColors,
} from './cloudinit-builders';

interface CloudInitConfig {
  apt: {
    sources: Record<string, { keyid: string; keyserver: string; source: string }>;
  };
  package_update: boolean;
  package_upgrade: boolean;
  packages: string[];
  runcmd: (string | string[])[];
  users: {
    groups: string[];
    name: string;
    shell: string;
    ssh_authorized_keys: string[];
    sudo: string;
  }[];
  write_files: {
    append?: boolean;
    content: string;
    defer?: boolean;
    owner?: string;
    path: string;
    permissions?: string;
  }[];
}

// Main generate function - creates cloud-init user-data with native modules
export function generateCloudInit(
  serverName: string,
  hetznerToken: string,
  config: GlobalConfig,
  options: {
    terminalColors?: TerminalColors;
    themeColors?: ThemeColors;
  } = {},
): string {
  // Handle replace mode: return user YAML directly
  const customYaml = config.customCloudInit.yaml.trim();
  const customMode = config.customCloudInit.mode;

  if (customYaml && customMode === 'replace') {
    return customYaml.startsWith('#cloud-config') ? customYaml : '#cloud-config\n' + customYaml;
  }

  const sshKeys = config.ssh.keys;
  const credential = config.git.credential;

  // Use provided theme colors or defaults
  const themeColors = options.themeColors ?? defaultThemeColors;
  const terminalColors = options.terminalColors ?? defaultTerminalColors;

  // Stryker disable all: cloud-init data constants
  // Build cloud-init object
  const cloudInit: CloudInitConfig = {
    apt: {
      sources: {
        caddy: {
          keyid: '65760C51EDEA2017CEA2CA15155B6D79CA56EA34',
          keyserver: 'keyserver.ubuntu.com',
          source: 'deb [signed-by=$KEY_FILE] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main',
        },
      },
    },
    package_update: true,
    package_upgrade: true,
    packages: [
      'git',
      'curl',
      'ufw',
      'mosh',
      'nodejs',
      'debian-keyring',
      'debian-archive-keyring',
      'apt-transport-https',
      'caddy',
    ],
    runcmd: [],
    users: [
      {
        groups: ['sudo'],
        name: 'dev',
        shell: '/bin/bash',
        ssh_authorized_keys: sshKeys.map((k) => k.pubKey).filter(Boolean),
        sudo: 'ALL=(ALL) NOPASSWD:ALL',
      },
    ],
    write_files: [],
  };
  // Stryker restore all

  // Stryker disable all: write_files and runcmd data constants
  // ========== WRITE_FILES ==========

  // Progress reporting script (must exist before runcmd runs, so no defer)
  cloudInit.write_files.push({
    content: `#!/bin/bash\nSID=$(curl -s -H "Metadata-Flavor:hetzner" http://169.254.169.254/hetzner/v1/metadata/instance-id)\ncurl -sf -X PUT \\\n  -H "Authorization: Bearer ${shellEscape(hetznerToken)}" \\\n  -H "Content-Type: application/json" \\\n  -d "{\\"labels\\":{\\"managed\\":\\"devbox\\",\\"progress\\":\\"$1\\"}}" \\\n  "https://api.hetzner.cloud/v1/servers/$SID" > /dev/null 2>&1 || true\n`,
    path: '/usr/local/bin/devbox-progress',
    permissions: '0755',
  });

  // Git credentials
  const gitCredsContent = buildGitCredentials(credential);
  if (gitCredsContent) {
    cloudInit.write_files.push({
      content: gitCredsContent,
      defer: true,
      owner: 'dev:dev',
      path: '/home/dev/.git-credentials',
      permissions: '0600',
    });
  }

  // Age key for chezmoi secret decryption
  const ageKey = config.chezmoi.ageKey.trim();
  if (ageKey) {
    cloudInit.write_files.push({
      content: ageKey.endsWith('\n') ? ageKey : ageKey + '\n',
      defer: true,
      owner: 'dev:dev',
      path: '/home/dev/.config/chezmoi/key.txt',
      permissions: '0600',
    });
  }

  // Minimal gitconfig (chezmoi manages the real one)
  cloudInit.write_files.push({
    content: '[credential]\n    helper = store\n',
    defer: true,
    owner: 'dev:dev',
    path: '/home/dev/.gitconfig',
    permissions: '0644',
  });

  // Devbox daemon (port scanning, Caddy API, autodelete)
  cloudInit.write_files.push(
    {
      content: buildDaemonScript(config, hetznerToken),
      path: '/usr/local/bin/devbox-daemon',
      permissions: '0755',
    },
    {
      content: `[Unit]\nDescription=Devbox Daemon\nAfter=network.target caddy.service\n[Service]\nType=simple\nUser=dev\nEnvironment="PATH=/usr/local/bin:/usr/bin:/bin"\nExecStart=/usr/bin/env node /usr/local/bin/devbox-daemon\nRestart=always\nRestartSec=10\n[Install]\nWantedBy=multi-user.target\n`,
      path: '/etc/systemd/system/devbox-daemon.service',
      permissions: '0644',
    },
  );

  // Shell terminal (ttyd)
  {
    const ttydTheme = JSON.stringify({
      background: themeColors.background,
      black: terminalColors.black,
      blue: terminalColors.blue,
      brightBlack: terminalColors.brightBlack,
      brightBlue: terminalColors.brightBlue,
      brightCyan: terminalColors.brightCyan,
      brightGreen: terminalColors.brightGreen,
      brightMagenta: terminalColors.brightMagenta,
      brightRed: terminalColors.brightRed,
      brightWhite: terminalColors.brightWhite,
      brightYellow: terminalColors.brightYellow,
      cursor: themeColors.primary,
      cursorAccent: themeColors.background,
      cyan: terminalColors.cyan,
      foreground: themeColors.foreground,
      green: terminalColors.green,
      magenta: terminalColors.magenta,
      red: terminalColors.red,
      selectionBackground: themeColors.muted,
      white: terminalColors.white,
      yellow: terminalColors.yellow,
    });
    cloudInit.write_files.push({
      content: `[Unit]\nDescription=Terminal\nAfter=network.target\n[Service]\nType=simple\nUser=dev\nWorkingDirectory=/home/dev\nEnvironment=HOME=/home/dev\nExecStart=/usr/local/bin/ttyd -p 65534 -t fontSize=14 -t smoothScrollDuration=50 -t 'theme=${ttydTheme}' -W bash --login\nRestart=always\nRestartSec=10\n[Install]\nWantedBy=multi-user.target\n`,
      path: '/etc/systemd/system/ttyd-term.service',
      permissions: '0644',
    });
  }

  // Caddy config and index page
  cloudInit.write_files.push({
    content: buildCaddyConfig(config),
    path: '/etc/caddy/Caddyfile.template',
    permissions: '0644',
  });
  cloudInit.write_files.push({
    content: buildOverviewPage(config, serverName, themeColors),
    path: '/var/www/devbox-overview/index.html.template',
    permissions: '0644',
  });

  // ========== RUNCMD ==========
  const runcmd: (string | string[])[] = [
    '/usr/local/bin/devbox-progress configuring',
    'ufw default deny incoming && ufw default allow outgoing && ufw allow 22 && ufw allow 80 && ufw allow 443 && ufw allow 60000:61000/udp && ufw --force enable',
  ];

  // Report progress: packages installed, now configuring

  // Chezmoi install and init (if repoUrl is set and valid)
  const chezmoiUrl = config.chezmoi.repoUrl.trim();
  if (chezmoiUrl && /^(https?:\/\/|git@)[\w.@:/~-]+$/.test(chezmoiUrl)) {
    runcmd.push('curl -sfL https://get.chezmoi.io | sh -s -- -b /usr/local/bin');
    runcmd.push(`su - dev -c '/usr/local/bin/chezmoi init --apply "${shellEscape(chezmoiUrl)}"' || true`);
  }

  // Install ttyd
  runcmd.push(
    'TTYD_ARCH=$(uname -m | sed "s/aarch64/aarch64/;s/x86_64/x86_64/") && curl -fsSL "https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.${TTYD_ARCH}" -o /usr/local/bin/ttyd && chmod +x /usr/local/bin/ttyd || true',
    'systemctl daemon-reload && systemctl enable --now devbox-daemon ttyd-term || true',
    'mkdir -p /var/www/devbox-overview',
    "IP=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1 | awk -F. '{printf \"%02x%02x%02x%02x\", $1, $2, $3, $4}')",
  );
  runcmd.push(
    `HASH=$(caddy hash-password --plaintext "${shellEscape(config.services.accessToken)}")`,
    'sed -e "s/__IP__/$IP/g" -e "s|__HASH__|$HASH|g" /etc/caddy/Caddyfile.template > /etc/caddy/Caddyfile',
    'sed "s/__IP__/$IP/g" /var/www/devbox-overview/index.html.template > /var/www/devbox-overview/index.html',
    'systemctl restart caddy || true',
    'apt-get clean && rm -rf /var/lib/apt/lists/* || true',
    'touch /home/dev/.devbox-ready && chown -R dev:dev /home/dev',
    '/usr/local/bin/devbox-progress ready',
  );
  // Stryker restore all

  cloudInit.runcmd = runcmd;

  // Merge custom cloud-init if provided
  if (customYaml) {
    const merged = mergeCustomCloudInit(cloudInit as unknown as Record<string, unknown>, customYaml);
    return '#cloud-config\n' + YAML.stringify(merged, { lineWidth: 0 });
  }

  // Convert to YAML
  return '#cloud-config\n' + YAML.stringify(cloudInit, { lineWidth: 0 });
}

// Stryker disable all: data constant, not testable logic
// Keys that custom cloud-init is not allowed to override
export const BLOCKED_CUSTOM_KEYS = new Set(['apt', 'package_update', 'package_upgrade', 'users']);
// Stryker restore all

// Merge user-provided cloud-init YAML into the generated base config
export function mergeCustomCloudInit(baseConfig: Record<string, unknown>, customYaml: string): Record<string, unknown> {
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
    (Array.isArray(writeFiles) ? writeFiles : []).map((f: unknown) => (f as Record<string, unknown>)['path']),
  );

  for (const [key, value] of Object.entries(custom)) {
    if (BLOCKED_CUSTOM_KEYS.has(key)) continue;

    switch (key) {
      case 'packages': {
        if (!Array.isArray(value)) continue;
        const existing = Array.isArray(result['packages']) ? (result['packages'] as string[]) : [];
        const combined = [...existing, ...value.filter((p): p is string => typeof p === 'string')];
        result['packages'] = [...new Set(combined)];

        break;
      }
      case 'runcmd': {
        if (!Array.isArray(value)) continue;
        const existing = Array.isArray(result['runcmd']) ? (result['runcmd'] as unknown[]) : [];
        // Insert user commands before the final "devbox-progress ready" entry
        const readyIndex = existing.findIndex(
          (cmd) => typeof cmd === 'string' && cmd.includes('devbox-progress ready'),
        );
        const typedValue = value as unknown[];
        result['runcmd'] =
          readyIndex !== -1
            ? [...existing.slice(0, readyIndex), ...typedValue, ...existing.slice(readyIndex)]
            : [...existing, ...typedValue];

        break;
      }
      case 'write_files': {
        if (!Array.isArray(value)) continue;
        const existing = Array.isArray(result['write_files']) ? (result['write_files'] as unknown[]) : [];
        const newFiles = value.filter((f: unknown) => {
          if (!f || typeof f !== 'object') return false;
          const filePath = (f as Record<string, unknown>)['path'];
          if (typeof filePath !== 'string' || !filePath) return false;
          return !generatedPaths.has(filePath);
        });
        result['write_files'] = [...existing, ...(newFiles as unknown[])];

        break;
      }
      default: {
        // Extra top-level keys: pass through
        result[key] = value;
      }
    }
  }

  return result;
}
