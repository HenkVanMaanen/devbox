// Cloud-init user-data generator - using native cloud-init modules

import type { GlobalConfig, SSHKey, GitCredential } from '$lib/types';
import {
  shellEscape,
  buildGitCredentials,
  buildGitConfig,
  buildDaemonScript,
  buildCaddyConfig,
  buildOverviewPage,
  defaultThemeColors,
  defaultTerminalColors,
} from './cloudinit-builders';

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
    sshKeys?: SSHKey[];
    gitCredentials?: GitCredential[];
  } = {}
): string {
  const gitCreds = options.gitCredentials ?? config.git?.credentials ?? [];
  const sshKeys = options.sshKeys ?? config.ssh?.keys ?? [];

  // Use default theme colors
  const themeColors = defaultThemeColors;
  const terminalColors = defaultTerminalColors;

  const servicesEnabled = config.services.codeServer || config.services.shellTerminal;
  const MISE_SHIMS = '/home/dev/.local/share/mise/shims';

  // Build cloud-init object
  const cloudInit: CloudInitConfig = {
    package_update: true,
    package_upgrade: true,
    apt: {
      sources: {
        'github-cli': {
          source: 'deb [signed-by=$KEY_FILE] https://cli.github.com/packages stable main',
          keyid: '23F3D4EA75716059',
          keyserver: 'keyserver.ubuntu.com',
        },
      },
    },
    packages: ['git', 'curl', 'wget', 'htop', 'tmux', 'jq', 'gh', 'ufw'],
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

  // Track existing packages to avoid duplicates
  const pkgSet = new Set(cloudInit.packages);

  // Add Caddy repo if services enabled
  if (servicesEnabled) {
    cloudInit.apt.sources['caddy'] = {
      source: 'deb [signed-by=$KEY_FILE] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main',
      keyid: '65760C51EDEA2017CEA2CA15155B6D79CA56EA34',
      keyserver: 'keyserver.ubuntu.com',
    };
    for (const pkg of ['debian-keyring', 'debian-archive-keyring', 'apt-transport-https', 'caddy']) {
      if (!pkgSet.has(pkg)) {
        cloudInit.packages.push(pkg);
        pkgSet.add(pkg);
      }
    }
  }

  // ========== WRITE_FILES ==========

  // Mise shims PATH (system-wide for all processes)
  cloudInit.write_files.push({
    path: '/etc/profile.d/mise.sh',
    permissions: '0644',
    content: `export PATH="${MISE_SHIMS}:$PATH"\n`,
  });

  // Fish config for system-wide fish shells
  cloudInit.write_files.push({
    path: '/etc/fish/conf.d/mise.fish',
    permissions: '0644',
    content: `set -gx PATH ${MISE_SHIMS} $PATH\n`,
  });

  // Bash config with mise activation and starship
  let bashContent = 'test -x /usr/local/bin/mise && eval "$(/usr/local/bin/mise activate bash)"\n';
  if (config.shell.starship) {
    bashContent += 'command -v starship >/dev/null && eval "$(starship init bash)"\n';
  }
  cloudInit.write_files.push({
    path: '/home/dev/.bashrc',
    owner: 'dev:dev',
    permissions: '0644',
    defer: true,
    append: true,
    content: bashContent,
  });

  // Tmux config with theme colors
  cloudInit.write_files.push({
    path: '/home/dev/.tmux.conf',
    owner: 'dev:dev',
    permissions: '0644',
    defer: true,
    content: `# Theme colors (auto-generated from devbox theme)
set -g status-style "bg=${themeColors.muted},fg=${themeColors.foreground}"
set -g status-left-style "bg=${themeColors.primary},fg=${themeColors.background}"
set -g status-right-style "bg=${themeColors.muted},fg=${themeColors.mutedForeground}"
set -g window-status-current-style "bg=${themeColors.primary},fg=${themeColors.background}"
set -g window-status-style "bg=${themeColors.muted},fg=${themeColors.mutedForeground}"
set -g pane-border-style "fg=${themeColors.border}"
set -g pane-active-border-style "fg=${themeColors.primary}"
set -g message-style "bg=${themeColors.muted},fg=${themeColors.foreground}"
set -g mode-style "bg=${themeColors.primary},fg=${themeColors.background}"

# Sensible defaults
set -g mouse on
set -g history-limit 50000
set -g default-terminal "screen-256color"
set -ga terminal-overrides ",*256col*:Tc"
set -g base-index 1
setw -g pane-base-index 1
set -g renumber-windows on
set -s escape-time 0
`,
  });

  // Git credentials
  if (gitCreds.length > 0) {
    cloudInit.write_files.push({
      path: '/home/dev/.git-credentials',
      owner: 'dev:dev',
      permissions: '0600',
      defer: true,
      content: buildGitCredentials(gitCreds),
    });
  }

  // Main gitconfig
  cloudInit.write_files.push({
    path: '/home/dev/.gitconfig',
    owner: 'dev:dev',
    permissions: '0644',
    defer: true,
    content: buildGitConfig(config, gitCreds),
  });

  // Claude config
  cloudInit.write_files.push({
    path: '/home/dev/.claude.json',
    owner: 'dev:dev',
    permissions: '0644',
    defer: true,
    content: '{"hasCompletedOnboarding":true,"bypassPermissionsModeAccepted":true}',
  });

  if (config.claude.credentialsJson) {
    cloudInit.write_files.push({
      path: '/home/dev/.claude/.credentials.json',
      owner: 'dev:dev',
      permissions: '0600',
      defer: true,
      content: JSON.stringify(config.claude.credentialsJson),
    });
  } else if (config.claude.apiKey) {
    cloudInit.write_files.push({
      path: '/home/dev/.claude/.credentials',
      owner: 'dev:dev',
      permissions: '0600',
      defer: true,
      content: config.claude.apiKey,
    });
  }

  if (config.claude.settings) {
    try {
      const settings = JSON.parse(config.claude.settings);
      if (Object.keys(settings).length > 0) {
        cloudInit.write_files.push({
          path: '/home/dev/.claude/settings.json',
          owner: 'dev:dev',
          permissions: '0644',
          defer: true,
          content: JSON.stringify(settings),
        });
      }
    } catch {
      // Invalid JSON, skip
    }
  }

  // Devbox daemon (port scanning, Caddy API, autodelete)
  if (config.autoDelete.enabled || servicesEnabled) {
    cloudInit.write_files.push({
      path: '/usr/local/bin/devbox-daemon',
      permissions: '0755',
      content: buildDaemonScript(config, hetznerToken),
    });
    cloudInit.write_files.push({
      path: '/etc/systemd/system/devbox-daemon.service',
      permissions: '0644',
      content: `[Unit]\nDescription=Devbox Daemon\nAfter=network.target caddy.service\n[Service]\nType=simple\nUser=dev\nEnvironment="PATH=${MISE_SHIMS}:/usr/local/bin:/usr/bin:/bin"\nExecStart=/usr/bin/env node /usr/local/bin/devbox-daemon\nRestart=always\nRestartSec=10\n[Install]\nWantedBy=multi-user.target\n`,
    });
  }

  // Code-server config
  if (config.services.codeServer) {
    cloudInit.write_files.push({
      path: '/home/dev/.config/code-server/config.yaml',
      owner: 'dev:dev',
      permissions: '0600',
      defer: true,
      content: 'bind-addr: 127.0.0.1:65532\nauth: none\ncert: false\n',
    });
    cloudInit.write_files.push({
      path: '/etc/systemd/system/code-server.service',
      permissions: '0644',
      content: `[Unit]\nDescription=Code Server\nAfter=network.target\n[Service]\nType=simple\nUser=dev\nWorkingDirectory=/home/dev\nEnvironment="PATH=${MISE_SHIMS}:/usr/local/bin:/usr/bin:/bin"\nExecStart=/usr/bin/code-server\nRestart=always\nRestartSec=10\n[Install]\nWantedBy=multi-user.target\n`,
    });
  }

  // Shell terminal (ttyd)
  if (config.services.shellTerminal) {
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
      content: `[Unit]\nDescription=Terminal\nAfter=network.target\n[Service]\nType=simple\nUser=dev\nWorkingDirectory=/home/dev\nEnvironment=HOME=/home/dev\nExecStart=/usr/local/bin/ttyd -p 65534 -t fontSize=14 -t smoothScrollDuration=50 -t 'theme=${ttydTheme}' -W bash\nRestart=always\nRestartSec=10\n[Install]\nWantedBy=multi-user.target\n`,
    });
  }

  // Caddy config and index page
  if (servicesEnabled) {
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
  }

  // ========== RUNCMD ==========
  const runcmd: Array<string | string[]> = [];

  // Configure firewall
  runcmd.push(
    'ufw default deny incoming && ufw default allow outgoing && ufw allow 22 && ufw allow 80 && ufw allow 443 && ufw --force enable'
  );

  // Mise installation
  runcmd.push('curl -fsSL https://mise.run | MISE_INSTALL_PATH=/usr/local/bin/mise sh || true');

  // Install node (required for daemon) via mise
  runcmd.push("su - dev -c '/usr/local/bin/mise use --global node@latest' || true");

  // claude-code
  runcmd.push(`su - dev -c 'PATH=${MISE_SHIMS}:$PATH npm install -g @anthropic-ai/claude-code' || true`);

  // Starship
  if (config.shell.starship) {
    runcmd.push('curl -fsSL https://starship.rs/install.sh | sh -s -- -y || true');
  }

  // Services - install binaries
  if (servicesEnabled) {
    if (config.services.shellTerminal) {
      runcmd.push(
        'TTYD_ARCH=$(uname -m | sed "s/aarch64/aarch64/;s/x86_64/x86_64/") && curl -fsSL "https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.${TTYD_ARCH}" -o /usr/local/bin/ttyd && chmod +x /usr/local/bin/ttyd || true'
      );
    }
    if (config.services.codeServer) {
      runcmd.push('curl -fsSL https://code-server.dev/install.sh | HOME=/root sh || true');
    }
  }

  // Reload systemd and enable services
  const servicesToEnable: string[] = [];
  if (config.autoDelete.enabled || servicesEnabled) servicesToEnable.push('devbox-daemon');
  if (servicesEnabled) {
    if (config.services.codeServer) servicesToEnable.push('code-server');
    if (config.services.shellTerminal) servicesToEnable.push('ttyd-term');
  }
  if (servicesToEnable.length > 0) {
    runcmd.push(`systemctl daemon-reload && systemctl enable --now ${servicesToEnable.join(' ')} || true`);
  }

  // IP/hash substitution and Caddy restart
  if (servicesEnabled) {
    runcmd.push('mkdir -p /var/www/devbox-overview');
    runcmd.push('IP=$(curl -4 -s ifconfig.me | tr "." "-")');
    runcmd.push(`HASH=$(caddy hash-password --plaintext "${shellEscape(config.services.accessToken)}")`);
    runcmd.push('sed -e "s/__IP__/$IP/g" -e "s|__HASH__|$HASH|g" /etc/caddy/Caddyfile.template > /etc/caddy/Caddyfile');
    runcmd.push('sed "s/__IP__/$IP/g" /var/www/devbox-overview/index.html.template > /var/www/devbox-overview/index.html');
    runcmd.push('systemctl restart caddy || true');
  }

  // Cleanup and fix ownership
  runcmd.push('apt-get clean && rm -rf /var/lib/apt/lists/* || true');
  runcmd.push('touch /home/dev/.devbox-ready && chown -R dev:dev /home/dev');

  cloudInit.runcmd = runcmd;

  // Convert to YAML
  return toYAML(cloudInit);
}

// Simple YAML serializer for cloud-init
function toYAML(obj: CloudInitConfig, indent = 0, isRoot = true): string {
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
          const lines = toYAML(item as unknown as CloudInitConfig, 0, false)
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
      yaml += toYAML(value as unknown as CloudInitConfig, indent + 1, false);
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
