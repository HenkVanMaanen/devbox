// Cloud-init user-data generator - using native cloud-init modules

import type { GlobalConfig, SSHKey, GitCredential } from '$lib/types';
import {
  shellEscape,
  fishEscape,
  buildGitCredentials,
  buildGitConfig,
  buildHostGitConfig,
  buildDaemonScript,
  buildCaddyConfig,
  buildOverviewPage,
  defaultThemeColors,
  defaultTerminalColors,
  type ThemeColors,
  type TerminalColors,
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
    themeColors?: ThemeColors;
    terminalColors?: TerminalColors;
  } = {}
): string {
  const gitCreds = options.gitCredentials ?? config.git?.credentials ?? [];
  const sshKeys = options.sshKeys ?? config.ssh?.keys ?? [];

  // Use provided theme colors or defaults
  const themeColors = options.themeColors ?? defaultThemeColors;
  const terminalColors = options.terminalColors ?? defaultTerminalColors;

  const servicesEnabled = config.services.codeServer || config.services.shellTerminal;
  const MISE_SHIMS = '/home/dev/.local/share/mise/shims';

  // DNS service (sslip.io or nip.io)
  const dnsService = config.services.dnsService || 'sslip.io';

  // Shell (fish, zsh, or bash)
  const defaultShell = config.shell.default || 'fish';
  const shellBin = defaultShell === 'fish' ? '/usr/bin/fish' : defaultShell === 'zsh' ? '/usr/bin/zsh' : '/bin/bash';

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
        shell: shellBin,
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

  // Add shell package if not bash
  if (defaultShell === 'fish' && !pkgSet.has('fish')) {
    cloudInit.packages.push('fish');
    pkgSet.add('fish');
  } else if (defaultShell === 'zsh' && !pkgSet.has('zsh')) {
    cloudInit.packages.push('zsh');
    pkgSet.add('zsh');
  }

  // Add user-selected APT packages
  if (config.packages?.apt?.length > 0) {
    for (const pkg of config.packages.apt) {
      if (!pkgSet.has(pkg)) {
        cloudInit.packages.push(pkg);
        pkgSet.add(pkg);
      }
    }
  }

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

  // Environment variables - inject into system-wide shell startup files
  // Validate env var names (POSIX compliant: start with letter/underscore, contain only letters/digits/underscores)
  const validEnvVarName = /^[A-Za-z_][A-Za-z0-9_]*$/;
  const envVars = (config.envVars ?? []).filter((ev) => validEnvVarName.test(ev.name));

  if (envVars.length > 0) {
    // Bash/Zsh system-wide env vars (/etc/profile.d/)
    const bashEnvContent = envVars.map((ev) => `export ${ev.name}="${shellEscape(ev.value)}"`).join('\n') + '\n';
    cloudInit.write_files.push({
      path: '/etc/profile.d/devbox-env.sh',
      permissions: '0644',
      content: bashEnvContent,
    });

    // Fish system-wide env vars (/etc/fish/conf.d/)
    const fishEnvContent = envVars.map((ev) => `set -gx ${ev.name} "${fishEscape(ev.value)}"`).join('\n') + '\n';
    cloudInit.write_files.push({
      path: '/etc/fish/conf.d/devbox-env.fish',
      permissions: '0644',
      content: fishEnvContent,
    });
  }

  // Bash config with mise activation and starship
  let bashContent = 'test -x /usr/local/bin/mise && eval "$(/usr/local/bin/mise activate bash)"\n';
  if (config.shell.starship) {
    bashContent += 'command -v starship >/dev/null && eval "$(starship init bash)"\n';
  }
  // Add env vars to .bashrc for non-login shells (e.g., ttyd)
  if (envVars.length > 0) {
    bashContent += envVars.map((ev) => `export ${ev.name}="${shellEscape(ev.value)}"`).join('\n') + '\n';
  }
  cloudInit.write_files.push({
    path: '/home/dev/.bashrc',
    owner: 'dev:dev',
    permissions: '0644',
    defer: true,
    append: true,
    content: bashContent,
  });

  // Zsh config
  if (defaultShell === 'zsh') {
    let zshContent = 'test -x /usr/local/bin/mise && eval "$(/usr/local/bin/mise activate zsh)"\n';
    if (config.shell.starship) {
      zshContent += 'command -v starship >/dev/null && eval "$(starship init zsh)"\n';
    }
    if (config.claude.skipPermissions) {
      zshContent += 'alias claude="claude --dangerously-skip-permissions"\n';
    }
    // Add env vars for non-login shells (e.g., ttyd)
    if (envVars.length > 0) {
      zshContent += envVars.map((ev) => `export ${ev.name}="${shellEscape(ev.value)}"`).join('\n') + '\n';
    }
    cloudInit.write_files.push({
      path: '/home/dev/.zshrc',
      owner: 'dev:dev',
      permissions: '0644',
      defer: true,
      content: zshContent,
    });
  }

  // Fish config
  if (defaultShell === 'fish') {
    let fishContent = `if test -x /usr/local/bin/mise
    /usr/local/bin/mise activate fish | source
end
`;
    if (config.shell.starship) {
      fishContent += `if command -v starship >/dev/null
    starship init fish | source
end
`;
    }
    if (config.claude.skipPermissions) {
      fishContent += 'alias claude="claude --dangerously-skip-permissions"\n';
    }
    // Add env vars for non-login shells (e.g., ttyd)
    if (envVars.length > 0) {
      fishContent += envVars.map((ev) => `set -gx ${ev.name} "${fishEscape(ev.value)}"`).join('\n') + '\n';
    }
    cloudInit.write_files.push({
      path: '/home/dev/.config/fish/config.fish',
      owner: 'dev:dev',
      permissions: '0644',
      defer: true,
      content: fishContent,
    });
  }

  // Bash - also add alias if skip permissions
  if (defaultShell === 'bash' && config.claude.skipPermissions) {
    cloudInit.write_files.push({
      path: '/home/dev/.bashrc',
      owner: 'dev:dev',
      permissions: '0644',
      defer: true,
      append: true,
      content: 'alias claude="claude --dangerously-skip-permissions"\n',
    });
  }

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

  // Zellij config with theme colors
  cloudInit.write_files.push({
    path: '/home/dev/.config/zellij/config.kdl',
    owner: 'dev:dev',
    permissions: '0644',
    defer: true,
    content: `// Theme colors (auto-generated from devbox theme)
theme "devbox"
themes {
    devbox {
        fg "${themeColors.foreground}"
        bg "${themeColors.background}"
        black "${themeColors.background}"
        red "${themeColors.destructive}"
        green "${themeColors.success}"
        yellow "${themeColors.warning}"
        blue "${themeColors.primary}"
        magenta "${themeColors.primary}"
        cyan "${themeColors.primary}"
        white "${themeColors.foreground}"
        orange "${themeColors.warning}"
    }
}

// Sensible defaults
pane_frames false
default_layout "compact"
mouse_mode true
copy_on_select true
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

  // Per-host gitconfigs for credentials with custom identity
  for (const cred of gitCreds) {
    const hostConfig = buildHostGitConfig(cred);
    if (hostConfig) {
      const safeHost = cred.host.replace(/[^a-zA-Z0-9._-]/g, '');
      cloudInit.write_files.push({
        path: `/home/dev/.gitconfig-${safeHost}`,
        owner: 'dev:dev',
        permissions: '0644',
        defer: true,
        content: hostConfig,
      });
    }
  }

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

  if (config.claude.theme || config.claude.settings) {
    const settings: Record<string, unknown> = {};
    if (config.claude.theme) settings.theme = config.claude.theme;
    if (config.claude.settings) {
      try {
        Object.assign(settings, JSON.parse(config.claude.settings));
      } catch {
        // Invalid JSON, skip
      }
    }
    if (Object.keys(settings).length > 0) {
      cloudInit.write_files.push({
        path: '/home/dev/.claude/settings.json',
        owner: 'dev:dev',
        permissions: '0644',
        defer: true,
        content: JSON.stringify(settings),
      });
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
      content: `[Unit]\nDescription=Terminal\nAfter=network.target\n[Service]\nType=simple\nUser=dev\nWorkingDirectory=/home/dev\nEnvironment=HOME=/home/dev\nExecStart=/usr/local/bin/ttyd -p 65534 -t fontSize=14 -t smoothScrollDuration=50 -t 'theme=${ttydTheme}' -W ${defaultShell}\nRestart=always\nRestartSec=10\n[Install]\nWantedBy=multi-user.target\n`,
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

  // Install node (required for daemon) plus any user-selected tools - parallel for speed
  const userTools = config.packages?.mise ?? [];
  const hasNode = userTools.some((t) => t.startsWith('node@'));
  const allMiseTools = hasNode ? userTools : ['node@latest', ...userTools];
  if (allMiseTools.length > 0) {
    const miseInstalls = allMiseTools
      .map((tool) => `su - dev -c '/usr/local/bin/mise use --global ${shellEscape(tool)}' &`)
      .join('\n');
    runcmd.push(['bash', '-c', `${miseInstalls}\nwait`]);
  }

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
    runcmd.push('IP=$(curl -4 -s ifconfig.me | awk -F. \'{printf "%02x%02x%02x%02x", $1, $2, $3, $4}\')');
    runcmd.push(`HASH=$(caddy hash-password --plaintext "${shellEscape(config.services.accessToken)}")`);
    runcmd.push('sed -e "s/__IP__/$IP/g" -e "s|__HASH__|$HASH|g" /etc/caddy/Caddyfile.template > /etc/caddy/Caddyfile');
    runcmd.push('sed "s/__IP__/$IP/g" /var/www/devbox-overview/index.html.template > /var/www/devbox-overview/index.html');
    runcmd.push('systemctl restart caddy || true');
  }

  // Clone repositories (shallow clones for speed)
  if (config.repos?.length > 0) {
    for (const repo of config.repos) {
      // Only valid URLs matching the input validation pattern
      if (!/^(https?:\/\/|git@)[\w.@:/~-]+$/.test(repo)) continue;
      const name = repo.split('/').pop()?.replace(/\.git$/, '') ?? 'repo';
      // Convert git@ SSH URLs to HTTPS for consistent authentication
      const sshMatch = repo.match(/^git@([^:]+):(.+)$/);
      const httpsURL = sshMatch ? `https://${sshMatch[1]}/${sshMatch[2]}` : repo;
      runcmd.push(`su - dev -c 'git clone --depth 1 "${shellEscape(httpsURL)}" ~/${shellEscape(name)}' || true`);
    }
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
