// Cloud-init user-data generator - using native cloud-init modules

import { getDefaultProfileConfig, getTheme as getStoredTheme } from './storage.js';
import { getTheme, getDefaultTheme, THEMES } from './themes.js';
import { shellEscape, buildGitCredentials, buildGitConfig, buildHostGitConfig, buildDaemonScript, buildCaddyConfig, buildIndexPage } from './cloudinit-builders.js';

// Main generate function - creates cloud-init user-data with native modules
export function generate(serverName, hetznerToken, config, options = {}) {
    if (!config) config = getDefaultProfileConfig();
    const gitCreds = options.gitCredentials || config.git?.credentials || [];
    const sshKeys = options.sshKeys || config.ssh?.keys || [];

    // Resolve theme colors
    let themeColors;
    if (options.themeColors) {
        themeColors = options.themeColors;
    } else {
        const storedTheme = getStoredTheme();
        const themeId = (storedTheme === 'system' || !storedTheme) ? getDefaultTheme() : storedTheme;
        const theme = getTheme(themeId) || THEMES[0];
        themeColors = theme.colors;
    }

    const servicesEnabled = config.services.codeServer || config.services.claudeTerminal || config.services.shellTerminal;
    const repos = config.repos || [];

    // Determine shell path
    const shellMap = { fish: '/usr/bin/fish', zsh: '/usr/bin/zsh', bash: '/bin/bash' };
    const shell = shellMap[config.shell.default] || '/bin/bash';

    // Build cloud-init object (using keyid+keyserver for reliable GPG key import)
    const cloudInit = {
        package_update: true,
        package_upgrade: true,
        apt: {
            sources: {
                'github-cli': {
                    source: 'deb [signed-by=$KEY_FILE] https://cli.github.com/packages stable main',
                    keyid: '23F3D4EA75716059',
                    keyserver: 'keyserver.ubuntu.com'
                }
            }
        },
        packages: [...new Set([...config.packages.apt, 'gh', 'ufw'])],
        users: [
            {
                name: 'dev',
                shell: shell,
                groups: ['sudo'],
                sudo: 'ALL=(ALL) NOPASSWD:ALL',
                ssh_authorized_keys: sshKeys.map(k => k.pubKey).filter(Boolean)
            }
        ],
        write_files: [],
        runcmd: []
    };

    // Track existing packages to avoid duplicates
    const pkgSet = new Set(cloudInit.packages);

    // Add Caddy repo if services enabled (using keyserver for reliable key import)
    if (servicesEnabled) {
        cloudInit.apt.sources['caddy'] = {
            source: 'deb [signed-by=$KEY_FILE] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main',
            keyid: '65760C51EDEA2017CEA2CA15155B6D79CA56EA34',
            keyserver: 'keyserver.ubuntu.com'
        };
        for (const pkg of ['debian-keyring', 'debian-archive-keyring', 'apt-transport-https', 'caddy']) {
            if (!pkgSet.has(pkg)) { cloudInit.packages.push(pkg); pkgSet.add(pkg); }
        }
    }

    // Add shell package if not bash (avoid duplicates with user packages)
    if (config.shell.default === 'fish' && !pkgSet.has('fish')) cloudInit.packages.push('fish');
    else if (config.shell.default === 'zsh' && !pkgSet.has('zsh')) cloudInit.packages.push('zsh');

    // dtach for persistent terminal sessions without tmux UI overhead
    if (!pkgSet.has('dtach')) cloudInit.packages.push('dtach');

    // ========== WRITE_FILES ==========

    // Mise shims PATH (system-wide for all processes, not just interactive shells)
    // Always enabled since daemon requires node
    const MISE_SHIMS = '/home/dev/.local/share/mise/shims';
    // /etc/profile.d/ for bash/zsh login shells
    cloudInit.write_files.push({
        path: '/etc/profile.d/mise.sh',
        permissions: '0644',
        content: `export PATH="${MISE_SHIMS}:$PATH"\n`
    });
    // fish config for system-wide fish shells
    cloudInit.write_files.push({
        path: '/etc/fish/conf.d/mise.fish',
        permissions: '0644',
        content: `set -gx PATH ${MISE_SHIMS} $PATH\n`
    });

    // Shell configs (mise activation for interactive features + starship)
    if (config.shell.default === 'fish') {
        let content = 'test -x /usr/local/bin/mise && /usr/local/bin/mise activate fish | source\n';
        if (config.shell.starship) content += 'type -q starship && starship init fish | source\n';
        cloudInit.write_files.push({
            path: '/home/dev/.config/fish/config.fish',
            owner: 'dev:dev',
            permissions: '0644',
            defer: true,
            content
        });
    } else if (config.shell.default === 'zsh') {
        let content = 'test -x /usr/local/bin/mise && eval "$(/usr/local/bin/mise activate zsh)"\n';
        if (config.shell.starship) content += 'command -v starship >/dev/null && eval "$(starship init zsh)"\n';
        cloudInit.write_files.push({
            path: '/home/dev/.zshrc',
            owner: 'dev:dev',
            permissions: '0644',
            defer: true,
            content
        });
    } else {
        let content = 'test -x /usr/local/bin/mise && eval "$(/usr/local/bin/mise activate bash)"\n';
        if (config.shell.starship) content += 'command -v starship >/dev/null && eval "$(starship init bash)"\n';
        cloudInit.write_files.push({
            path: '/home/dev/.bashrc',
            owner: 'dev:dev',
            permissions: '0644',
            append: true,
            defer: true,
            content
        });
    }

    // Git credentials
    if (gitCreds.length > 0) {
        cloudInit.write_files.push({
            path: '/home/dev/.git-credentials',
            owner: 'dev:dev',
            permissions: '0600',
            defer: true,
            content: buildGitCredentials(gitCreds)
        });
    }

    // Main gitconfig
    cloudInit.write_files.push({
        path: '/home/dev/.gitconfig',
        owner: 'dev:dev',
        permissions: '0644',
        defer: true,
        content: buildGitConfig(config, gitCreds)
    });

    // Per-host gitconfigs for credentials with custom identity
    gitCreds.forEach(cred => {
        const hostConfig = buildHostGitConfig(cred);
        if (hostConfig) {
            const safeHost = cred.host.replace(/[^a-zA-Z0-9._-]/g, '');
            cloudInit.write_files.push({
                path: `/home/dev/.gitconfig-${safeHost}`,
                owner: 'dev:dev',
                permissions: '0644',
                defer: true,
                content: hostConfig
            });
        }
    });

    // Claude config
    cloudInit.write_files.push({
        path: '/home/dev/.claude.json',
        owner: 'dev:dev',
        permissions: '0644',
        defer: true,
        content: '{"hasCompletedOnboarding":true,"bypassPermissionsModeAccepted":true}'
    });

    if (config.claude.credentialsJson) {
        cloudInit.write_files.push({
            path: '/home/dev/.claude/.credentials.json',
            owner: 'dev:dev',
            permissions: '0600',
            defer: true,
            content: JSON.stringify(config.claude.credentialsJson)
        });
    } else if (config.claude.apiKey) {
        cloudInit.write_files.push({
            path: '/home/dev/.claude/.credentials',
            owner: 'dev:dev',
            permissions: '0600',
            defer: true,
            content: config.claude.apiKey
        });
    }

    if (config.claude.theme || config.claude.settings) {
        const settings = {};
        if (config.claude.theme) settings.theme = config.claude.theme;
        if (config.claude.settings) {
            try { Object.assign(settings, JSON.parse(config.claude.settings)); } catch {}
        }
        if (Object.keys(settings).length > 0) {
            cloudInit.write_files.push({
                path: '/home/dev/.claude/settings.json',
                owner: 'dev:dev',
                permissions: '0644',
                defer: true,
                content: JSON.stringify(settings)
            });
        }
    }

    // Devbox daemon (port scanning, Caddy API, autodelete)
    // Enable if autodelete OR services are enabled (daemon handles both)
    if (config.autoDelete.enabled || servicesEnabled) {
        cloudInit.write_files.push({
            path: '/usr/local/bin/devbox-daemon',
            permissions: '0755',
            content: buildDaemonScript(config, hetznerToken)
        });
        // Include mise shims in PATH so daemon can use mise-installed node
        // Run as dev user so mise trusts the config
        cloudInit.write_files.push({
            path: '/etc/systemd/system/devbox-daemon.service',
            permissions: '0644',
            content: `[Unit]\nDescription=Devbox Daemon\nAfter=network.target caddy.service\n[Service]\nType=simple\nUser=dev\nEnvironment="PATH=${MISE_SHIMS}:/usr/local/bin:/usr/bin:/bin"\nExecStart=/usr/bin/env node /usr/local/bin/devbox-daemon\nRestart=always\nRestartSec=10\n[Install]\nWantedBy=multi-user.target\n`
        });
    }

    // Code-server config
    if (config.services.codeServer) {
        cloudInit.write_files.push({
            path: '/home/dev/.config/code-server/config.yaml',
            owner: 'dev:dev',
            permissions: '0600',
            defer: true,
            content: 'bind-addr: 127.0.0.1:65532\nauth: none\ncert: false\n'
        });
        // Include mise shims in PATH so code-server tasks/extensions can access mise-installed tools
        cloudInit.write_files.push({
            path: '/etc/systemd/system/code-server.service',
            permissions: '0644',
            content: `[Unit]\nDescription=Code Server\nAfter=network.target\n[Service]\nType=simple\nUser=dev\nWorkingDirectory=/home/dev\nEnvironment="PATH=${MISE_SHIMS}:/usr/local/bin:/usr/bin:/bin"\nExecStart=/usr/bin/code-server\nRestart=always\nRestartSec=10\n[Install]\nWantedBy=multi-user.target\n`
        });
    }

    // Claude terminal
    if (config.services.claudeTerminal) {
        // Include mise shims in PATH so claude can access mise-installed tools
        cloudInit.write_files.push({
            path: '/usr/local/bin/claude-terminal',
            permissions: '0755',
            content: `#!/bin/bash\nexport HOME=/home/dev\nexport PATH="${MISE_SHIMS}:$PATH"\ncd /home/dev\nexec dtach -A /tmp/devbox-claude -z claude --dangerously-skip-permissions\n`
        });
        cloudInit.write_files.push({
            path: '/etc/systemd/system/ttyd-claude.service',
            permissions: '0644',
            content: '[Unit]\nDescription=Claude\nAfter=network.target\n[Service]\nType=simple\nUser=dev\nWorkingDirectory=/home/dev\nExecStart=/usr/local/bin/ttyd -p 65533 -t fontSize=14 -t theme={"background":"#1a1a2e"} -W /usr/local/bin/claude-terminal\nRestart=always\nRestartSec=10\n[Install]\nWantedBy=multi-user.target\n'
        });
    }

    // Shell terminal
    if (config.services.shellTerminal) {
        cloudInit.write_files.push({
            path: '/etc/systemd/system/ttyd-term.service',
            permissions: '0644',
            content: `[Unit]\nDescription=Terminal\nAfter=network.target\n[Service]\nType=simple\nUser=dev\nWorkingDirectory=/home/dev\nEnvironment=HOME=/home/dev\nExecStart=/usr/local/bin/ttyd -p 65534 -t fontSize=14 -t theme={"background":"#1a1a2e"} -W dtach -A /tmp/devbox-shell -z ${config.shell.default || 'bash'}\nRestart=always\nRestartSec=10\n[Install]\nWantedBy=multi-user.target\n`
        });
    }

    // Caddy config and index page (use __IP__ placeholder)
    if (servicesEnabled) {
        cloudInit.write_files.push({
            path: '/etc/caddy/Caddyfile.template',
            permissions: '0644',
            content: buildCaddyConfig(config)
        });
        cloudInit.write_files.push({
            path: '/var/www/devbox-index/index.html.template',
            permissions: '0644',
            content: buildIndexPage(config, serverName, themeColors)
        });
    }

    // ========== RUNCMD ==========
    const runcmd = [];

    // Configure firewall (default deny, allow SSH/HTTP/HTTPS only)
    runcmd.push('ufw default deny incoming && ufw default allow outgoing && ufw allow 22 && ufw allow 80 && ufw allow 443 && ufw --force enable');

    // Mise installation (always required - daemon needs node)
    runcmd.push('curl -fsSL https://mise.run | MISE_INSTALL_PATH=/usr/local/bin/mise sh || true');
    // Install node (required for daemon) plus any user-selected tools
    const userTools = config.packages.mise || [];
    const hasNode = userTools.some(t => t.startsWith('node@'));
    const miseTools = hasNode ? userTools : ['node@latest', ...userTools];
    const miseInstalls = miseTools.map(tool =>
        `su - dev -c '/usr/local/bin/mise use --global ${shellEscape(tool)}' &`
    ).join('\n');
    runcmd.push(['bash', '-c', `${miseInstalls}\nwait`]);

    // claude-code (uses mise-installed node)
    runcmd.push(`su - dev -c 'PATH=${MISE_SHIMS}:$PATH npm install -g @anthropic-ai/claude-code' || true`);

    // Starship
    if (config.shell.starship) {
        runcmd.push('curl -fsSL https://starship.rs/install.sh | sh -s -- -y || true');
    }

    // Services - install binaries
    if (servicesEnabled) {
        if (config.services.claudeTerminal || config.services.shellTerminal) {
            runcmd.push('TTYD_ARCH=$(uname -m | sed "s/aarch64/aarch64/;s/x86_64/x86_64/") && curl -fsSL "https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.${TTYD_ARCH}" -o /usr/local/bin/ttyd && chmod +x /usr/local/bin/ttyd || true');
        }
        if (config.services.codeServer) {
            runcmd.push('curl -fsSL https://code-server.dev/install.sh | HOME=/root sh || true');
        }
    }

    // Reload systemd once and enable all services
    const servicesToEnable = [];
    if (config.autoDelete.enabled || servicesEnabled) servicesToEnable.push('devbox-daemon');
    if (servicesEnabled) {
        if (config.services.codeServer) servicesToEnable.push('code-server');
        if (config.services.claudeTerminal) servicesToEnable.push('ttyd-claude');
        if (config.services.shellTerminal) servicesToEnable.push('ttyd-term');
    }
    if (servicesToEnable.length > 0) {
        runcmd.push(`systemctl daemon-reload && systemctl enable --now ${servicesToEnable.join(' ')} || true`);
    }

    // IP/hash substitution and Caddy restart
    if (servicesEnabled) {
        runcmd.push('mkdir -p /var/www/devbox-index');
        runcmd.push('IP=$(curl -4 -s ifconfig.me | tr "." "-")');
        runcmd.push(`HASH=$(caddy hash-password --plaintext "${shellEscape(config.services.accessToken)}")`);
        runcmd.push('sed -e "s/__IP__/$IP/g" -e "s|__HASH__|$HASH|g" /etc/caddy/Caddyfile.template > /etc/caddy/Caddyfile');
        runcmd.push('sed "s/__IP__/$IP/g" /var/www/devbox-index/index.html.template > /var/www/devbox-index/index.html');
        runcmd.push('systemctl restart caddy || true');
    }

    // Clone repos (only valid URLs matching the input validation pattern)
    if (repos.length > 0) {
        repos.forEach(repo => {
            if (!/^(https?:\/\/|git@)[\w.@:\/~-]+$/.test(repo)) return;
            const name = repo.split('/').pop().replace(/\.git$/, '');
            const sshMatch = repo.match(/^git@([^:]+):(.+)$/);
            const httpsURL = sshMatch ? `https://${sshMatch[1]}/${sshMatch[2]}` : repo;
            runcmd.push(`su - dev -c 'git clone --depth 1 "${shellEscape(httpsURL)}" ~/${shellEscape(name)}' || true`);
        });
    }

    // Cleanup and fix ownership
    runcmd.push('apt-get clean && rm -rf /var/lib/apt/lists/* || true');
    runcmd.push('touch /home/dev/.devbox-ready && chown -R dev:dev /home/dev');

    cloudInit.runcmd = runcmd;

    // Convert to YAML
    return toYAML(cloudInit);
}

// Simple YAML serializer for cloud-init
function toYAML(obj, indent = 0, isRoot = true) {
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
                    const lines = toYAML(item, 0, false).split('\n').filter(l => l);
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
            yaml += toYAML(value, indent + 1, false);
        } else {
            yaml += `${pad}${key}: ${formatYAMLValue(value, indent)}\n`;
        }
    }
    return yaml;
}

function formatYAMLValue(value, indent = 0) {
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    if (typeof value === 'number') return String(value);
    if (typeof value === 'string') {
        // Multi-line strings - use block scalar
        if (value.includes('\n')) {
            const pad = '  '.repeat(indent + 1);
            let lines = value.split('\n');
            // Use | (keep) to preserve trailing newline, |- (strip) otherwise
            const chomp = value.endsWith('\n') ? '' : '-';
            // Remove empty trailing element from split (trailing newline is handled by chomp indicator)
            if (chomp === '' && lines[lines.length - 1] === '') {
                lines = lines.slice(0, -1);
            }
            return `|${chomp}\n` + lines.map(l => pad + l).join('\n');
        }
        // Strings that need quoting (YAML special chars, look like numbers/booleans/special values)
        if (value === '' || /^\s|\s$/.test(value) ||
            value.match(/^[{[\]#&*!|>'"%@`,?~]/) ||
            value.includes(': ') || value.includes(' #') || value.endsWith(':') ||
            /^[-+]?(\d[\d_]*\.?[\d_]*|\.inf|\.nan)$/i.test(value) ||
            /^(true|false|null|yes|no|on|off|~)$/i.test(value)) {
            return JSON.stringify(value);
        }
        return value;
    }
    return String(value);
}
