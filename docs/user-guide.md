# User Guide

## Getting Started

### Prerequisites

1. A [Hetzner Cloud](https://www.hetzner.com/cloud) account
2. A Hetzner API token (create in Hetzner Cloud Console → Security → API Tokens)
3. A domain name (optional, for HTTPS access)

### Initial Setup

1. Open Devbox in your browser
2. Navigate to **Credentials** (`#/credentials`)
3. Enter your Hetzner API token
4. Configure your Global Config with:
   - SSH public keys
   - Git name and email
   - Preferred shell

## Core Concepts

### Global Configuration

Global config contains settings that apply to all servers by default:

- **SSH Keys**: Your public keys for server access
- **Git Configuration**: Name, email, and optional credentials
- **Shell**: Default shell (bash, zsh, fish)
- **Packages**: Default apt and mise packages
- **Services**: ttyd, Caddy, and other services
- **Claude Code**: API key and preferences

Access via **Global Config** in the navigation.

### Profiles

Profiles let you override specific global settings for different projects or use cases.

**Example profiles:**

| Profile | Purpose | Overrides |
|---------|---------|-----------|
| `nodejs` | Node.js projects | `packages.mise: ["node@lts"]` |
| `python-ml` | ML/Data science | `packages.mise: ["python@3.12"]`, `packages.apt: ["python3-venv"]` |
| `minimal` | Quick experiments | Most services disabled |
| `full-stack` | Web development | Node.js + database packages |

### Creating a Profile

1. Go to **Profiles** (`#/profiles`)
2. Click **New Profile**
3. Give it a name
4. Toggle settings to override (click the checkbox next to each setting)
5. Save

Only toggled settings will override global config.

## Creating a Server

### Quick Create

1. Go to **Dashboard** (`#/`)
2. Select a profile (or use global defaults)
3. Choose server type and location
4. Click **Create Server**

The server will be provisioned with your configuration via cloud-init.

### Cloud-Init Preview

Before creating, you can preview the generated cloud-init script:

1. Go to **Cloud-Init** (`#/cloudinit`)
2. Review the YAML that will be sent to Hetzner
3. Check the size indicator (must be under 32KB)

### Accessing Your Server

Once the server is running:

1. Click the **Terminal** link on the dashboard
2. A new tab opens with ttyd terminal access
3. Start coding with Claude Code: `claude`

## Configuration Reference

### SSH Keys

```
ssh.keys: ["ssh-ed25519 AAAA... user@machine"]
```

Multiple keys supported. These are added to the dev user's `authorized_keys`.

### Git Configuration

```
git.name: "Your Name"
git.email: "you@example.com"
git.credentials: [
  { host: "github.com", username: "user", token: "ghp_..." }
]
```

Credentials are stored in `~/.git-credentials` with HTTPS credential helper.

### Packages

**APT packages** (system packages):
```
packages.apt: ["git", "curl", "jq", "ripgrep"]
```

**mise packages** (runtime versions):
```
packages.mise: ["node@lts", "python@3.12", "go@latest"]
```

### Shell Configuration

```
shell.default: "zsh"           # bash, zsh, or fish
shell.starship: true           # Enable Starship prompt
```

### Services

```
services.ttyd: true            # Browser terminal (recommended)
services.caddy: true           # Reverse proxy for HTTPS
services.acmeProvider: "letsencrypt"  # Certificate provider
services.domain: "dev.example.com"    # Your domain
```

### Claude Code

```
claude.apiKey: "sk-ant-..."    # Anthropic API key
claude.skipPermissions: false  # Auto-approve tool use
claude.theme: "dark"           # Match UI theme
```

## Workflows

### Daily Development Workflow

1. **Morning**: Create a server with your project's profile
2. **Day**: Develop using Claude Code in the browser terminal
3. **Evening**: Commit/push changes, delete the server

Servers are billed hourly, so deleting overnight saves money.

### Sharing an Environment

Share your configuration via QR code:

1. Go to **Cloud-Init** preview
2. Click **Generate QR Code**
3. Share the QR code — others can scan to import the cloud-init script

Note: This shares configuration, not credentials.

### Auto-Delete

Configure servers to auto-delete after a period:

```
server.autoDelete: true
server.autoDeleteHours: 8
```

Useful to avoid forgetting to delete servers.

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+Enter` | Submit current form |
| `Escape` | Close modal |
| `Tab` | Navigate between fields |

## Troubleshooting

### Server won't start

- Check Hetzner Cloud Console for error messages
- Verify your API token has write permissions
- Check cloud-init size (must be under 32KB)

### Can't access terminal

- Wait for cloud-init to complete (check `/var/log/cloud-init-output.log`)
- Verify Caddy is running: `systemctl status caddy`
- Check DNS is pointing to server IP

### Claude Code not working

- Verify API key is correct
- Check `~/.claude/settings.json` on the server
- Try running `claude` manually to see error messages

## Tips

1. **Use mise for runtimes**: More flexible than system packages
2. **Enable Starship**: Better terminal prompt experience
3. **Use zsh**: Better completion and history than bash
4. **Save profiles**: Don't recreate config each time
5. **Check cloud-init size**: Large configs may need trimming
