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
   - Chezmoi dotfiles repo URL and age key
   - Git credential for cloning

## Core Concepts

### Global Configuration

Global config contains settings that apply to all servers by default:

- **SSH Keys**: Your public keys for server access
- **Chezmoi Dotfiles**: Repo URL, age key, and bootstrap git credential
- **Hetzner Settings**: Server type, location, base image
- **Services**: DNS service, ACME provider, access token
- **Auto-Delete**: Idle timeout settings

Personal dev environment config (shell, packages, git user, Claude Code, env vars) is managed by [chezmoi](https://github.com/twpayne/chezmoi) in your dotfiles repo.

Access via **Global Config** in the navigation.

### Profiles

Profiles let you override specific global settings for different projects or use cases.

**Example profiles:**

| Profile        | Purpose                 | Overrides                        |
| -------------- | ----------------------- | -------------------------------- |
| `eu-server`    | European location       | `hetzner.location: "fsn1"`       |
| `heavy`        | Resource-intensive work | `hetzner.serverType: "cx42"`     |
| `long-running` | Extended sessions       | `autoDelete.timeoutMinutes: 480` |

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

### Chezmoi Dotfiles

```
chezmoi.repoUrl: "https://github.com/user/dotfiles.git"
chezmoi.ageKey: "AGE-SECRET-KEY-1..."
```

Your private dotfiles repo is cloned and applied via `chezmoi init --apply` on server boot. The age key is used to decrypt encrypted secrets in your chezmoi repo. Chezmoi manages shell config, packages, git user settings, Claude Code setup, and environment variables.

### Git Credential

```
git.credential: { host: "github.com", username: "user", token: "ghp_..." }
```

A single bootstrap credential used to clone your chezmoi repo and any private repositories. Additional credentials are managed by chezmoi.

### Services

```
services.dnsService: "sslip.io"         # DNS service for subdomains
services.acmeProvider: "zerossl"        # Certificate provider
services.acmeEmail: "admin@example.com" # ACME registration email
services.accessToken: "abc123"          # Basic auth token for services
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

| Key          | Action                  |
| ------------ | ----------------------- |
| `Ctrl+Enter` | Submit current form     |
| `Escape`     | Close modal             |
| `Tab`        | Navigate between fields |

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

- Verify your chezmoi dotfiles correctly configure Claude Code
- Check `~/.claude/settings.json` on the server
- Try running `claude` manually to see error messages

## Tips

1. **Use chezmoi**: Manage your entire dev environment as code in a git repo
2. **Use age encryption**: Keep secrets (API keys, tokens) encrypted in your dotfiles
3. **Save profiles**: Use profiles for different server types/locations
4. **Check cloud-init size**: Large configs may need trimming
