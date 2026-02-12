# ADR 0023: chezmoi for Dotfile Management

## Status

Accepted (supersedes ADR 0010 for runtime management, changes scope of ADR 0003 and ADR 0011)

## Context

Devbox previously baked all dev environment configuration into cloud-init via UI settings:

- Shell selection and configuration (bash, zsh, fish, starship)
- Package management (apt packages, mise runtimes)
- Git user config (name, email, multiple credentials)
- Claude Code settings (API key, theme, permissions, credentials.json)
- Environment variables
- Repository cloning

This approach had several problems:

1. **Cloud-init bloat**: All config was serialized into the 32KB user-data, leaving less room for services
2. **UI complexity**: The config form had 7+ cards for personal preferences that differ per user
3. **Coupling**: The Devbox UI was tightly coupled to personal dev environment choices
4. **Duplication**: Users already manage dotfiles — Devbox was recreating that in a web UI
5. **Limited flexibility**: Only settings exposed in the UI could be configured

## Decision

Use [chezmoi](https://github.com/twpayne/chezmoi) to manage all personal dev environment configuration. The Devbox UI provides only:

- **SSH keys** — needed for Hetzner API registration
- **Chezmoi config** — dotfiles repo URL and age private key for secret decryption
- **Bootstrap git credential** — single credential to clone the chezmoi repo
- **Hetzner settings** — server type, location, base image
- **Service settings** — DNS service, ACME provider, access token
- **Auto-delete** — idle timeout configuration

Cloud-init is now minimal: it installs chezmoi, writes the bootstrap credential and age key, then runs `chezmoi init --apply` which sets up everything else.

## Consequences

### Positive

- **Smaller cloud-init**: Significantly less user-data, well within 32KB limit
- **Simpler UI**: Fewer config cards, focused on infrastructure not preferences
- **Environment as code**: Users manage their dev environment in a git repo
- **Full flexibility**: Any tool, config, or script can be in the chezmoi repo
- **Portable**: Same dotfiles work on any machine, not just Devbox servers
- **Encrypted secrets**: age encryption keeps API keys and tokens safe in the repo

### Negative

- **Learning curve**: Users must learn chezmoi (repo setup, templates, age encryption)
- **Bootstrap dependency**: Need a git credential to clone the chezmoi repo itself
- **Slower first boot**: chezmoi init downloads and applies dotfiles after cloud-init

### Neutral

- **Age key management**: Users must generate and store an age key pair

## What Moved to chezmoi

| Previously in Devbox UI | Now in chezmoi dotfiles |
|------------------------|------------------------|
| Shell selection (bash/zsh/fish) | `~/.bashrc`, `~/.zshrc`, `chsh` |
| Starship prompt | Starship install + `starship.toml` |
| mise runtimes | `.mise.toml`, mise install script |
| APT packages | chezmoi run script |
| Git user config (name, email) | `~/.gitconfig` template |
| Git credentials (multiple hosts) | `~/.git-credentials` encrypted |
| Claude Code API key + settings | `~/.claude/` config files |
| Environment variables | Shell rc files or `~/.env` |
| Repository cloning | chezmoi run script |
| tmux/zellij config | Dotfiles |
| Code-server setup | chezmoi run script (if desired) |

## What Remains in Devbox

| Setting | Why |
|---------|-----|
| SSH keys | Registered with Hetzner API before server creation |
| Chezmoi repo URL | Needed in cloud-init before chezmoi is installed |
| Age key | Written to disk before chezmoi runs |
| Bootstrap git credential | Needed to clone the chezmoi repo |
| Hetzner server type/location | Infrastructure, not personal config |
| Service settings (DNS, ACME) | Caddy/daemon config, not personal |
| Auto-delete | Server lifecycle, not personal |

## Alternatives Considered

### Keep UI-based configuration

Continue managing everything through the Devbox web UI:
- Familiar to existing users
- But increasingly complex UI
- Duplicates dotfile management that users already do

Rejected because it doesn't scale and couples infrastructure to preferences.

### Ansible/scripts via SSH

Run configuration management after boot:
- Maximum flexibility
- But requires a backend or SSH access
- Contradicts zero-backend architecture (ADR 0001)

Rejected for same reasons as in ADR 0003.

### Nix/NixOS

Declarative system configuration:
- Reproducible environments
- But steep learning curve
- Heavyweight for ephemeral dev servers

Rejected because chezmoi is simpler and focused on dotfiles.
