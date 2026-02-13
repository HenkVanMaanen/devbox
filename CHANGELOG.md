# Changelog

All notable changes to Devbox will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [3.1.2] - 2026-02-13

### Added

- Add cloud-init progress tracking via Hetzner labels

### CI/Build

- Auto-generate CHANGELOG.md with git-cliff
## [3.1.1] - 2026-02-13

### Fixed

- Escape dot and hyphen in DNS domain input pattern for v-flag regex
## [3.1.0] - 2026-02-13

### Added

- Add SWR caching for Hetzner API calls
## [3.0.1] - 2026-02-13

### Fixed

- Use local network interface for IP detection instead of ifconfig.me
## [3.0.0] - 2026-02-12

### Added

- Replace UI config with chezmoi dotfile management

### Chore

- Add mosh back to changelog
- Remove mosh from changelog
## [2.6.0] - 2026-02-10

### Added

- Domain-agnostic Caddy configuration with custom domain support
## [2.5.1] - 2026-02-09

### Fixed

- Filter servers by label instead of name prefix
## [2.5.0] - 2026-02-09

### Added

- Simplify server names to just two words
## [2.4.0] - 2026-02-09

### Added

- Use hex IP format for DNS service URLs
## [2.3.0] - 2026-02-06

### Added

- Render changelog markdown at build time
## [2.2.0] - 2026-02-06

### Added

- Add changelog modal on version click
## [2.1.0] - 2026-02-06

### Added

- Add environment variables and cost estimation

### Changed

- Remove old vanilla JS app
## [2.0.19] - 2026-02-06

### Added

- Add Claude credentials upload to profile settings
## [2.0.18] - 2026-02-06

### Added

- Add all settings to ConfigForm for per-profile override
## [2.0.17] - 2026-02-05

### Changed

- Extract shared ConfigForm component for Config and ProfileEdit
## [2.0.16] - 2026-02-05

### Added

- Replace profile edit modal with dedicated page

### Documentation

- Restore ADR index in ADR README
- Remove ADR list from README, update tech stack
- Simplify ADR README by removing index table
- Add ADRs for Svelte 5 migration and update superseded decisions
## [2.0.15] - 2026-02-05

### Fixed

- Resolve profile editing and default selection bugs
## [2.0.14] - 2026-02-03

### Fixed

- Use UI theme for overview page, tmux, zellij, and xterm
## [2.0.13] - 2026-02-03

### Fixed

- Correct Actalis ACME directory URL
## [2.0.12] - 2026-02-03

### Added

- Add missing Svelte features for parity with vanilla JS
## [2.0.11] - 2026-02-03

### Fixed

- Restore missing cloud-init features from vanilla JS version
## [2.0.10] - 2026-02-03

### Added

- Add cloud-init preview page and fix server tokens
## [2.0.9] - 2026-02-03

### Added

- Add edit functionality for lists and import token/theme
## [2.0.8] - 2026-02-03

### Fixed

- Support both old and new config import formats
## [2.0.7] - 2026-02-03

### Added

- Add comprehensive configuration options
## [2.0.6] - 2026-02-03

### Added

- Add theme selector and SSH key validation
## [2.0.5] - 2026-02-03

### Added

- Add Profiles page, Export/Import, and full cloud-init
## [2.0.4] - 2026-02-03

### Fixed

- Add crypto.randomUUID fallback for older browsers
## [2.0.3] - 2026-02-03

### Fixed

- Use JSON clone for Svelte 5 proxy compatibility
## [2.0.2] - 2026-02-03

### Fixed

- Use Node.js test runner for legacy tests
## [2.0.1] - 2026-02-03

### Chore

- Add mise config for node and pnpm
- Switch to pnpm package manager
## [2.0.0] - 2026-02-03

### Added

- Add Svelte 5 + TypeScript implementation
## [1.0.11] - 2026-02-03

### Fixed

- Discard button triggering file picker, remove duplicate Save
## [1.0.10] - 2026-02-03

### Fixed

- Stop infinite re-render loop in form tracking
## [1.0.9] - 2026-02-03

### Fixed

- Allow form inputs to receive focus on click
## [1.0.8] - 2026-02-03

### Fixed

- Prevent re-render when tracking dirty form state
## [1.0.7] - 2026-02-03

### Fixed

- Console errors - clipboard fallback, matches() guard, favicon
## [1.0.6] - 2026-02-03

### Fixed

- Fetch git tags in deploy workflow
## [1.0.5] - 2026-02-03

### Fixed

- Set APP_VERSION from latest git tag in deploy workflow
## [1.0.4] - 2026-02-03

### Fixed

- Use APP_VERSION env var instead of package.json for version
## [1.0.3] - 2026-02-03

### Added

- Add version display with automated release versioning
## [1.0.2] - 2026-02-03

### Documentation

- Add contributing guidelines, changelog, and templates
## [1.0.1] - 2026-02-03

### Documentation

- Add v1.0.1 to changelog
## [1.0.0] - 2026-02-03

### Added

- Add UX enhancements for forms and clipboard
- Add smooth scrolling to ttyd terminal
- Add ANSI terminal colors to all themes
- Generate funny alliterative server names
- Add theme-matching configs for tmux and zellij
- Match ttyd terminal colors to user's selected theme
- Add skip permissions option for Claude Code
- Pre-warm TLS certificates when services are discovered
- Change default base image to Ubuntu 24.04 LTS
- Add @latest version option to all mise tools
- Add useful default packages for Claude Code users
- Replace NodeSource apt repo with mise for node
- Use wildcard Caddy route for dynamic services
- Add system-wide PATH for mise-installed tools

### CI/Build

- Add GitHub Actions workflow for automatic releases

### Changed

- Simplify terminal setup and rename index to overview
- Simplify domain format to {port}.{ip}.{dns}

### Chore

- Add local files to .gitignore
- Remove accidentally committed local files

### Documentation

- Update changelog for v1.0.0 release
- Add contributing guidelines, changelog, and templates
- Make AGENTS.md generic for all AI assistants
- Rename to AGENTS.md with CLAUDE.md reference
- Add CLAUDE.md with AI assistant guidelines
- Convert ASCII diagrams to Mermaid
- Add comprehensive documentation and ADRs

### Fixed

- Replace inline onclick handlers with event delegation for CSP compliance
- Strengthen CSP and add security headers
- Quote ttyd theme JSON in systemd service file
- Run devbox-daemon as dev user for mise trust
- Prevent infinite Hetzner API retry loop on invalid token

### Other

- Add multiple SSH keys support and inline editing for list fields

- Convert SSH keys from single pubKey string to array of {name, pubKey}
- Add sshKeys field type with add/edit/remove UI
- Add inline editing for both SSH keys and git credentials lists
- Sanitize SSH key names for Hetzner API compatibility
- Update cloud-init to map multiple keys to ssh_authorized_keys
- Add editingListItem state for tracking inline edit mode
- Add comprehensive tests for new functionality

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
- Add automatic port-based service discovery with Caddy Admin API

Rename devbox-autodelete to devbox-daemon with expanded functionality:
- Scan localhost ports every 10s and detect process names via ss -tlnp
- Auto-create Caddy routes for discovered services with basic auth
- Expose services at <port>.<domain> subdomains
- Clean up stale routes on startup and when services stop
- Enable daemon when services OR autodelete is enabled

Update index page to show process names and use globe icon for
auto-discovered services.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
- Use high ports (65531-65534) for internal services and add ufw firewall

- Change internal service ports to highest available range:
  - 8081 → 65531 (Autodelete Daemon API)
  - 8090 → 65532 (Code Server)
  - 7681 → 65533 (Claude Terminal)
  - 7682 → 65534 (Shell Terminal)

- Add ufw firewall with default-deny policy:
  - Install ufw package automatically
  - Configure firewall as first runcmd entry
  - Allow only SSH (22), HTTP (80), HTTPS (443)
  - Use --force to skip interactive prompt

- Add tests for firewall configuration and ufw package

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
- Add per-credential git identity (name/email)

Allow each git credential to optionally specify a custom name and email.
When working with repos from that host, commits use the credential's
identity instead of the global git config.

Uses Git's includeIf "hasconfig:remote.*.url:..." conditional includes
(Git 2.36+) to generate per-host gitconfig files that are automatically
included when working with repos from that host.

Changes:
- Add name/email inputs to git credentials UI in settings
- Generate .gitconfig file instead of runcmd git config commands
- Generate per-host .gitconfig-{host} files for credentials with identity
- Add escapeGitConfig helper for proper gitconfig value escaping
- Move SSH key and git credentials into global/profile config

Consolidate SSH public key and git credentials from the separate
Credentials page into the global config system, making them
profile-overridable. The Hetzner token remains on its own page,
renamed from "Credentials" to "API Token".

- Add ssh.pubKey and git.credentials to DEFAULT_GLOBAL_CONFIG
- Add SSH section and gitCredentials field type to settings
- Add git credential handlers for global and profile modes
- Remove old standalone credential functions from storage.js
- Update cloudinit.js to read credentials from config
- Update all "Credentials" text references to "API Token"
- Add comprehensive tests for new handlers

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
- Fix deploy workflow: use main branch and dist output dir

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
- Add esbuild bundling with content-hashed assets and Tailwind PostCSS integration

Replace standalone Tailwind CLI with esbuild + @tailwindcss/postcss for a unified
build pipeline. Production builds output to dist/ with hashed filenames for cache
busting. Dev server uses esbuild's watch + serve with live reload via SSE.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
- Replace Tailwind CDN with v4 build step, add CI/CD and project files

Move from runtime Tailwind CDN to a local Tailwind CSS v4 build using
@tailwindcss/cli. Extract inline config and styles into web/src/input.css
with @theme inline for runtime CSS variable theming. Update utility
classes for v4 compatibility (outline-hidden, --text-* namespace).

Add GitHub Actions workflow for automated GitHub Pages deployment,
pnpm lockfile, LICENSE (MIT), and README.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>

