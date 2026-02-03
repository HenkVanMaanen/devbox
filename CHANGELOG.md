# Changelog

All notable changes to Devbox will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [1.0.9] - 2026-02-03

### Fixed
- Form inputs now properly receive focus on click

## [1.0.8] - 2026-02-03

### Fixed
- Input fields no longer lose focus while typing (dirty tracking fix)

## [1.0.7] - 2026-02-03

### Fixed
- Clipboard copy now works on HTTP (fallback for non-secure contexts)
- Fixed "matches is not a function" error from browser extensions
- Added favicon

## [1.0.6] - 2026-02-03

### Fixed
- Fetch git tags in deploy workflow for correct version display

## [1.0.5] - 2026-02-03

### Fixed
- GitHub Pages deployment now shows correct version from latest git tag

## [1.0.4] - 2026-02-03

### Fixed
- Version now correctly derived from git tag (shows "dev" locally)

## [1.0.3] - 2026-02-03

### Added
- Version display in navigation bar
- Automated version injection from git tag during release build
- Pre-built dist zip attached to GitHub releases

## [1.0.2] - 2026-02-03

### Added
- GitHub Actions workflow for automatic releases on tag push

### Fixed
- Replace inline onclick handlers with event delegation for CSP compliance

## [1.0.0] - 2026-02-03

### Added
- Hetzner Cloud integration (list, create, rebuild, delete servers)
- Cloud-init generator with configurable profiles
- Profile management system with global config + overrides
- QR code export for cloud-init scripts
- 7 themes with WCAG AAA accessibility (7:1 contrast)
- Zero-backend architecture (browser-only, localStorage)
- ttyd terminal integration with theme-matched colors
- Caddy reverse proxy with automatic HTTPS
- mise runtime version management
- Claude Code configuration support
- Funny alliterative server name generator
- Auto-delete functionality for ephemeral servers
- Copy to clipboard buttons for server IPs and service URLs
- SSH key validation with auto-name extraction from key comments
- Floating save/discard bar for unsaved form changes
- Unsaved changes warning on page navigation
- Tooltips with help text for settings fields
- Comprehensive documentation (architecture, security, user guide)
- 13 Architecture Decision Records (ADRs)
- AGENTS.md with AI assistant guidelines
- CONTRIBUTING.md with contribution guidelines

### Security
- Content Security Policy without unsafe-inline
- frame-ancestors 'none' to prevent clickjacking
- X-Content-Type-Options: nosniff header
- Input validation and HTML escaping throughout
