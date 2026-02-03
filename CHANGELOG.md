# Changelog

All notable changes to Devbox will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Comprehensive documentation with architecture overview, security guide, and user guide
- 13 Architecture Decision Records (ADRs) documenting major decisions
- AGENTS.md with AI assistant guidelines
- CONTRIBUTING.md with contribution guidelines
- GitHub issue and PR templates
- Mermaid diagrams for all architecture documentation

### Changed
- Converted ASCII diagrams to Mermaid format
- Improved README with quick start and documentation links

### Security
- Removed `unsafe-inline` from script-src CSP directive
- Added `frame-ancestors 'none'` to prevent clickjacking
- Added `X-Content-Type-Options: nosniff` header

## [1.0.0] - 2025

### Added
- Initial release
- Hetzner Cloud integration (list, create, rebuild, delete servers)
- Cloud-init generator with configurable profiles
- Profile management system with global config + overrides
- QR code export for cloud-init scripts
- 7 themes with WCAG AAA accessibility (7:1 contrast)
- Zero-backend architecture (browser-only, localStorage)
- ttyd terminal integration
- Caddy reverse proxy with automatic HTTPS
- mise runtime version management
- Claude Code configuration support
- Funny alliterative server name generator
- Auto-delete functionality for ephemeral servers
