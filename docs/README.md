# Devbox Documentation

## Overview

Devbox is a browser-based development environment manager for Hetzner Cloud. It allows solo developers to quickly spin up ephemeral cloud development servers configured for AI-assisted coding with Claude Code.

## Quick Links

- [Architecture Overview](./architecture.md)
- [Security](./security.md)
- [Architecture Decision Records](./adr/)
- [User Guide](./user-guide.md)

## Key Concepts

### Ephemeral Dev Environments

Devbox is designed for **short-running development environments** — typically lasting a single workday. This approach:

- Keeps costs minimal (Hetzner charges hourly)
- Encourages reproducible environments
- Eliminates "works on my machine" drift
- Makes experimentation cheap

### Zero-Backend Architecture

The entire application runs in your browser. There is no central server:

- Your Hetzner API token stays on your machine
- Credentials are stored in localStorage
- API calls go directly from your browser to Hetzner Cloud

### Profile-Based Configuration

Devbox uses a two-level configuration system:

1. **Global Config** — Default settings for all servers
2. **Profiles** — Override specific settings for different projects/use cases

This lets you maintain consistent defaults while customizing per-project needs.

## Architecture Decision Records

ADRs document the significant architectural decisions made in this project:

| ADR                                               | Title                                 | Status            |
| ------------------------------------------------- | ------------------------------------- | ----------------- |
| [001](./adr/0001-zero-backend-architecture.md)    | Zero-Backend Architecture             | Accepted          |
| [002](./adr/0002-hetzner-cloud-provider.md)       | Hetzner Cloud as Initial Provider     | Accepted          |
| [003](./adr/0003-cloud-init-provisioning.md)      | Cloud-Init for Server Provisioning    | Accepted          |
| [004](./adr/0004-hash-based-routing.md)           | Hash-Based Client-Side Routing        | Accepted          |
| [005](./adr/0005-localstorage-persistence.md)     | localStorage for Data Persistence     | Accepted          |
| [006](./adr/0006-two-level-config-hierarchy.md)   | Two-Level Configuration Hierarchy     | Accepted          |
| [007](./adr/0007-wcag-aaa-accessibility.md)       | WCAG AAA Accessibility Compliance     | Accepted          |
| [008](./adr/0008-ttyd-terminal.md)                | ttyd for Browser-Based Terminal       | Accepted          |
| [009](./adr/0009-caddy-reverse-proxy.md)          | Caddy as Reverse Proxy                | Accepted          |
| [010](./adr/0010-mise-runtime-manager.md)         | mise for Runtime Version Management   | Accepted          |
| [011](./adr/0011-claude-code-primary-use-case.md) | Claude Code as Primary Use Case       | Accepted          |
| [012](./adr/0012-security-model.md)               | Security Model and Threat Assumptions | Accepted          |
| [013](./adr/0013-mermaid-diagrams.md)             | Mermaid for Documentation Diagrams    | Accepted          |
| [014](./adr/0014-esbuild-bundler.md)              | esbuild as Build Tool                 | Superseded by 018 |
| [015](./adr/0015-native-test-runner.md)           | Node.js Native Test Runner            | Accepted          |
| [016](./adr/0016-no-typescript.md)                | Plain JavaScript (No TypeScript)      | Superseded by 020 |
| [018](./adr/0018-vite-build-tool.md)              | Vite as Build Tool                    | Accepted          |
| [020](./adr/0020-svelte5-runes.md)                | Svelte 5 with Runes                   | Accepted          |
| [021](./adr/0021-tailwind-v4.md)                  | Tailwind CSS v4                       | Accepted          |
| [022](./adr/0022-pnpm.md)                         | pnpm Package Manager                  | Accepted          |
| [023](./adr/0023-chezmoi-dotfile-management.md)   | chezmoi for Dotfile Management        | Accepted          |

## Project Structure

```
devbox/
├── src/                    # Svelte 5 + TypeScript SPA
│   ├── App.svelte         # Root component
│   ├── main.ts            # Entry point
│   ├── components/        # Reusable UI components
│   ├── pages/             # Page components
│   └── lib/
│       ├── api/           # API clients (Hetzner)
│       ├── stores/        # Svelte runes-based stores
│       ├── utils/         # Utility functions
│       └── data/          # Static data (options)
├── tests/                  # Test suite
├── docs/                   # Documentation
│   └── adr/               # Architecture Decision Records
├── dist/                   # Production build output
├── index.html             # Entry HTML with CSP headers
└── vite.config.ts         # Vite build configuration
```

## Technology Stack

| Component       | Technology                 | Why                                          |
| --------------- | -------------------------- | -------------------------------------------- |
| Framework       | Svelte 5 with runes        | Reactive, minimal boilerplate, excellent DX  |
| Language        | TypeScript                 | Type safety, better tooling, maintainability |
| Styling         | Tailwind CSS v4            | Utility-first, small bundle, easy theming    |
| Build           | Vite                       | Fast HMR, excellent Svelte support           |
| Testing         | Node.js native test runner | Zero dependencies, built-in                  |
| Package Manager | pnpm                       | Fast, disk-efficient                         |
| Deployment      | GitHub Pages               | Free, automatic via GitHub Actions           |
