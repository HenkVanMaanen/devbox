# Devbox

A browser-based development environment manager for Hetzner Cloud. Spin up ephemeral cloud dev servers for AI-assisted coding with Claude Code — all from a single-page app with no backend.

## Why Devbox?

- **Cheap**: Hetzner's hourly billing means a full day of development costs cents
- **Fast**: Servers ready in under a minute with your full dev environment
- **Ephemeral**: Spin up in the morning, delete at night — no state to maintain
- **Private**: Your API tokens never leave your browser

## Features

- **Hetzner Cloud integration** — list, create, rebuild, and delete servers via API
- **Cloud-init generator** — build user-data scripts from configurable profiles
- **Profile management** — save and switch between configurations
- **QR code export** — share cloud-init scripts
- **WCAG AAA accessible** — 7:1 contrast, keyboard navigation, reduced-motion support
- **Theme support** — dark and light themes with live switching
- **Zero backend** — runs entirely in browser, credentials in localStorage

## Quick Start

```sh
# Install dependencies
pnpm install

# Build for production
pnpm run build

# Open in browser
open web/index.html
```

Or for development with auto-reload:

```sh
pnpm run dev
```

## Usage

1. **Add credentials**: Enter your Hetzner API token in Credentials
2. **Configure**: Set up SSH keys, Git config, packages in Global Config
3. **Create profiles**: Save configurations for different projects
4. **Launch**: Create a server and access via browser terminal
5. **Code**: Use Claude Code for AI-assisted development
6. **Clean up**: Delete server when done

## Documentation

- [User Guide](./docs/user-guide.md) — how to use Devbox
- [Architecture](./docs/architecture.md) — system design and module structure
- [Security](./docs/security.md) — security model, controls, and considerations
- [ADRs](./docs/adr/) — architecture decision records

## Tech Stack

| Component | Technology |
|-----------|------------|
| Framework | Svelte 5 |
| Language | TypeScript (strict) |
| Styling | Tailwind CSS v4 |
| Build | Vite |
| Testing | Node.js native test runner |
| Package Manager | pnpm |
| Deployment | GitHub Pages |

## Development

Run tests:

```sh
pnpm test
```

Watch for changes:

```sh
pnpm run dev
```

## Deployment

Deploys automatically to GitHub Pages on push to `main` via GitHub Actions.

## License

[MIT](LICENSE)
