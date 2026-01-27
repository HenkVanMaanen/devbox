# Devbox

A browser-based development environment manager for Hetzner Cloud. Configure, provision, and manage cloud dev servers with generated cloud-init scripts — all from a single-page app with no backend.

## Features

- **Hetzner Cloud integration** — list, create, rebuild, and delete servers via the Hetzner API directly from the browser
- **Cloud-init generator** — build cloud-init user-data scripts from configurable profiles (packages, SSH keys, dotfiles, shell config)
- **Profile management** — save and switch between multiple server configuration profiles
- **QR code export** — generate QR codes for cloud-init scripts
- **WCAG AAA accessible** — 7:1 contrast ratios, visible focus indicators, keyboard navigation, reduced-motion support
- **Theme support** — multiple dark and light themes with live switching
- **Zero backend** — runs entirely in the browser, credentials stored in localStorage

## Setup

```sh
pnpm install
pnpm run build
```

Open `web/index.html` in a browser.

## Development

Watch for CSS changes:

```sh
pnpm run dev
```

Run tests:

```sh
pnpm test
```

## Deployment

The project deploys to GitHub Pages automatically on push to `master` via GitHub Actions. The workflow builds Tailwind CSS, runs tests, and publishes the `web/` directory.

## License

[MIT](LICENSE)
