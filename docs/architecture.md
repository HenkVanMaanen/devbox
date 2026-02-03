# Architecture Overview

Devbox is a single-page application (SPA) that runs entirely in the browser with no backend server.

## System Architecture

```mermaid
flowchart TB
    subgraph Browser
        subgraph SPA["Devbox SPA"]
            State["State Manager"]
            Storage["Storage (localStorage)"]
            Themes["Themes System"]
            CloudInit["Cloud-Init Generator"]
            State & Storage & Themes & CloudInit --> App["App Orchestrator (app.js)"]
            App --> Hetzner["Hetzner API Client (hetzner.js)"]
        end
    end

    Hetzner -->|"HTTPS (CORS)"| API["Hetzner Cloud API"]
    API --> Server["Cloud Server"]

    subgraph Server
        Init["cloud-init (first boot)"]
        Init --> Caddy["Caddy (reverse proxy)"]
        Caddy --> ttyd["ttyd (terminal)"]
        Caddy -->|HTTPS| Internet((Internet))
    end
```

## Module Architecture

### Core Modules

| Module | Responsibility |
|--------|----------------|
| `app.js` | Main orchestrator: initialization, event wiring, API actions |
| `state.js` | Application state, routing, notifications, modals |
| `storage.js` | localStorage wrapper with typed accessors |
| `hetzner.js` | Hetzner Cloud API client (servers, SSH keys, images) |

### UI Modules

| Module | Responsibility |
|--------|----------------|
| `pages.js` | Page renderers (Profiles, Config, Credentials, ProfileEdit) |
| `pages/dashboard.js` | Dashboard page (server list, create form) |
| `pages/cloudinit.js` | Cloud-init preview page |
| `handlers.js` | UI event handlers for form interactions |
| `combobox.js` | Multi-select and single-select combobox components |
| `themes.js` | Theme definitions and CSS variable injection |
| `settings.js` | Settings field definitions and rendering |
| `ui.js` | Design system constants and HTML escaping |

### Generation Modules

| Module | Responsibility |
|--------|----------------|
| `cloudinit.js` | Cloud-init YAML generation engine |
| `cloudinit-builders.js` | Helper functions for cloud-init components |
| `packages.js` | APT and mise package definitions |
| `names.js` | Funny alliterative server name generator |
| `qrcode.js` | QR code generation wrapper |

## Data Flow

### Server Creation Flow

```mermaid
flowchart TD
    A["User clicks 'Create Server'"] --> B["handlers.js<br/>handleCreateServer"]
    B --> C["storage.js<br/>getEffectiveConfig"]
    C -->|"Merge global + profile"| D["cloudinit.js<br/>generateCloudInit"]
    D -->|"YAML generation"| E["hetzner.js<br/>createServer"]
    E -->|"API call with user-data"| F["state.js<br/>notify + re-render"]
```

### Configuration Inheritance

```mermaid
flowchart TD
    subgraph Global["Global Config"]
        G1["ssh.keys: [...]"]
        G2["git.name: 'User'"]
        G3["git.email: 'user@example.com'"]
        G4["packages.apt: ['git', 'curl']"]
        G5["shell.default: 'zsh'"]
    end

    Global -->|"deepMerge"| Profile

    subgraph Profile["Profile Overrides"]
        P1["packages.mise: ['node@lts']"]
        P2["services.vscode: true"]
    end

    Profile -->|"Result"| Effective

    subgraph Effective["Effective Config"]
        E1["ssh.keys: [...] (global)"]
        E2["git.name: 'User' (global)"]
        E3["git.email: '...' (global)"]
        E4["packages.apt: [...] (global)"]
        E5["packages.mise: [...] (profile)"]
        E6["shell.default: 'zsh' (global)"]
        E7["services.vscode: true (profile)"]
    end
```

## State Management

Devbox uses a simple centralized state pattern:

```javascript
// state.js
let state = {
  servers: [],
  sshKeys: [],
  profiles: [],
  globalConfig: {},
  activeProfile: null,
  notifications: [],
  modal: null,
};

export function setState(updates, callback) {
  Object.assign(state, updates);
  if (callback) callback(state);
}
```

State changes trigger re-renders via explicit callbacks, not automatic reactivity.

## Security Model

### Credential Handling

1. **Hetzner API token**: Stored in localStorage, sent only to Hetzner API
2. **Git credentials**: Embedded in cloud-init, sent to Hetzner as user-data
3. **SSH keys**: Fetched from Hetzner account, not stored locally
4. **Claude API key**: Embedded in cloud-init for server configuration

### XSS Prevention

All user input is escaped before rendering:

```javascript
// ui.js
export function escapeHtml(str) {
  return str.replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;',
    '"': '&quot;', "'": '&#39;'
  })[char]);
}
```

### Content Security Policy

The HTML includes CSP headers restricting script sources and API endpoints.

## Provisioned Server Architecture

When a server is created, cloud-init configures:

```mermaid
flowchart TB
    subgraph Server["Cloud Server"]
        subgraph Services["Services"]
            Caddy["Caddy<br/>(port 443)<br/>- Auto HTTPS<br/>- Subdomains"]
            ttyd["ttyd<br/>(port 7681)<br/>- WebSocket<br/>- Terminal"]
            DevServers["Dev Servers<br/>(port 3000+)"]
        end

        Caddy --> ttyd
        Caddy --> DevServers

        ttyd --> Mux["tmux/zellij<br/>(multiplexer)"]
        Mux --> Shell["User Shell<br/>(bash/zsh)"]
        Shell --> Claude["Claude Code<br/>(primary use)"]

        subgraph Runtimes["mise (runtimes)"]
            Node["node@lts"]
            Python["python@3.12"]
            Go["go@latest"]
            Other["..."]
        end
    end

    Internet((HTTPS)) --> Caddy
```

## Build Pipeline

```mermaid
flowchart LR
    subgraph Source
        JS["web/js/*.js"]
        CSS["web/src/*"]
    end

    Source --> Build["esbuild<br/>+ PostCSS<br/>+ Tailwind"]

    subgraph Dist["dist/"]
        Bundle["bundle.js"]
        Styles["style.css"]
    end

    Build --> Dist
    Dist -->|"GitHub Actions"| Pages["GitHub Pages"]
```
