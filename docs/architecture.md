# Architecture Overview

Devbox is a single-page application (SPA) that runs entirely in the browser with no backend server.

## System Architecture

```mermaid
flowchart TB
    subgraph Browser
        subgraph SPA["Devbox SPA (Svelte 5)"]
            Stores["Svelte Stores"]
            Storage["Storage (localStorage)"]
            Themes["Themes System"]
            CloudInit["Cloud-Init Generator"]
            Stores & Storage & Themes & CloudInit --> App["App.svelte"]
            App --> Hetzner["Hetzner API Client"]
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

## Tech Stack

- **Framework**: Svelte 5 with runes (`$state`, `$derived`, `$effect`)
- **Language**: TypeScript (strict mode)
- **Build Tool**: Vite 6
- **CSS**: Tailwind CSS v4
- **Package Manager**: pnpm

## Module Architecture

### Core Modules

| Module                       | Responsibility                             |
| ---------------------------- | ------------------------------------------ |
| `src/App.svelte`             | Root component, routing, layout            |
| `src/main.ts`                | Entry point, mounts Svelte app             |
| `src/lib/stores/*.svelte.ts` | Reactive state stores using Svelte 5 runes |
| `src/lib/api/hetzner.ts`     | Hetzner Cloud API client                   |
| `src/lib/utils/storage.ts`   | localStorage wrapper                       |

### UI Components

| Module                       | Responsibility                                         |
| ---------------------------- | ------------------------------------------------------ |
| `src/pages/*.svelte`         | Page components (Dashboard, Config, Credentials, etc.) |
| `src/components/*.svelte`    | Reusable UI components (Nav, ServerCard, etc.)         |
| `src/components/ui/*.svelte` | Base UI components (Button, Card, Input, Modal)        |

### Generation Modules

| Module                                | Responsibility                             |
| ------------------------------------- | ------------------------------------------ |
| `src/lib/utils/cloudinit.ts`          | Cloud-init YAML generation engine          |
| `src/lib/utils/cloudinit-builders.ts` | Helper functions for cloud-init components |
| `src/lib/utils/names.ts`              | Funny alliterative server name generator   |
| `src/lib/utils/qrcode.ts`             | QR code generation                         |

## Data Flow

### Server Creation Flow

```mermaid
flowchart TD
    A["User clicks 'Create Server'"] --> B["Dashboard.svelte"]
    B --> C["config.svelte.ts<br/>getEffectiveConfig"]
    C -->|"Merge global + profile"| D["cloudinit.ts<br/>generateCloudInit"]
    D -->|"YAML generation"| E["hetzner.ts<br/>createServer"]
    E -->|"API call with user-data"| F["toast.svelte.ts<br/>notify"]
```

### Configuration Inheritance

```mermaid
flowchart TD
    subgraph Global["Global Config"]
        G1["ssh.keys: [...]"]
        G2["chezmoi.repoUrl: '...'"]
        G3["git.credential: {...}"]
        G4["services.dnsService: 'sslip.io'"]
        G5["hetzner.serverType: 'cx22'"]
    end

    Global -->|"deepMerge"| Profile

    subgraph Profile["Profile Overrides"]
        P1["hetzner.serverType: 'cx32'"]
        P2["hetzner.location: 'nbg1'"]
    end

    Profile -->|"Result"| Effective

    subgraph Effective["Effective Config"]
        E1["ssh.keys: [...] (global)"]
        E2["chezmoi.repoUrl: '...' (global)"]
        E3["git.credential: {...} (global)"]
        E4["services.dnsService: '...' (global)"]
        E5["hetzner.serverType: 'cx32' (profile)"]
        E6["hetzner.location: 'nbg1' (profile)"]
    end
```

## State Management

Devbox uses Svelte 5 runes for reactive state:

```typescript
// src/lib/stores/servers.svelte.ts
let servers = $state<Server[]>([]);

export function setServers(newServers: Server[]) {
  servers = newServers;
}

export function getServers() {
  return servers;
}
```

State changes automatically trigger re-renders via Svelte's reactivity system.

## Security Model

### Credential Handling

1. **Hetzner API token**: Stored in localStorage, sent only to Hetzner API
2. **Git credential**: Bootstrap credential embedded in cloud-init for cloning chezmoi repo
3. **SSH keys**: Registered with Hetzner, added to server's authorized_keys
4. **Age key**: Written to server for chezmoi secret decryption

### XSS Prevention

Svelte automatically escapes content in templates. Use `{@html}` carefully:

```svelte
<!-- Safe - auto-escaped -->
<div>{userInput}</div>

<!-- Dangerous - only use with trusted content -->
{@html trustedHtml}
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
            ttyd["ttyd<br/>(port 65534)<br/>- WebSocket<br/>- Terminal"]
            DevServers["Dev Servers<br/>(port 3000+)"]
        end

        Caddy --> ttyd
        Caddy --> DevServers

        ttyd --> Shell["User Shell<br/>(bash)"]
        Shell --> Chezmoi["chezmoi<br/>(dotfiles)"]
        Shell --> Claude["Claude Code<br/>(primary use)"]
    end

    Internet((HTTPS)) --> Caddy
```

## Build Pipeline

```mermaid
flowchart LR
    subgraph Source
        Svelte["src/**/*.svelte"]
        TS["src/**/*.ts"]
        CSS["src/app.css"]
    end

    Source --> Build["Vite<br/>+ Svelte<br/>+ Tailwind"]

    subgraph Dist["dist/"]
        Bundle["index-*.js"]
        Styles["index-*.css"]
        HTML["index.html"]
    end

    Build --> Dist
    Dist -->|"GitHub Actions"| Pages["GitHub Pages"]
```
