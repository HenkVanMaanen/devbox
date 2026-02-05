# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) documenting significant technical decisions made in the Devbox project.

## What are ADRs?

ADRs capture important architectural decisions along with their context and consequences. They help:

- New contributors understand why things are the way they are
- Future maintainers make informed decisions about changes
- Track the evolution of the architecture over time

## ADR Index

| # | Title | Status | Summary |
|---|-------|--------|---------|
| [001](./0001-zero-backend-architecture.md) | Zero-Backend Architecture | Accepted | Browser makes API calls directly to Hetzner, no central server |
| [002](./0002-hetzner-cloud-provider.md) | Hetzner Cloud as Initial Provider | Accepted | Cheap, European, simple API; may add other providers later |
| [003](./0003-cloud-init-provisioning.md) | Cloud-Init for Server Provisioning | Accepted | Stateless provisioning that works without a backend |
| [004](./0004-hash-based-routing.md) | Hash-Based Client-Side Routing | Accepted | Works with GitHub Pages without server-side URL rewriting |
| [005](./0005-localstorage-persistence.md) | localStorage for Data Persistence | Accepted | Simple, sufficient for small config data |
| [006](./0006-two-level-config-hierarchy.md) | Two-Level Configuration Hierarchy | Accepted | Global defaults + profile overrides for flexibility |
| [007](./0007-wcag-aaa-accessibility.md) | WCAG AAA Accessibility Compliance | Accepted | 7:1 contrast ratios for maximum accessibility |
| [008](./0008-ttyd-terminal.md) | ttyd for Browser-Based Terminal | Accepted | Lightweight, works out of the box |
| [009](./0009-caddy-reverse-proxy.md) | Caddy as Reverse Proxy | Accepted | Automatic HTTPS, minimal configuration |
| [010](./0010-mise-runtime-manager.md) | mise for Runtime Version Management | Accepted | Fast, easy setup, single tool for all languages |
| [011](./0011-claude-code-primary-use-case.md) | Claude Code as Primary Use Case | Accepted | Optimized for AI-assisted coding workflow |
| [012](./0012-security-model.md) | Security Model and Threat Assumptions | Accepted | Trusted user, trusted machine, untrusted network |
| [013](./0013-mermaid-diagrams.md) | Mermaid for Documentation Diagrams | Accepted | Text-based diagrams with native GitHub rendering |
| [014](./0014-esbuild-bundler.md) | esbuild as Build Tool | Superseded | Fast, simple, sufficient for SPA needs |
| [015](./0015-native-test-runner.md) | Node.js Native Test Runner | Accepted | Zero dependencies, built into Node.js |
| [016](./0016-no-typescript.md) | Plain JavaScript (No TypeScript) | Superseded | Simplicity over type safety at current scale |
| [017](./0017-svelte5-framework.md) | Svelte 5 Framework | Accepted | Migration from vanilla JS to Svelte 5 with runes |
| [018](./0018-vite-build-tool.md) | Vite Build Tool | Accepted | Replaces esbuild for Svelte/Tailwind integration |
| [019](./0019-typescript-strict-mode.md) | TypeScript Strict Mode | Accepted | Full type safety with strictest settings |
| [020](./0020-svelte-runes-stores.md) | Reactive Stores with Runes | Accepted | Global state management using Svelte 5 runes |
| [021](./0021-tailwind-css-v4.md) | Tailwind CSS v4 | Accepted | Utility-first CSS with runtime theming |
| [022](./0022-pnpm-package-manager.md) | pnpm Package Manager | Accepted | Disk-efficient, strict package management |

## ADR Template

When adding new ADRs, use this template:

```markdown
# ADR XXXX: Title

## Status

Proposed | Accepted | Deprecated | Superseded

## Context

What is the issue that we're seeing that is motivating this decision?

## Decision

What is the change that we're proposing and/or doing?

## Consequences

What becomes easier or more difficult to do because of this change?

### Positive

- ...

### Negative

- ...

## Alternatives Considered

What other options were considered and why were they rejected?
```

## Naming Convention

ADRs are numbered sequentially: `0001-short-title.md`

Use lowercase with hyphens for file names.
