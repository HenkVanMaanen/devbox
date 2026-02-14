# ADR 0018: Vite Build Tool

## Status

Accepted (supersedes [ADR 0014](./0014-esbuild-bundler.md))

## Context

The original Devbox application used esbuild for bundling (see ADR 0014). When migrating to Svelte 5, we needed to reconsider the build tooling because:

1. **Svelte compilation**: Svelte requires a compiler plugin that integrates with the bundler
2. **Development experience**: Svelte's HMR (Hot Module Replacement) requires specific dev server integration
3. **Tailwind CSS v4**: The new Tailwind version has a Vite-specific plugin

While esbuild is fast, its plugin ecosystem for Svelte is less mature than Vite's official support.

## Decision

Use Vite as the build tool and development server.

## Consequences

### Positive

- **Official Svelte support**: `@sveltejs/vite-plugin-svelte` is maintained by the Svelte team
- **Excellent HMR**: Component state preserved during development
- **Fast cold start**: Vite uses native ES modules in development
- **Tailwind v4 integration**: `@tailwindcss/vite` plugin works seamlessly
- **Production optimization**: Rollup-based builds with tree-shaking
- **Path aliases**: Easy configuration for `$lib`, `$components`, etc.

### Negative

- **More dependencies**: Vite + Rollup vs just esbuild
- **Slightly slower prod builds**: Rollup is slower than esbuild (but still fast)
- **Configuration file**: Requires `vite.config.ts`

### Neutral

- **Different from esbuild**: Team needs to learn Vite conventions

## Implementation

```typescript
// vite.config.ts
import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [svelte(), tailwindcss()],
  resolve: {
    alias: {
      $lib: resolve(__dirname, './src/lib'),
      $components: resolve(__dirname, './src/components'),
      $pages: resolve(__dirname, './src/pages'),
    },
  },
  build: {
    outDir: 'dist',
  },
});
```

### Scripts

```json
{
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  }
}
```

## Alternatives Considered

### Keep esbuild

Continue with esbuild + community Svelte plugin:

- Faster builds
- But less mature Svelte integration
- No official HMR support
- Would need separate dev server

Rejected because Svelte integration is critical.

### SvelteKit

Full-featured Svelte meta-framework:

- Built-in routing, SSR, adapters
- But adds complexity we don't need
- We're a simple SPA, not a multi-page app
- Would change deployment model

Rejected because it's overkill for our use case (see also ADR 0004 on hash-based routing).

### Rollup Directly

Use Rollup without Vite:

- More control over bundling
- But no dev server built-in
- More configuration required
- Vite provides better DX

Rejected because Vite wraps Rollup with better defaults.

## Migration Notes

The old vanilla JS codebase (`web/js/`) and esbuild configuration have been removed after the Svelte 5 migration was completed. The `old:*` scripts in package.json have also been removed.
