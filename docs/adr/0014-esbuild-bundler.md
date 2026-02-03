# ADR 0014: esbuild as Build Tool

## Status

Accepted

## Context

The project needs a build tool to:

- Bundle JavaScript modules for production
- Process Tailwind CSS
- Provide a development server with hot reload
- Generate hashed filenames for cache busting

Options considered:

1. **esbuild**: Fast Go-based bundler
2. **Vite**: Modern dev server with Rollup for production
3. **Webpack**: Established, highly configurable bundler
4. **Rollup**: ES module focused bundler
5. **Parcel**: Zero-config bundler

## Decision

Use esbuild for all build tasks.

## Consequences

### Positive

- **Extremely fast**: 10-100x faster than JavaScript-based bundlers
- **Simple configuration**: Minimal setup in `esbuild.js`
- **ES Modules native**: First-class support for ES modules
- **Small footprint**: Single dependency, no plugin ecosystem needed
- **Sufficient features**: Handles our needs (bundling, minification, sourcemaps)

### Negative

- **Less ecosystem**: Fewer plugins than Webpack
- **No HMR**: Hot Module Replacement not as sophisticated as Vite
- **Less transformation**: Limited compared to Babel for complex transforms

### Neutral

- **Good enough**: For a simple SPA, advanced features aren't needed

## Implementation

```javascript
// esbuild.js
import * as esbuild from 'esbuild';

await esbuild.build({
    entryPoints: ['web/js/app.js'],
    bundle: true,
    outdir: 'dist',
    format: 'esm',
    sourcemap: true,
    minify: process.env.NODE_ENV === 'production',
});
```

## Alternatives Considered

### Vite

Modern, fast development experience:
- Better HMR than esbuild
- But adds complexity (Rollup for prod, Vite for dev)
- More dependencies
- Overkill for our simple build needs

Rejected because esbuild is simpler and fast enough.

### Webpack

Industry standard:
- Most plugins and loaders
- But complex configuration
- Slower builds
- Heavy dependency tree

Rejected because we don't need its advanced features.

### No Bundler

Serve ES modules directly:
- Simplest approach
- But no minification or cache busting
- Many HTTP requests in production
- No CSS processing

Rejected because production optimization matters.
