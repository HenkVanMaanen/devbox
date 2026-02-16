# AI Agent Instructions

This file provides context and guidelines for AI coding assistants working on the Devbox codebase.

## Project Overview

Devbox is a browser-based development environment manager for Hetzner Cloud. It's a zero-backend SPA that provisions ephemeral cloud servers for AI-assisted coding.

**Key characteristics:**

- No backend server - browser talks directly to Hetzner API
- All state in localStorage
- Cloud-init for server provisioning
- Primary use case: ephemeral dev environments

## Quick Start

```bash
pnpm install   # Install dependencies
pnpm dev       # Development server with hot reload
pnpm check     # Run ALL checks (format, lint, types, spelling, tests, etc.)
pnpm build     # Production build
pnpm fix       # Auto-fix lint + format issues
```

## Architecture

Read these files first for context:

- `docs/architecture.md` - System design and module structure
- `docs/security.md` - Security model and controls
- `docs/adr/` - Architecture Decision Records for major decisions

### Tech Stack

- **Framework**: Svelte 5 with runes
- **Language**: TypeScript (strict mode)
- **Validation**: Zod (runtime validation for localStorage, API responses, config import)
- **Build tool**: Vite 6
- **CSS**: Tailwind CSS v4
- **Package manager**: pnpm
- **Runtime**: Node 24 (managed via mise)

### Module Structure

| Module                                | Purpose                         |
| ------------------------------------- | ------------------------------- |
| `src/App.svelte`                      | Root component                  |
| `src/main.ts`                         | Entry point                     |
| `src/lib/stores/`                     | Svelte runes-based state stores |
| `src/lib/api/hetzner.ts`              | Hetzner Cloud API client        |
| `src/lib/utils/cloudinit.ts`          | Cloud-init YAML generation      |
| `src/lib/utils/cloudinit-builders.ts` | Helper functions for cloud-init |
| `src/components/`                     | Reusable UI components          |
| `src/pages/`                          | Page components                 |

## Coding Standards

### Naming Conventions

- **Functions**: camelCase (`generateCloudInit`, `escapeHtml`)
- **Constants**: UPPER_SNAKE_CASE (`DEFAULT_GLOBAL_CONFIG`, `API_BASE`)
- **Files**: kebab-case (`cloudinit-builders.ts`)
- **Components**: PascalCase (`ServerCard.svelte`)
- **CSS classes**: kebab-case with Tailwind utilities

### File Organization

- Reusable components go in `src/components/`
- Page components go in `src/pages/`
- State stores go in `src/lib/stores/`
- Utility functions go in `src/lib/utils/`
- Tests go in `tests/` with `.test.mjs` extension
- Documentation goes in `docs/`

### Code Style

- TypeScript with strict mode
- Svelte 5 runes for reactivity (`$state`, `$derived`, `$effect`)
- Prefer `const` over `let`
- Always escape user content before rendering
- Code is auto-formatted with Prettier (120 char width, single quotes)
- ESLint enforces strictest TypeScript rules (`strictTypeChecked`)

## Linting & Tooling

The project uses comprehensive linting and code quality tools. All checks run via a single command:

```bash
pnpm check     # Run ALL checks (must pass before committing)
pnpm fix       # Auto-fix lint errors + format code
```

### Tools

| Tool             | Config                 | Purpose                                    |
| ---------------- | ---------------------- | ------------------------------------------ |
| **Prettier**     | `.prettierrc`          | Code formatting (single quotes, 120 width) |
| **ESLint**       | `eslint.config.js`     | Strict TypeScript + Svelte linting         |
| **Stylelint**    | `.stylelintrc.json`    | CSS linting                                |
| **svelte-check** | `tsconfig.json`        | Svelte + TypeScript type checking          |
| **cspell**       | `cspell.json`          | Spell checking                             |
| **knip**         | `knip.json`            | Dead code / unused dependency detection    |
| **jscpd**        | `.jscpd.json`          | Copy-paste detection                       |
| **Stryker**      | `stryker.config.json`  | Mutation testing (80% break threshold)     |
| **commitlint**   | `commitlint.config.js` | Conventional commit enforcement            |
| **lefthook**     | `lefthook.yml`         | Git hooks (pre-commit + commit-msg)        |

### Individual Check Commands

```bash
pnpm check:format    # Prettier format check
pnpm check:lint      # ESLint
pnpm check:css       # Stylelint
pnpm check:types     # svelte-check / TypeScript
pnpm check:spell     # cspell
pnpm check:knip      # Dead code detection
pnpm check:cpd       # Copy-paste detection
pnpm check:coverage  # Unit tests + coverage thresholds (90% lines, 85% branches, 100% functions)
pnpm test            # Unit tests only (no coverage enforcement)
pnpm test:mutation   # Stryker mutation testing (80% break threshold)
```

### Git Hooks (lefthook)

- **pre-commit**: Runs prettier, eslint, stylelint, typecheck, and cspell on staged files (in parallel)
- **commit-msg**: Enforces conventional commit format via commitlint

## Security Requirements

**Always follow these rules:**

1. **HTML escaping**: Svelte handles this automatically in templates, but be careful with `{@html}`

2. **Shell escaping**: Use `shellEscape()` for values embedded in cloud-init scripts

   ```typescript
   // Good
   `chezmoi init --apply "${shellEscape(repoUrl)}"`
   // Bad - command injection
   `chezmoi init --apply "${repoUrl}"`;
   ```

3. **Prototype pollution**: Check for `__proto__`, `constructor`, `prototype` when handling dynamic object paths

4. **No secrets in code**: All credentials come from user config, never hardcoded

## Testing Requirements

- **Run checks before committing**: `pnpm check`
- **Add tests for new functions**: Especially for cloud-init and storage utilities
- **Test file naming**: `modulename.test.mjs`
- **Use Node.js native test runner**: `import { describe, it } from 'node:test'`
- **Use `assert.strictEqual`** for null/undefined checks (not `assert.equal` which uses loose equality)
- **Coverage thresholds** (enforced by `pnpm check:coverage`): 90% lines, 85% branches, 100% functions
- **Mutation score** (enforced by `pnpm test:mutation`): 80% minimum

Example test:

```javascript
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { myFunction } from '../src/lib/utils/mymodule.ts';

describe('myFunction', () => {
  it('does something', () => {
    assert.strictEqual(myFunction('input'), 'expected');
  });
});
```

## Documentation Requirements

- **Update docs for behavior changes**: If you change how something works, update relevant docs
- **Add ADR for architectural changes**: New patterns, new dependencies, new integrations
- **Use Mermaid for diagrams**: Not ASCII art (see ADR-0013)

## Sensitive Areas

**Be careful when modifying:**

| Area        | Why                   | Files                                   |
| ----------- | --------------------- | --------------------------------------- |
| Security    | XSS, injection risks  | `cloudinit-builders.ts`                 |
| Storage     | User data persistence | `src/lib/utils/storage.ts`              |
| Cloud-init  | Server provisioning   | `cloudinit.ts`, `cloudinit-builders.ts` |
| CSP headers | Security policy       | `index.html`                            |

**Ask before:**

- Adding new npm dependencies
- Changing the CSP policy
- Modifying credential handling
- Changing localStorage keys (breaks existing user data)

## Common Pitfalls

### Cloud-init Size Limit

Hetzner limits user-data to 32KB. The UI shows a size indicator. Don't add verbose content to cloud-init generation.

### Browser-Only Environment

This is a browser SPA - no Node.js APIs available in the main code:

- No `fs`, `path`, `process`
- No `require()` - use ES imports
- Tests run in Node.js and mock browser APIs

### No Backend

Everything happens client-side:

- Can't make server-side API calls
- Can't store shared state
- Can't run background jobs
- CORS must be supported by external APIs

### Theme System

Themes use CSS variables via Tailwind. When adding new UI:

- Use Tailwind utility classes
- Test with both dark and light themes
- Ensure 7:1 contrast ratio (WCAG AAA)

### State Management

State uses Svelte 5 runes in store files:

```typescript
// In src/lib/stores/example.svelte.ts
let value = $state(initialValue);

export function setValue(newValue) {
  value = newValue;
}
```

## Commit Guidelines

Use conventional commit format (enforced by commitlint):

```
type: short description

Longer explanation if needed.
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, `perf`, `revert`, `build`

Examples:

- `feat: Add server rebuild functionality`
- `fix: Escape HTML in server names`
- `docs: Update architecture diagram`

## Release Process

When creating a release:

1. **Create and push tag** - `git tag -a vX.Y.Z -m "vX.Y.Z" && git push && git push origin vX.Y.Z`

GitHub Actions automatically:

- Extracts the version from the tag (e.g., `v1.0.3` → `1.0.3`)
- Generates CHANGELOG.md from conventional commits using git-cliff (configured in `cliff.toml`)
- Builds the project with the version injected
- Commits the updated CHANGELOG.md back to `main`
- Creates a GitHub release with release notes and a downloadable zip

**Note:** CHANGELOG.md is auto-generated by CI — do not edit it manually.

## Useful Commands

```bash
pnpm check                  # Run ALL checks (format, lint, types, spell, coverage, etc.)
pnpm fix                    # Auto-fix lint + format issues
pnpm dev                    # Dev server with watch
pnpm build                  # Production build
pnpm test                   # Unit tests only
pnpm check:coverage         # Unit tests + coverage thresholds
pnpm test:mutation          # Stryker mutation testing
git log --oneline -10       # Recent commits for context
```

## When in Doubt

1. Check existing code for patterns
2. Read the relevant ADR
3. Run `pnpm check`
4. Ask the user
