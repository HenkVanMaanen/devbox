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
npm install    # Install dependencies
npm run dev    # Development server with hot reload
npm test       # Run all tests (do this before committing)
npm run build  # Production build
```

## Architecture

Read these files first for context:
- `docs/architecture.md` - System design and module structure
- `docs/security.md` - Security model and controls
- `docs/adr/` - Architecture Decision Records for major decisions

### Module Structure

| Module | Purpose |
|--------|---------|
| `web/js/app.js` | Main orchestrator - start here |
| `web/js/state.js` | Application state and routing |
| `web/js/storage.js` | localStorage persistence |
| `web/js/hetzner.js` | Hetzner Cloud API client |
| `web/js/cloudinit.js` | Cloud-init YAML generation |
| `web/js/cloudinit-builders.js` | Helper functions for cloud-init |
| `web/js/handlers.js` | UI event handlers |
| `web/js/themes.js` | Theme definitions and application |
| `web/js/settings.js` | Settings field definitions |

## Coding Standards

### Naming Conventions

- **Functions**: camelCase (`generateCloudInit`, `escapeHtml`)
- **Constants**: UPPER_SNAKE_CASE (`DEFAULT_GLOBAL_CONFIG`, `API_BASE`)
- **Files**: kebab-case (`cloudinit-builders.js`)
- **CSS classes**: kebab-case with Tailwind utilities

### File Organization

- New UI modules go in `web/js/`
- New page renderers go in `web/js/pages/`
- Tests go in `tests/` with `.test.mjs` extension
- Documentation goes in `docs/`

### Code Style

- ES Modules (import/export)
- No TypeScript - plain JavaScript
- Prefer `const` over `let`
- Use template literals for HTML generation
- Always escape user content before rendering

## Security Requirements

**Always follow these rules:**

1. **HTML escaping**: Use `escapeHtml()` or `escapeAttr()` for all user-controlled content
   ```javascript
   // Good
   `<div>${escapeHtml(userInput)}</div>`

   // Bad - XSS vulnerability
   `<div>${userInput}</div>`
   ```

2. **Shell escaping**: Use `shellEscape()` for values embedded in cloud-init scripts
   ```javascript
   // Good
   `echo ${shellEscape(userName)}`

   // Bad - command injection
   `echo ${userName}`
   ```

3. **Prototype pollution**: Check for `__proto__`, `constructor`, `prototype` when handling dynamic object paths

4. **No secrets in code**: All credentials come from user config, never hardcoded

## Testing Requirements

- **Run tests before committing**: `npm test`
- **Add tests for new functions**: Especially for `cloudinit.js`, `storage.js`, `handlers.js`
- **Test file naming**: `modulename.test.mjs`
- **Use Node.js native test runner**: `import { describe, it } from 'node:test'`

Example test:
```javascript
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { myFunction } from '../web/js/mymodule.js';

describe('myFunction', () => {
    it('does something', () => {
        assert.equal(myFunction('input'), 'expected');
    });
});
```

## Documentation Requirements

- **Update docs for behavior changes**: If you change how something works, update relevant docs
- **Add ADR for architectural changes**: New patterns, new dependencies, new integrations
- **Use Mermaid for diagrams**: Not ASCII art (see ADR-0013)

## Sensitive Areas

**Be careful when modifying:**

| Area | Why | Files |
|------|-----|-------|
| Security | XSS, injection risks | `ui.js`, `cloudinit-builders.js` |
| Storage | User data persistence | `storage.js` |
| Cloud-init | Server provisioning | `cloudinit.js`, `cloudinit-builders.js` |
| CSP headers | Security policy | `web/index.html` |

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

Themes inject CSS variables at runtime. When adding new UI:
- Use CSS variables from `themes.js` (e.g., `var(--primary)`)
- Test with both dark and light themes
- Ensure 7:1 contrast ratio (WCAG AAA)

### State Management

State is simple - no reactive framework:
```javascript
setState({ key: value }); // Updates state and triggers render
```

Don't mutate state directly. Always use `setState()`.

## Commit Guidelines

Use conventional commit format:
```
type: short description

Longer explanation if needed.
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

Examples:
- `feat: Add server rebuild functionality`
- `fix: Escape HTML in server names`
- `docs: Update architecture diagram`

## Release Process

When creating a release:

1. **Update CHANGELOG.md** - Add entry for the new version
2. **Commit changes** - `git commit -m "chore: release vX.Y.Z"`
3. **Create and push tag** - `git tag -a vX.Y.Z -m "vX.Y.Z" && git push && git push origin vX.Y.Z`

GitHub Actions automatically:
- Extracts the version from the tag (e.g., `v1.0.3` → `1.0.3`)
- Updates package.json with that version
- Builds the project with the version injected
- Creates a GitHub release with a downloadable zip

**Changelog format** (Keep a Changelog):
```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- New features

### Changed
- Changes to existing functionality

### Fixed
- Bug fixes

### Security
- Security fixes
```

## Useful Commands

```bash
npm test                    # Run all tests
npm run dev                 # Dev server with watch
npm run build              # Production build
git log --oneline -10      # Recent commits for context
```

## When in Doubt

1. Check existing code for patterns
2. Read the relevant ADR
3. Run the tests
4. Ask the user
