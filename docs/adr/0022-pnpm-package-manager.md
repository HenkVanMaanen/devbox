# ADR 0022: pnpm Package Manager

## Status

Accepted

## Context

The project needs a package manager for:

1. Installing dependencies
2. Running scripts
3. Ensuring reproducible builds
4. Managing the lock file

Node.js projects commonly use npm, yarn, or pnpm. Each has different tradeoffs for disk usage, speed, and strictness.

## Decision

Use pnpm as the package manager, pinned via `packageManager` field.

## Consequences

### Positive

- **Disk efficiency**: Hard links shared across projects save significant disk space
- **Strict by default**: Prevents accessing undeclared dependencies (phantom dependencies)
- **Fast installs**: Often faster than npm/yarn due to linking strategy
- **Reproducible**: Lock file format is deterministic
- **Built-in Node.js support**: Works with corepack for version management

### Negative

- **Less common**: Some developers unfamiliar with pnpm
- **Different commands**: Some flags differ from npm (`pnpm add` vs `npm install`)
- **Symlink complexity**: Some tools have issues with pnpm's node_modules structure

### Neutral

- **Corepack**: Node.js's corepack handles pnpm installation automatically

## Implementation

### Package.json Configuration

```json
{
  "packageManager": "pnpm@10.28.2"
}
```

This ensures everyone uses the same pnpm version.

### Installation

With corepack enabled:

```bash
corepack enable
pnpm install
```

Or install pnpm directly:

```bash
npm install -g pnpm
pnpm install
```

### Common Commands

| Task                 | Command                                |
| -------------------- | -------------------------------------- |
| Install dependencies | `pnpm install`                         |
| Add a dependency     | `pnpm add <package>`                   |
| Add a dev dependency | `pnpm add -D <package>`                |
| Run a script         | `pnpm run <script>` or `pnpm <script>` |
| Update dependencies  | `pnpm update`                          |

### CI/CD

GitHub Actions example:

```yaml
- uses: pnpm/action-setup@v2
- uses: actions/setup-node@v4
  with:
    node-version: '22'
    cache: 'pnpm'
- run: pnpm install --frozen-lockfile
```

### Mise Integration

The project uses mise for tool version management:

```toml
# .mise.toml
[tools]
node = "22"
```

Combined with `packageManager` in package.json, this ensures consistent environments.

## Alternatives Considered

### npm

Node.js built-in package manager:

- Universal availability
- But slower installs
- Less strict (phantom dependencies possible)
- Larger node_modules

Rejected because pnpm's strictness catches dependency issues.

### Yarn (Classic v1)

Original Yarn:

- Fast, reliable
- But maintenance mode
- node_modules same as npm
- Less active development

Rejected in favor of more modern alternatives.

### Yarn (Berry v2+)

Modern Yarn with Plug'n'Play:

- Zero-installs possible
- But PnP can break tooling
- Complex migration
- Less intuitive

Rejected because PnP compatibility issues outweigh benefits.

### Bun

Fast JavaScript runtime with built-in package manager:

- Extremely fast
- But less mature
- Not all npm packages compatible
- Different runtime behavior

Considered for future; rejected for now due to maturity concerns.

## Migration Notes

If moving from npm:

```bash
rm -rf node_modules package-lock.json
pnpm import  # Optional: import from package-lock.json
pnpm install
```

The `pnpm-lock.yaml` file should be committed to version control.
