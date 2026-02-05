# ADR 0019: TypeScript with Strict Mode

## Status

Accepted (supersedes [ADR 0016](./0016-no-typescript.md))

## Context

The original Devbox application used plain JavaScript (see ADR 0016). The decision to avoid TypeScript was based on:

- Simplicity for a small codebase
- No build step for development
- Lower barrier for contributors

However, when migrating to Svelte 5, several factors changed:

1. **Build step required anyway**: Svelte requires compilation regardless
2. **Codebase grew**: More complex state management with profiles, credentials, servers
3. **Svelte 5 runes**: The new reactivity system benefits greatly from type inference
4. **Bug prevention**: Several bugs were caught during migration that types would have prevented

## Decision

Use TypeScript with the strictest possible configuration.

## Consequences

### Positive

- **Catch errors early**: Type errors found at compile time, not runtime
- **Better IDE support**: Autocomplete, refactoring, go-to-definition all work perfectly
- **Self-documenting**: Types serve as documentation for data shapes
- **Refactoring confidence**: Large changes are safer with type checking
- **Svelte integration**: Svelte 5 + TypeScript provides excellent type inference for runes

### Negative

- **Learning curve**: Contributors need TypeScript knowledge
- **Strict mode friction**: Some patterns require explicit type annotations
- **Build required**: Can't edit and run directly (but Svelte requires this anyway)

### Neutral

- **Migration cost**: One-time effort to add types (already done)

## Implementation

### Configuration

The strictest possible TypeScript configuration is used:

```json
{
  "compilerOptions": {
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictFunctionTypes": true,
    "strictBindCallApply": true,
    "strictPropertyInitialization": true,
    "noImplicitThis": true,
    "useUnknownInCatchVariables": true,
    "alwaysStrict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "exactOptionalPropertyTypes": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitOverride": true,
    "noPropertyAccessFromIndexSignature": true,
    "allowUnusedLabels": false,
    "allowUnreachableCode": false
  }
}
```

### Key Strict Options Explained

| Option | Purpose |
|--------|---------|
| `noUncheckedIndexedAccess` | Array/object access returns `T \| undefined` |
| `exactOptionalPropertyTypes` | `prop?: string` means `string \| undefined`, not `string \| undefined \| null` |
| `noPropertyAccessFromIndexSignature` | Forces bracket notation for dynamic keys |
| `useUnknownInCatchVariables` | Catch blocks get `unknown`, not `any` |

### Type Definitions

All data shapes are defined in `src/lib/types.ts`:

```typescript
export interface Profile {
  id: string;
  name: string;
  overrides: Record<string, unknown>;
}

export interface Server {
  id: number;
  name: string;
  status: 'running' | 'starting' | 'stopping' | 'off';
  // ...
}
```

### Svelte Component Types

Components use typed props via `$props()`:

```svelte
<script lang="ts">
  interface Props {
    variant?: 'primary' | 'secondary' | 'destructive' | 'ghost';
    size?: 'sm' | 'md' | 'lg';
    disabled?: boolean;
    children: Snippet;
  }

  let { variant = 'primary', size = 'md', ...rest }: Props = $props();
</script>
```

## Alternatives Considered

### Keep Plain JavaScript

Continue without types:
- Simpler setup
- But bugs kept appearing that types would catch
- IDE support was poor
- Refactoring was risky

Rejected because the codebase complexity warranted type safety.

### TypeScript with Relaxed Settings

Use TypeScript but with fewer strict options:
- Easier migration
- But defeats the purpose
- "Strict" catches real bugs
- Inconsistent type safety is confusing

Rejected because if we're using TypeScript, we should use it properly.

### JSDoc Type Annotations

Add types via comments:
- No build step for types
- But verbose and not enforced
- Doesn't integrate as well with Svelte
- Second-class citizen in the ecosystem

Rejected because Svelte's TypeScript integration is first-class.

## When ADR 0016 Was Right

The original decision to avoid TypeScript was correct at the time:

- Small vanilla JS codebase
- No build step
- Single developer
- Simple data structures

The migration to Svelte 5 changed all of these factors, making TypeScript the right choice now.
