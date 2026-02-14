# ADR 0025: Zod Runtime Validation

## Status

Accepted

## Context

The codebase had zero runtime validation. All data from localStorage and Hetzner API responses was trusted via `JSON.parse() as T` type assertions. TypeScript types only exist at compile time and are erased at runtime, so corrupted localStorage, malformed API responses, or invalid imported config files could cause the app to crash with unhelpful errors far from the source of the problem.

Specific risks:

- **Corrupted localStorage**: A browser extension or manual edit could produce invalid config shapes
- **API contract changes**: Hetzner API evolving could return unexpected fields or types
- **Config import**: Users importing JSON files had no validation beyond `JSON.parse` succeeding
- **Silent data loss**: Invalid data was silently accepted and could propagate through the app

## Decision

Add [Zod](https://zod.dev) for runtime validation, replacing TypeScript interfaces with Zod schemas that provide both compile-time types (via `z.infer<>`) and runtime validation.

Key design choices:

1. **Schemas as source of truth**: `src/lib/types.ts` defines Zod schemas from which TypeScript types are inferred. This eliminates type/validation drift.

2. **Graceful degradation**: `loadValidated()` uses `safeParse` and returns `null` on failure, matching the existing `load()` fallback behavior. The config store falls back to `DEFAULT_CONFIG` if validation fails.

3. **Config merging preserved**: The `deepMerge(DEFAULT_CONFIG, stored)` pattern continues to fill missing fields before Zod validates the complete result.

4. **API response validation**: Each Hetzner API function validates its response through a local `validate()` helper that wraps `ZodError` into `HetznerApiError` for consistent error handling.

5. **Import validation**: Config file import uses a top-level schema with `safeParse` and shows specific field errors to the user via toast.

6. **Form validation**: `validateSSHKey()` replaced with `sshPublicKeySchema` using Zod's `superRefine` for the same detailed error messages.

## Consequences

### Positive

- Runtime protection against corrupted or unexpected data
- Single source of truth for types (schema defines both runtime validation and TypeScript types)
- User-friendly error messages for config import failures
- API response validation catches contract drift early
- Form validation uses the same schema system as data validation

### Negative

- Adds a runtime dependency (~14KB minified+gzipped)
- Slight performance overhead for `safeParse`/`parse` calls on every localStorage load and API response
- Developers must update schemas when adding new fields (can't just add to an interface)

## Alternatives Considered

### Manual validation functions

Writing custom `isValidConfig()` functions. Rejected because this creates type/validation drift and is tedious to maintain for nested objects.

### io-ts / effect/Schema

Other TypeScript validation libraries. Rejected because Zod has the largest ecosystem, simplest API, and best TypeScript inference.

### JSON Schema (ajv)

Standard JSON Schema validation. Rejected because it doesn't integrate with TypeScript types and requires separate schema + type definitions.
