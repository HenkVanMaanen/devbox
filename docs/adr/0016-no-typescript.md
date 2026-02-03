# ADR 0016: Plain JavaScript (No TypeScript)

## Status

Accepted

## Context

Modern JavaScript projects often use TypeScript for:

- Static type checking
- Better IDE support
- Self-documenting code
- Catching errors at compile time

However, TypeScript adds complexity:

- Build step required
- Configuration overhead
- Learning curve for contributors
- Type definition maintenance

## Decision

Use plain JavaScript (ES Modules) without TypeScript.

## Consequences

### Positive

- **Simplicity**: No compilation step for development
- **Lower barrier**: Contributors don't need TypeScript knowledge
- **Faster iteration**: Edit and refresh, no build wait
- **Browser-native**: Code runs directly in browser (after bundling)
- **Less configuration**: No tsconfig.json, no type definitions
- **Smaller toolchain**: Fewer moving parts

### Negative

- **No type safety**: Runtime errors instead of compile-time
- **Less IDE support**: Autocomplete less accurate without types
- **Self-discipline required**: Must be careful with data shapes
- **No interface documentation**: Types don't document APIs

### Neutral

- **JSDoc available**: Can add type hints via JSDoc if needed later

## Mitigations

### Code Organization

- Keep modules small and focused
- Use consistent naming conventions
- Document expected shapes in comments where helpful

### Testing

- Comprehensive unit tests catch type-related bugs
- Test edge cases (null, undefined, wrong types)

### Runtime Validation

- Validate user input at boundaries
- Use defensive programming for external data

## When to Reconsider

Consider adding TypeScript if:

- Team grows significantly
- Codebase exceeds ~20k lines
- Complex data transformations become error-prone
- Multiple developers struggle with data shapes

## Alternatives Considered

### TypeScript

Full static typing:
- Better for large teams
- Better for complex codebases
- But adds build complexity
- Overkill for small SPA

Rejected because simplicity is more valuable at current scale.

### JSDoc Type Annotations

Type hints in comments:
- No build step
- IDE support via TypeScript language server
- But verbose, not enforced

Could be added incrementally if needed.

### Flow

Facebook's type checker:
- Similar to TypeScript
- But less popular, smaller ecosystem
- Additional tooling required

Rejected for same reasons as TypeScript plus smaller community.
