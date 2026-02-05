# ADR 0017: Svelte 5 Framework Migration

## Status

Accepted

## Context

The original Devbox application was built with vanilla JavaScript and manual DOM manipulation. While this approach worked for the initial implementation, several pain points emerged:

- **Manual state synchronization**: Keeping the UI in sync with state required careful `setState()` calls and manual re-renders
- **Template string HTML**: Building complex UIs with template literals was error-prone and hard to maintain
- **No component isolation**: Styles and logic weren't encapsulated, leading to potential conflicts
- **Limited reactivity**: Changes required explicit subscription patterns

As the application grew to include profiles, credentials management, and server monitoring, the vanilla JS approach became increasingly difficult to maintain.

## Decision

Migrate to Svelte 5 with its new runes-based reactivity system.

Svelte 5 was chosen over other frameworks for these reasons:

1. **Compiled output**: Svelte compiles to vanilla JS with no runtime overhead
2. **Runes simplicity**: `$state`, `$derived`, and `$effect` are intuitive and explicit
3. **No virtual DOM**: Direct DOM updates align with our performance-first approach
4. **Small bundle size**: Critical for a tool that should load instantly
5. **TypeScript integration**: First-class support for strict TypeScript

## Consequences

### Positive

- **Cleaner code**: Components are self-contained with scoped styles
- **Reactive by default**: UI automatically updates when state changes
- **Better DX**: Hot module replacement, better error messages
- **Type safety**: Full TypeScript integration catches errors early
- **Smaller bundle**: ~30KB gzipped for the entire app

### Negative

- **Learning curve**: Contributors need Svelte knowledge
- **Build step required**: No more editing JS directly in browser
- **Runes are new**: Svelte 5 runes are different from Svelte 4 stores

### Neutral

- **Migration effort**: Required rewriting all UI code (one-time cost)

## Implementation

The application uses Svelte 5 runes throughout:

```svelte
<script lang="ts">
  // Reactive state
  let count = $state(0);

  // Derived values
  let doubled = $derived(count * 2);

  // Side effects
  $effect(() => {
    console.log('Count changed:', count);
  });
</script>

<button onclick={() => count++}>
  {count} (doubled: {doubled})
</button>
```

### Project Structure

```
src/
├── App.svelte           # Root component with routing
├── components/          # Reusable UI components
│   ├── ui/             # Generic components (Button, Modal, etc.)
│   └── Nav.svelte      # Navigation component
├── pages/              # Page components
├── lib/
│   ├── stores/         # Global reactive stores
│   ├── utils/          # Utility functions
│   └── types.ts        # TypeScript interfaces
└── app.css             # Global styles and theme variables
```

## Alternatives Considered

### React

Most popular framework:
- Large ecosystem and community
- But heavier runtime (~40KB)
- JSX less intuitive than Svelte templates
- Hooks have subtle complexity (dependency arrays)

Rejected due to bundle size and complexity.

### Vue 3

Similar reactive model:
- Composition API is powerful
- But larger runtime than Svelte
- Less seamless TypeScript integration
- Two-way binding can be confusing

Rejected because Svelte's compilation model is more aligned with our goals.

### Solid.js

Similar compilation approach:
- Very fast, small runtime
- But smaller community
- Less mature tooling
- JSX-based (personal preference against)

Rejected due to ecosystem maturity.

### Keep Vanilla JS

Continue without a framework:
- No dependencies
- But increasingly difficult to maintain
- Manual state management is error-prone
- No component encapsulation

Rejected because the codebase had grown beyond what vanilla JS handles well.
