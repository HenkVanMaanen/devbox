# ADR 0020: Reactive Stores with Svelte 5 Runes

## Status

Accepted

## Context

The application needs global state management for:

- **Configuration**: Global settings that affect server provisioning
- **Profiles**: Named configuration overrides
- **Servers**: List of created servers and their status
- **Credentials**: API tokens, SSH keys, Claude credentials
- **Theme**: Current UI theme selection
- **Toast**: Notification messages

In the vanilla JS version, state was managed with a simple `setState()` function and manual re-renders. Svelte 5 introduces runes (`$state`, `$derived`, `$effect`) which provide fine-grained reactivity.

## Decision

Use Svelte 5 runes to create reactive stores as plain objects with getter/setter patterns.

## Consequences

### Positive

- **Fine-grained reactivity**: Only affected components re-render
- **Type safety**: Full TypeScript support with inference
- **Explicit dependencies**: `$derived` makes dependencies clear
- **No boilerplate**: Simpler than Svelte 4 stores or Redux
- **Debuggable**: State is inspectable in devtools

### Negative

- **Svelte 5 specific**: Can't use with other frameworks
- **Learning curve**: Runes are new even to Svelte developers
- **Proxy limitations**: Must use `$state` correctly for reactivity

### Neutral

- **Different from Svelte 4**: Existing Svelte knowledge needs updating

## Implementation

### Store Pattern

Each store follows this pattern:

```typescript
// src/lib/stores/example.svelte.ts
import { load, save } from '$lib/utils/storage';

function createExampleStore() {
  // Reactive state
  let items = $state<Item[]>(load('items') ?? []);

  return {
    // Getters for reading state
    get items() {
      return items;
    },
    get count() {
      return items.length;
    },

    // Methods for mutations
    add(item: Item) {
      items.push(item);
      this.save();
    },

    remove(id: string) {
      items = items.filter(i => i.id !== id);
      this.save();
    },

    // Persistence
    save() {
      save('items', items);
    }
  };
}

export const exampleStore = createExampleStore();
```

### Store Files

| Store | Purpose | Persisted |
|-------|---------|-----------|
| `config.svelte.ts` | Global configuration settings | Yes |
| `profiles.svelte.ts` | Named config overrides | Yes |
| `servers.svelte.ts` | Server list and status | No (fetched from API) |
| `credentials.svelte.ts` | API tokens, SSH keys | Yes |
| `theme.svelte.ts` | Current theme selection | Yes |
| `toast.svelte.ts` | Notification queue | No |

### Usage in Components

```svelte
<script lang="ts">
  import { configStore } from '$lib/stores/config.svelte';
  import { profilesStore } from '$lib/stores/profiles.svelte';

  // Reading state (reactive)
  let serverType = $derived(configStore.get('hetzner.serverType'));

  // Or access directly
  let profiles = $derived(profilesStore.profileList);
</script>

<select value={serverType} onchange={(e) => configStore.set('hetzner.serverType', e.target.value)}>
  ...
</select>
```

### Derived State

Complex derived state uses `$derived`:

```typescript
// In component
let mergedConfig = $derived(
  profilesStore.getConfigForProfile(selectedProfileId)
);

// Or in store
get profileList() {
  return Object.values(profiles);  // Reactive because profiles is $state
}
```

### Effects for Side Effects

```svelte
<script lang="ts">
  import { themeStore } from '$lib/stores/theme.svelte';

  // Apply theme CSS variables when theme changes
  $effect(() => {
    const theme = themeStore.current;
    Object.entries(theme.colors).forEach(([key, value]) => {
      document.documentElement.style.setProperty(`--color-${key}`, value);
    });
  });
</script>
```

## Key Patterns

### 1. JSON Cloning for Proxy Safety

Svelte 5's `$state` creates proxies. When storing to localStorage or passing to external code, clone first:

```typescript
import { clone } from '$lib/utils/storage';

// clone() uses JSON.parse(JSON.stringify()) for proxy safety
save('config', clone(config));
```

### 2. Direct Property Access for Reactivity

For `$derived` to track dependencies, access `$state` directly:

```typescript
// Good - tracks profiles reactivity
let profile = $derived(profilesStore.profiles[profileId]);

// May not track - method call obscures access
let profile = $derived(profilesStore.get(profileId));
```

### 3. Getters for Computed Values

Use getters for values that should be computed on access:

```typescript
return {
  get profileList() {
    return Object.values(profiles);  // Fresh array each time
  }
};
```

## Alternatives Considered

### Svelte 4 Stores

Traditional `writable`/`readable` stores:
- More familiar to existing Svelte devs
- But being phased out in Svelte 5
- Less intuitive than runes
- Require `$` prefix everywhere

Rejected because runes are the future of Svelte.

### External State Library (Zustand, Jotai)

Framework-agnostic state management:
- Works across frameworks
- But adds dependencies
- Doesn't integrate as well with Svelte
- Overkill for our needs

Rejected because Svelte's built-in solution is sufficient.

### Context API

Svelte's context for dependency injection:
- Good for component trees
- But awkward for global state
- Requires provider components
- Less ergonomic than module-level stores

Rejected for global state; may use for component-scoped state later.

### Redux Pattern

Actions, reducers, immutable updates:
- Predictable state changes
- But verbose boilerplate
- Overkill for small app
- Doesn't leverage Svelte's reactivity

Rejected because Svelte's reactivity handles this more elegantly.
