# ADR 0021: Tailwind CSS v4 with Runtime Theming

## Status

Accepted

## Context

The application needs a styling solution that supports:

1. **Multiple themes**: 6 color themes (dark, light, nord, etc.)
2. **Runtime switching**: Users can change themes without page reload
3. **WCAG AAA compliance**: 7:1 contrast ratios (see ADR 0007)
4. **Consistent design**: Reusable design tokens across components
5. **Developer experience**: Fast iteration, good IDE support

The vanilla JS version used CSS variables with manual class utilities. With the Svelte migration, we needed to integrate styling with the component architecture.

## Decision

Use Tailwind CSS v4 with CSS custom properties for runtime theming.

## Consequences

### Positive

- **Utility-first**: Rapid UI development with composable classes
- **CSS variables**: Native theming without JavaScript runtime
- **Small bundle**: Only used utilities are included
- **IDE support**: Excellent autocomplete with Tailwind extension
- **v4 improvements**: Native CSS imports, better performance

### Negative

- **Class verbosity**: Long class strings in templates
- **Learning curve**: Utility naming conventions
- **Tailwind v4 is new**: Less documentation than v3

### Neutral

- **Different from traditional CSS**: Team needs to adopt utility-first mindset

## Implementation

### Setup

```typescript
// vite.config.ts
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [svelte(), tailwindcss()],
});
```

```css
/* src/app.css */
@import 'tailwindcss';
```

### Theme Architecture

CSS variables define the color system:

```css
/* Default theme (dark) */
:root {
  --color-background: #0a0a0a;
  --color-foreground: #fafafa;
  --color-card: #141414;
  --color-muted: #262626;
  --color-primary: #6366f1;
  --color-destructive: #ef4444;
  /* ... */
}
```

Tailwind v4's `@theme` directive maps variables to utilities:

```css
@theme {
  --color-background: var(--color-background);
  --color-foreground: var(--color-foreground);
  /* ... */
}
```

This enables classes like `bg-background`, `text-foreground`, `border-border`.

### Runtime Theme Switching

The theme store applies themes by updating CSS variables:

```typescript
// src/lib/stores/theme.svelte.ts
function applyTheme(theme: Theme) {
  const root = document.documentElement;
  Object.entries(theme.colors).forEach(([key, value]) => {
    root.style.setProperty(`--color-${key}`, value);
  });
}
```

No class changes needed - Tailwind utilities reference the variables.

### Available Themes

| Theme             | Description                           |
| ----------------- | ------------------------------------- |
| `dark`            | Default dark theme with indigo accent |
| `light`           | Light theme for bright environments   |
| `nord`            | Nord color palette                    |
| `dracula`         | Dracula color palette                 |
| `solarized-dark`  | Solarized dark variant                |
| `solarized-light` | Solarized light variant               |

All themes maintain WCAG AAA contrast ratios.

### Component Usage

```svelte
<button
  class="
  bg-primary text-primary-foreground
  hover:bg-primary-hover focus:ring-focus
  rounded-md
  px-4
  py-2 focus:ring-3
"
>
  Click me
</button>
```

### Semantic Color Names

Colors are named by purpose, not appearance:

| Variable           | Purpose                |
| ------------------ | ---------------------- |
| `background`       | Page background        |
| `foreground`       | Primary text           |
| `card`             | Card/panel backgrounds |
| `muted`            | Secondary backgrounds  |
| `muted-foreground` | Secondary text         |
| `border`           | Border color           |
| `primary`          | Primary actions        |
| `destructive`      | Dangerous actions      |
| `success`          | Success states         |
| `warning`          | Warning states         |

## Accessibility

### Focus Indicators

```css
:focus-visible {
  outline: 2px solid var(--color-focus);
  outline-offset: 2px;
}
```

### Reduced Motion

```css
@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}
```

## Alternatives Considered

### CSS Modules

Scoped CSS per component:

- Good encapsulation
- But requires more boilerplate
- No design system built-in
- Theme switching more complex

Rejected because Tailwind provides better DX for our use case.

### Styled Components / Emotion

CSS-in-JS solutions:

- Dynamic styling
- But runtime overhead
- Less common in Svelte ecosystem
- Bundle size concerns

Rejected due to runtime cost and Svelte's native scoped styles.

### Tailwind v3

Previous stable version:

- More documentation
- But v4 has better CSS variable support
- Native @theme directive
- Better Vite integration

Rejected in favor of v4's improvements for theming.

### Plain CSS with Variables

No framework, just CSS:

- Simplest approach
- But no utility classes
- More CSS to write
- Less consistent

Rejected because utility-first speeds up development significantly.
