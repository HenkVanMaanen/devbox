# ADR 0007: WCAG AAA Accessibility Compliance

## Status

Accepted

## Context

Web accessibility guidelines define three conformance levels:

- **WCAG A**: Minimum accessibility
- **WCAG AA**: Standard level, required by many regulations
- **WCAG AAA**: Highest level, strictest requirements

Most applications target AA compliance. AAA is considered aspirational by W3C because some criteria are difficult to meet for all content types.

## Decision

Target WCAG AAA compliance where applicable, particularly for visual design:

- **7:1 contrast ratio** for normal text (vs 4.5:1 for AA)
- **4.5:1 contrast ratio** for large text (vs 3:1 for AA)
- Visible focus indicators (3px ring with offset)
- Minimum 44x44px touch targets
- Reduced motion support
- Color not used as the only means of conveying information

## Consequences

### Positive

- **Maximum accessibility**: Usable by people with severe visual impairments
- **Better for everyone**: High contrast is easier to read in all conditions (bright sunlight, tired eyes)
- **Professional quality**: Demonstrates attention to detail and care for users
- **Future-proof**: Exceeds current legal requirements

### Negative

- **Design constraints**: Fewer color options meet 7:1 contrast
- **Potentially less "trendy"**: Cannot use low-contrast minimalist designs
- **More testing**: Must verify contrast ratios for all themes

### Neutral

- **Theme implementation**: All 7+ themes are designed with AAA contrast requirements

## Implementation

### Contrast Ratios

All themes in `themes.js` define colors that meet 7:1 contrast:

```javascript
{
  name: 'dark',
  colors: {
    text: '#e5e5e5',        // Light gray on dark background
    background: '#171717',   // Near-black
    // Calculated contrast ratio: 12.6:1
  }
}
```

### Focus Indicators

```css
:focus-visible {
  outline: 3px solid var(--focus-ring);
  outline-offset: 2px;
}
```

### Touch Targets

All interactive elements have minimum dimensions:

```css
button, a, input {
  min-height: 44px;
  min-width: 44px;
}
```

### Reduced Motion

```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}
```

## Alternatives Considered

### WCAG AA Only

Standard compliance level:
- More design flexibility
- But excludes users with more severe impairments
- Less differentiation from other apps

Rejected because accessibility is a core value, and the constraints are manageable.

### No Specific Target

Design by feel without formal compliance:
- Maximum creative freedom
- But inconsistent accessibility
- May exclude users unintentionally

Rejected because formal standards ensure consistent quality.
