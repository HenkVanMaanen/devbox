// Design System - Tailwind CSS component classes and utility helpers

export const UI = {
    // Cards
    card: 'bg-card border border-border rounded-lg',
    cardHeader: 'px-6 py-4 border-b border-border',
    cardBody: 'px-6 py-4',
    cardFooter: 'px-6 py-4 border-t border-border',

    // Typography (WCAG AAA: using high-contrast colors)
    title: 'text-lg font-semibold',
    subtitle: 'text-sm text-muted-foreground',
    label: 'block text-sm font-medium mb-1.5',
    hint: 'text-sm text-muted-foreground mt-1',

    // Buttons (WCAG AAA: min 44px touch targets, high contrast focus)
    btn: 'inline-flex items-center justify-center min-h-[44px] min-w-[44px] px-4 py-2 text-base font-medium rounded-md transition-colors focus:outline-hidden focus:ring-3 focus:ring-focus focus:ring-offset-2 focus:ring-offset-background disabled:opacity-60 disabled:cursor-not-allowed',
    btnPrimary: 'bg-primary text-primary-foreground hover:bg-primary-hover',
    btnSecondary: 'bg-muted text-foreground hover:bg-muted-hover',
    btnDestructive: 'bg-destructive text-destructive-foreground hover:bg-destructive-hover',
    btnOutline: 'border-2 border-border bg-transparent hover:bg-muted',
    btnGhost: 'hover:bg-muted',
    btnSm: 'min-h-[44px] px-3 py-1.5 text-sm',

    // Form elements (WCAG AAA: visible focus, adequate sizing)
    input: 'w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md focus:outline-hidden focus:ring-3 focus:ring-focus focus:ring-offset-2 focus:ring-offset-background focus:border-primary placeholder:text-placeholder',
    select: 'w-full min-h-[44px] px-3 py-2 text-base bg-background border-2 border-border rounded-md focus:outline-hidden focus:ring-3 focus:ring-focus focus:ring-offset-2 focus:ring-offset-background focus:border-primary',
    textarea: 'w-full min-h-[88px] px-3 py-2 text-base bg-background border-2 border-border rounded-md focus:outline-hidden focus:ring-3 focus:ring-focus focus:ring-offset-2 focus:ring-offset-background focus:border-primary placeholder:text-placeholder resize-y',
    checkbox: 'w-5 h-5 rounded border-2 border-border text-primary focus:ring-3 focus:ring-focus bg-background cursor-pointer',

    // Layout
    stack: 'flex flex-col gap-4',
    row: 'flex items-center gap-3',
    grid2: 'grid grid-cols-1 sm:grid-cols-2 gap-4',
    grid3: 'grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3',

    // Status badges (WCAG AAA: sufficient contrast)
    badge: 'inline-flex items-center px-2.5 py-1 rounded-full text-sm font-semibold',
    badgeSuccess: 'bg-success/30 text-success',
    badgeWarning: 'bg-warning/30 text-warning',
    badgeMuted: 'bg-muted text-foreground',
};

// Combine CSS classes, filtering falsy values
export const cn = (...classes) => classes.filter(Boolean).join(' ');

// Escape HTML special characters to prevent XSS
export function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    const s = typeof str === 'string' ? str : String(str);
    return s
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Escape a value for safe use inside an HTML attribute (e.g., onclick)
export function escapeAttr(str) {
    if (str === null || str === undefined) return '';
    const s = typeof str === 'string' ? str : String(str);
    return s
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}
