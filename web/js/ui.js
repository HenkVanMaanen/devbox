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

// ============================================================================
// CLIPBOARD
// ============================================================================

/**
 * Copy text to clipboard and show a toast notification
 * @param {string} text - The text to copy
 * @param {string} successMsg - Message to show on success (default: 'Copied to clipboard')
 * @returns {Promise<boolean>} - Whether the copy was successful
 */
export async function copyToClipboard(text, successMsg = 'Copied to clipboard') {
    // Import showToast dynamically to avoid circular dependency
    const { showToast } = await import('./state.js');

    try {
        await navigator.clipboard.writeText(text);
        showToast(successMsg, 'success');
        return true;
    } catch (err) {
        console.error('Failed to copy:', err);
        showToast('Failed to copy to clipboard', 'error');
        return false;
    }
}

/**
 * Render a copy button that copies the given value to clipboard
 * @param {string} value - The value to copy
 * @param {string} ariaLabel - Accessibility label for the button
 * @returns {string} - HTML string for the copy button
 */
export function renderCopyButton(value, ariaLabel = 'Copy to clipboard') {
    const escapedValue = escapeAttr(value);
    return `
        <button type="button"
            class="copy-btn"
            data-action="copyToClipboard"
            data-value="${escapedValue}"
            aria-label="${escapeAttr(ariaLabel)}"
            title="${escapeAttr(ariaLabel)}">
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
            </svg>
        </button>`;
}

// ============================================================================
// TOOLTIPS
// ============================================================================

/**
 * Render a help icon with tooltip
 * @param {string} helpText - The help text to display
 * @param {string} fieldId - ID for the tooltip (for accessibility)
 * @returns {string} - HTML string for the help icon and tooltip
 */
export function renderTooltip(helpText, fieldId) {
    const tooltipId = `tooltip-${fieldId}`;
    return `
        <span class="tooltip-trigger" tabindex="0" role="button"
            aria-describedby="${tooltipId}"
            aria-label="Help">
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span class="tooltip" id="${tooltipId}" role="tooltip">${escapeHtml(helpText)}</span>
        </span>`;
}

/**
 * Render a validation message container for a field
 * @param {string} fieldId - The field ID
 * @returns {string} - HTML string for the validation message container
 */
export function renderValidationMessage(fieldId) {
    return `<p id="${fieldId}-validation" class="validation-message hidden" role="alert" aria-live="polite"></p>`;
}
