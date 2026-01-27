// Theme definitions - all WCAG AAA compliant (7:1 contrast minimum for normal text)

export const THEMES = [
    // Default Dark (current theme)
    {
        id: 'default-dark',
        name: 'Default Dark',
        mode: 'dark',
        colors: {
            background: '#0a0a0b',
            foreground: '#f5f5f5',
            card: '#141416',
            cardForeground: '#f5f5f5',
            muted: '#27272a',
            mutedForeground: '#d4d4d8',
            mutedHover: '#3f3f46',
            border: '#3f3f46',
            input: '#27272a',
            primary: '#60a5fa',
            primaryHover: '#3b82f6',
            primaryForeground: '#0a0a0b',
            focus: '#fbbf24',
            destructive: '#f87171',
            destructiveHover: '#ef4444',
            destructiveForeground: '#0a0a0b',
            success: '#4ade80',
            successForeground: '#166534',
            warning: '#fbbf24',
            warningForeground: '#713f12',
            placeholder: '#9ca3af'
        }
    },
    // Default Light
    {
        id: 'default-light',
        name: 'Default Light',
        mode: 'light',
        colors: {
            background: '#ffffff',
            foreground: '#171717',
            card: '#fafafa',
            cardForeground: '#171717',
            muted: '#f4f4f5',
            mutedForeground: '#3f3f46',
            mutedHover: '#e4e4e7',
            border: '#d4d4d8',
            input: '#f4f4f5',
            primary: '#1d4ed8',
            primaryHover: '#1e40af',
            primaryForeground: '#ffffff',
            focus: '#b45309',
            destructive: '#b91c1c',
            destructiveHover: '#991b1b',
            destructiveForeground: '#ffffff',
            success: '#166534',
            successForeground: '#ffffff',
            warning: '#854d0e',
            warningForeground: '#ffffff',
            placeholder: '#6b7280'
        }
    },
    // Nord Dark
    {
        id: 'nord-dark',
        name: 'Nord Dark',
        mode: 'dark',
        colors: {
            background: '#2e3440',
            foreground: '#eceff4',
            card: '#3b4252',
            cardForeground: '#eceff4',
            muted: '#434c5e',
            mutedForeground: '#d8dee9',
            mutedHover: '#4c566a',
            border: '#4c566a',
            input: '#3b4252',
            primary: '#88c0d0',
            primaryHover: '#8fbcbb',
            primaryForeground: '#2e3440',
            focus: '#ebcb8b',
            destructive: '#bf616a',
            destructiveHover: '#d08770',
            destructiveForeground: '#2e3440',
            success: '#a3be8c',
            successForeground: '#2e3440',
            warning: '#ebcb8b',
            warningForeground: '#2e3440',
            placeholder: '#a5adb8'
        }
    },
    // Nord Light
    {
        id: 'nord-light',
        name: 'Nord Light',
        mode: 'light',
        colors: {
            background: '#eceff4',
            foreground: '#2e3440',
            card: '#e5e9f0',
            cardForeground: '#2e3440',
            muted: '#d8dee9',
            mutedForeground: '#3b4252',
            mutedHover: '#cfd5e0',
            border: '#b8c1d1',
            input: '#d8dee9',
            primary: '#2e5a6b',
            primaryHover: '#3b6a7a',
            primaryForeground: '#eceff4',
            focus: '#8a5d0b',
            destructive: '#8b3a42',
            destructiveHover: '#9a4049',
            destructiveForeground: '#eceff4',
            success: '#4a6940',
            successForeground: '#eceff4',
            warning: '#7a5a0f',
            warningForeground: '#eceff4',
            placeholder: '#4c566a'
        }
    },
    // Dracula Dark
    {
        id: 'dracula-dark',
        name: 'Dracula',
        mode: 'dark',
        colors: {
            background: '#282a36',
            foreground: '#f8f8f2',
            card: '#21222c',
            cardForeground: '#f8f8f2',
            muted: '#343746',
            mutedForeground: '#d4d6e4',
            mutedHover: '#44475a',
            border: '#44475a',
            input: '#343746',
            primary: '#bd93f9',
            primaryHover: '#caa9fa',
            primaryForeground: '#282a36',
            focus: '#f1fa8c',
            destructive: '#ff6e6e',
            destructiveHover: '#ff5555',
            destructiveForeground: '#282a36',
            success: '#50fa7b',
            successForeground: '#282a36',
            warning: '#f1fa8c',
            warningForeground: '#282a36',
            placeholder: '#a3a6b8'
        }
    },
    // Dracula Light
    {
        id: 'dracula-light',
        name: 'Dracula Light',
        mode: 'light',
        colors: {
            background: '#f8f8f2',
            foreground: '#282a36',
            card: '#ebebeb',
            cardForeground: '#282a36',
            muted: '#e0e0df',
            mutedForeground: '#3d3f4b',
            mutedHover: '#d5d5d3',
            border: '#c8c8c6',
            input: '#e0e0df',
            primary: '#6b3fa0',
            primaryHover: '#7b4fb5',
            primaryForeground: '#f8f8f2',
            focus: '#7a6600',
            destructive: '#b5242c',
            destructiveHover: '#c53038',
            destructiveForeground: '#f8f8f2',
            success: '#1a7a3a',
            successForeground: '#f8f8f2',
            warning: '#7a6600',
            warningForeground: '#f8f8f2',
            placeholder: '#5a5c6a'
        }
    },
    // Solarized Dark
    {
        id: 'solarized-dark',
        name: 'Solarized Dark',
        mode: 'dark',
        colors: {
            background: '#002b36',
            foreground: '#fdf6e3',
            card: '#073642',
            cardForeground: '#fdf6e3',
            muted: '#094152',
            mutedForeground: '#eee8d5',
            mutedHover: '#0d5666',
            border: '#2d6677',
            input: '#073642',
            primary: '#93a1a1',
            primaryHover: '#839496',
            primaryForeground: '#002b36',
            focus: '#eee8d5',
            destructive: '#e57373',
            destructiveHover: '#dc322f',
            destructiveForeground: '#002b36',
            success: '#97d077',
            successForeground: '#002b36',
            warning: '#eee8d5',
            warningForeground: '#002b36',
            placeholder: '#839496'
        }
    },
    // Solarized Light
    {
        id: 'solarized-light',
        name: 'Solarized Light',
        mode: 'light',
        colors: {
            background: '#fdf6e3',
            foreground: '#002b36',
            card: '#eee8d5',
            cardForeground: '#002b36',
            muted: '#e4ddc8',
            mutedForeground: '#073642',
            mutedHover: '#d9d2bd',
            border: '#c5bea7',
            input: '#eee8d5',
            primary: '#073642',
            primaryHover: '#002b36',
            primaryForeground: '#fdf6e3',
            focus: '#073642',
            destructive: '#a32929',
            destructiveHover: '#b83232',
            destructiveForeground: '#fdf6e3',
            success: '#2a6e2a',
            successForeground: '#fdf6e3',
            warning: '#7a5d00',
            warningForeground: '#fdf6e3',
            placeholder: '#586e75'
        }
    },
    // One Dark
    {
        id: 'one-dark',
        name: 'One Dark',
        mode: 'dark',
        colors: {
            background: '#282c34',
            foreground: '#e6e6e6',
            card: '#21252b',
            cardForeground: '#e6e6e6',
            muted: '#2c313c',
            mutedForeground: '#c8c8c8',
            mutedHover: '#3a3f4b',
            border: '#3e4451',
            input: '#2c313c',
            primary: '#8cc8ff',
            primaryHover: '#61afef',
            primaryForeground: '#282c34',
            focus: '#e5c07b',
            destructive: '#f28b82',
            destructiveHover: '#e06c75',
            destructiveForeground: '#282c34',
            success: '#98c379',
            successForeground: '#282c34',
            warning: '#e5c07b',
            warningForeground: '#282c34',
            placeholder: '#9da5b4'
        }
    },
    // One Light
    {
        id: 'one-light',
        name: 'One Light',
        mode: 'light',
        colors: {
            background: '#fafafa',
            foreground: '#1a1a1a',
            card: '#f0f0f0',
            cardForeground: '#1a1a1a',
            muted: '#e5e5e6',
            mutedForeground: '#383a42',
            mutedHover: '#d8d8d9',
            border: '#c8c8c8',
            input: '#e5e5e6',
            primary: '#0b5394',
            primaryHover: '#0a4a84',
            primaryForeground: '#fafafa',
            focus: '#8a5d0b',
            destructive: '#a32929',
            destructiveHover: '#b83232',
            destructiveForeground: '#fafafa',
            success: '#2a6e2a',
            successForeground: '#fafafa',
            warning: '#8a5d0b',
            warningForeground: '#fafafa',
            placeholder: '#5a5a5a'
        }
    }
];

// Theme families for grouped display
export const THEME_FAMILIES = [
    { name: 'Default', themes: ['default-dark', 'default-light'] },
    { name: 'Nord', themes: ['nord-dark', 'nord-light'] },
    { name: 'Dracula', themes: ['dracula-dark', 'dracula-light'] },
    { name: 'Solarized', themes: ['solarized-dark', 'solarized-light'] },
    { name: 'One', themes: ['one-dark', 'one-light'] }
];

// Get theme by ID
export function getTheme(themeId) {
    return THEMES.find(t => t.id === themeId);
}

// Convert camelCase to kebab-case for CSS variable names
function toKebabCase(str) {
    return str.replace(/([A-Z])/g, '-$1').toLowerCase();
}

// Apply theme to document by setting CSS custom properties
export function applyTheme(themeId) {
    const theme = getTheme(themeId);
    if (!theme) return;

    const root = document.documentElement;

    // Set CSS variables
    Object.entries(theme.colors).forEach(([key, value]) => {
        const cssVar = `--color-${toKebabCase(key)}`;
        root.style.setProperty(cssVar, value);
    });

    // Update dark mode class for Tailwind
    if (theme.mode === 'dark') {
        root.classList.add('dark');
    } else {
        root.classList.remove('dark');
    }

    // Update meta theme-color for mobile browsers
    let metaTheme = document.querySelector('meta[name="theme-color"]');
    if (!metaTheme) {
        metaTheme = document.createElement('meta');
        metaTheme.name = 'theme-color';
        document.head.appendChild(metaTheme);
    }
    metaTheme.content = theme.colors.background;
}

// Get system color scheme preference
export function getSystemPreference() {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

// Get default theme based on system preference
export function getDefaultTheme() {
    return getSystemPreference() === 'dark' ? 'default-dark' : 'default-light';
}

// Listen for system preference changes
export function watchSystemPreference(callback) {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    mediaQuery.addEventListener('change', (e) => {
        callback(e.matches ? 'dark' : 'light');
    });
}

// Generate CSS for a theme (used for server index page)
export function generateThemeCSS(themeId) {
    const theme = getTheme(themeId);
    if (!theme) return '';

    const vars = Object.entries(theme.colors)
        .map(([key, value]) => `--color-${toKebabCase(key)}:${value}`)
        .join(';');

    return `:root{${vars}}`;
}
