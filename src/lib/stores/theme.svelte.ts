// Theme store using Svelte 5 runes

import { load, save } from '$lib/utils/storage';

export interface Theme {
  id: string;
  name: string;
  mode: 'dark' | 'light';
  colors: ThemeColors;
  terminal: TerminalColors;
}

export interface ThemeColors {
  background: string;
  foreground: string;
  card: string;
  cardForeground: string;
  muted: string;
  mutedForeground: string;
  mutedHover: string;
  border: string;
  input: string;
  primary: string;
  primaryHover: string;
  primaryForeground: string;
  focus: string;
  destructive: string;
  destructiveHover: string;
  destructiveForeground: string;
  success: string;
  successForeground: string;
  warning: string;
  warningForeground: string;
  placeholder: string;
}

export interface TerminalColors {
  black: string;
  red: string;
  green: string;
  yellow: string;
  blue: string;
  magenta: string;
  cyan: string;
  white: string;
  brightBlack: string;
  brightRed: string;
  brightGreen: string;
  brightYellow: string;
  brightBlue: string;
  brightMagenta: string;
  brightCyan: string;
  brightWhite: string;
}

export const THEMES: Theme[] = [
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
      placeholder: '#9ca3af',
    },
    terminal: {
      black: '#1a1a1a',
      red: '#f87171',
      green: '#4ade80',
      yellow: '#fbbf24',
      blue: '#60a5fa',
      magenta: '#c084fc',
      cyan: '#22d3ee',
      white: '#e5e5e5',
      brightBlack: '#525252',
      brightRed: '#fca5a5',
      brightGreen: '#86efac',
      brightYellow: '#fcd34d',
      brightBlue: '#93c5fd',
      brightMagenta: '#d8b4fe',
      brightCyan: '#67e8f9',
      brightWhite: '#ffffff',
    },
  },
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
      placeholder: '#6b7280',
    },
    terminal: {
      black: '#171717',
      red: '#dc2626',
      green: '#16a34a',
      yellow: '#ca8a04',
      blue: '#2563eb',
      magenta: '#9333ea',
      cyan: '#0891b2',
      white: '#e5e5e5',
      brightBlack: '#525252',
      brightRed: '#ef4444',
      brightGreen: '#22c55e',
      brightYellow: '#eab308',
      brightBlue: '#3b82f6',
      brightMagenta: '#a855f7',
      brightCyan: '#06b6d4',
      brightWhite: '#fafafa',
    },
  },
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
      placeholder: '#a5adb8',
    },
    terminal: {
      black: '#3b4252',
      red: '#bf616a',
      green: '#a3be8c',
      yellow: '#ebcb8b',
      blue: '#81a1c1',
      magenta: '#b48ead',
      cyan: '#88c0d0',
      white: '#e5e9f0',
      brightBlack: '#4c566a',
      brightRed: '#bf616a',
      brightGreen: '#a3be8c',
      brightYellow: '#ebcb8b',
      brightBlue: '#81a1c1',
      brightMagenta: '#b48ead',
      brightCyan: '#8fbcbb',
      brightWhite: '#eceff4',
    },
  },
  {
    id: 'dracula',
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
      placeholder: '#a3a6b8',
    },
    terminal: {
      black: '#21222c',
      red: '#ff5555',
      green: '#50fa7b',
      yellow: '#f1fa8c',
      blue: '#bd93f9',
      magenta: '#ff79c6',
      cyan: '#8be9fd',
      white: '#f8f8f2',
      brightBlack: '#6272a4',
      brightRed: '#ff6e6e',
      brightGreen: '#69ff94',
      brightYellow: '#ffffa5',
      brightBlue: '#d6acff',
      brightMagenta: '#ff92df',
      brightCyan: '#a4ffff',
      brightWhite: '#ffffff',
    },
  },
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
      placeholder: '#839496',
    },
    terminal: {
      black: '#073642',
      red: '#dc322f',
      green: '#859900',
      yellow: '#b58900',
      blue: '#268bd2',
      magenta: '#d33682',
      cyan: '#2aa198',
      white: '#eee8d5',
      brightBlack: '#586e75',
      brightRed: '#cb4b16',
      brightGreen: '#859900',
      brightYellow: '#b58900',
      brightBlue: '#268bd2',
      brightMagenta: '#6c71c4',
      brightCyan: '#2aa198',
      brightWhite: '#fdf6e3',
    },
  },
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
      placeholder: '#9da5b4',
    },
    terminal: {
      black: '#3f4451',
      red: '#e06c75',
      green: '#98c379',
      yellow: '#e5c07b',
      blue: '#61afef',
      magenta: '#c678dd',
      cyan: '#56b6c2',
      white: '#abb2bf',
      brightBlack: '#4f5666',
      brightRed: '#be5046',
      brightGreen: '#98c379',
      brightYellow: '#d19a66',
      brightBlue: '#61afef',
      brightMagenta: '#c678dd',
      brightCyan: '#56b6c2',
      brightWhite: '#e6e6e6',
    },
  },
];

function toKebabCase(str: string): string {
  return str.replace(/([A-Z])/g, '-$1').toLowerCase();
}

function applyThemeToDOM(theme: Theme): void {
  const root = document.documentElement;

  // Set CSS variables
  for (const [key, value] of Object.entries(theme.colors)) {
    const cssVar = `--color-${toKebabCase(key)}`;
    root.style.setProperty(cssVar, value);
  }

  // Update dark mode class
  if (theme.mode === 'dark') {
    root.classList.add('dark');
  } else {
    root.classList.remove('dark');
  }

  // Update meta theme-color
  let metaTheme = document.querySelector('meta[name="theme-color"]');
  if (!metaTheme) {
    metaTheme = document.createElement('meta');
    metaTheme.setAttribute('name', 'theme-color');
    document.head.appendChild(metaTheme);
  }
  metaTheme.setAttribute('content', theme.colors.background);
}

function getSystemPreference(): 'dark' | 'light' {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function createThemeStore() {
  const stored = load<string>('theme');
  const defaultTheme = stored ?? (getSystemPreference() === 'dark' ? 'default-dark' : 'default-light');
  let currentThemeId = $state(defaultTheme);

  // Apply theme on initialization
  if (typeof document !== 'undefined') {
    const theme = THEMES.find((t) => t.id === currentThemeId) ?? THEMES[0]!;
    applyThemeToDOM(theme);
  }

  return {
    get themeId() {
      return currentThemeId;
    },
    get theme() {
      return THEMES.find((t) => t.id === currentThemeId) ?? THEMES[0]!;
    },
    get themes() {
      return THEMES;
    },

    setTheme(themeId: string) {
      const theme = THEMES.find((t) => t.id === themeId);
      if (!theme) return;

      currentThemeId = themeId;
      save('theme', themeId);
      applyThemeToDOM(theme);
    },
  };
}

export const themeStore = createThemeStore();
