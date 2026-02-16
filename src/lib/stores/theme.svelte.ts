// Theme store using Svelte 5 runes

import { z } from 'zod';

import { loadValidated, save } from '$lib/utils/storage';

export interface TerminalColors {
  [key: string]: string;
  black: string;
  blue: string;
  brightBlack: string;
  brightBlue: string;
  brightCyan: string;
  brightGreen: string;
  brightMagenta: string;
  brightRed: string;
  brightWhite: string;
  brightYellow: string;
  cyan: string;
  green: string;
  magenta: string;
  red: string;
  white: string;
  yellow: string;
}

export interface Theme {
  colors: ThemeColors;
  id: string;
  mode: 'dark' | 'light';
  name: string;
  terminal: TerminalColors;
}

export interface ThemeColors {
  [key: string]: string;
  background: string;
  border: string;
  card: string;
  cardForeground: string;
  destructive: string;
  destructiveForeground: string;
  destructiveHover: string;
  focus: string;
  foreground: string;
  input: string;
  muted: string;
  mutedForeground: string;
  mutedHover: string;
  placeholder: string;
  primary: string;
  primaryForeground: string;
  primaryHover: string;
  success: string;
  successForeground: string;
  warning: string;
  warningForeground: string;
}

// Stryker disable all: Pure data - theme color hex values are not testable logic
export const THEMES: Theme[] = [
  {
    colors: {
      background: '#0a0a0b',
      border: '#3f3f46',
      card: '#141416',
      cardForeground: '#f5f5f5',
      destructive: '#f87171',
      destructiveForeground: '#0a0a0b',
      destructiveHover: '#ef4444',
      focus: '#fbbf24',
      foreground: '#f5f5f5',
      input: '#27272a',
      muted: '#27272a',
      mutedForeground: '#d4d4d8',
      mutedHover: '#3f3f46',
      placeholder: '#9ca3af',
      primary: '#60a5fa',
      primaryForeground: '#0a0a0b',
      primaryHover: '#3b82f6',
      success: '#4ade80',
      successForeground: '#166534',
      warning: '#fbbf24',
      warningForeground: '#713f12',
    },
    id: 'default-dark',
    mode: 'dark',
    name: 'Default Dark',
    terminal: {
      black: '#1a1a1a',
      blue: '#60a5fa',
      brightBlack: '#525252',
      brightBlue: '#93c5fd',
      brightCyan: '#67e8f9',
      brightGreen: '#86efac',
      brightMagenta: '#d8b4fe',
      brightRed: '#fca5a5',
      brightWhite: '#ffffff',
      brightYellow: '#fcd34d',
      cyan: '#22d3ee',
      green: '#4ade80',
      magenta: '#c084fc',
      red: '#f87171',
      white: '#e5e5e5',
      yellow: '#fbbf24',
    },
  },
  {
    colors: {
      background: '#ffffff',
      border: '#d4d4d8',
      card: '#fafafa',
      cardForeground: '#171717',
      destructive: '#b91c1c',
      destructiveForeground: '#ffffff',
      destructiveHover: '#991b1b',
      focus: '#b45309',
      foreground: '#171717',
      input: '#f4f4f5',
      muted: '#f4f4f5',
      mutedForeground: '#3f3f46',
      mutedHover: '#e4e4e7',
      placeholder: '#6b7280',
      primary: '#1d4ed8',
      primaryForeground: '#ffffff',
      primaryHover: '#1e40af',
      success: '#166534',
      successForeground: '#ffffff',
      warning: '#854d0e',
      warningForeground: '#ffffff',
    },
    id: 'default-light',
    mode: 'light',
    name: 'Default Light',
    terminal: {
      black: '#171717',
      blue: '#2563eb',
      brightBlack: '#525252',
      brightBlue: '#3b82f6',
      brightCyan: '#06b6d4',
      brightGreen: '#22c55e',
      brightMagenta: '#a855f7',
      brightRed: '#ef4444',
      brightWhite: '#fafafa',
      brightYellow: '#eab308',
      cyan: '#0891b2',
      green: '#16a34a',
      magenta: '#9333ea',
      red: '#dc2626',
      white: '#e5e5e5',
      yellow: '#ca8a04',
    },
  },
  {
    colors: {
      background: '#2e3440',
      border: '#4c566a',
      card: '#3b4252',
      cardForeground: '#eceff4',
      destructive: '#bf616a',
      destructiveForeground: '#2e3440',
      destructiveHover: '#d08770',
      focus: '#ebcb8b',
      foreground: '#eceff4',
      input: '#3b4252',
      muted: '#434c5e',
      mutedForeground: '#d8dee9',
      mutedHover: '#4c566a',
      placeholder: '#a5adb8',
      primary: '#88c0d0',
      primaryForeground: '#2e3440',
      primaryHover: '#8fbcbb',
      success: '#a3be8c',
      successForeground: '#2e3440',
      warning: '#ebcb8b',
      warningForeground: '#2e3440',
    },
    id: 'nord-dark',
    mode: 'dark',
    name: 'Nord Dark',
    terminal: {
      black: '#3b4252',
      blue: '#81a1c1',
      brightBlack: '#4c566a',
      brightBlue: '#81a1c1',
      brightCyan: '#8fbcbb',
      brightGreen: '#a3be8c',
      brightMagenta: '#b48ead',
      brightRed: '#bf616a',
      brightWhite: '#eceff4',
      brightYellow: '#ebcb8b',
      cyan: '#88c0d0',
      green: '#a3be8c',
      magenta: '#b48ead',
      red: '#bf616a',
      white: '#e5e9f0',
      yellow: '#ebcb8b',
    },
  },
  {
    colors: {
      background: '#282a36',
      border: '#44475a',
      card: '#21222c',
      cardForeground: '#f8f8f2',
      destructive: '#ff6e6e',
      destructiveForeground: '#282a36',
      destructiveHover: '#ff5555',
      focus: '#f1fa8c',
      foreground: '#f8f8f2',
      input: '#343746',
      muted: '#343746',
      mutedForeground: '#d4d6e4',
      mutedHover: '#44475a',
      placeholder: '#a3a6b8',
      primary: '#bd93f9',
      primaryForeground: '#282a36',
      primaryHover: '#caa9fa',
      success: '#50fa7b',
      successForeground: '#282a36',
      warning: '#f1fa8c',
      warningForeground: '#282a36',
    },
    id: 'dracula',
    mode: 'dark',
    name: 'Dracula',
    terminal: {
      black: '#21222c',
      blue: '#bd93f9',
      brightBlack: '#6272a4',
      brightBlue: '#d6acff',
      brightCyan: '#a4ffff',
      brightGreen: '#69ff94',
      brightMagenta: '#ff92df',
      brightRed: '#ff6e6e',
      brightWhite: '#ffffff',
      brightYellow: '#ffffa5',
      cyan: '#8be9fd',
      green: '#50fa7b',
      magenta: '#ff79c6',
      red: '#ff5555',
      white: '#f8f8f2',
      yellow: '#f1fa8c',
    },
  },
  {
    colors: {
      background: '#002b36',
      border: '#2d6677',
      card: '#073642',
      cardForeground: '#fdf6e3',
      destructive: '#e57373',
      destructiveForeground: '#002b36',
      destructiveHover: '#dc322f',
      focus: '#eee8d5',
      foreground: '#fdf6e3',
      input: '#073642',
      muted: '#094152',
      mutedForeground: '#eee8d5',
      mutedHover: '#0d5666',
      placeholder: '#839496',
      primary: '#93a1a1',
      primaryForeground: '#002b36',
      primaryHover: '#839496',
      success: '#97d077',
      successForeground: '#002b36',
      warning: '#eee8d5',
      warningForeground: '#002b36',
    },
    id: 'solarized-dark',
    mode: 'dark',
    name: 'Solarized Dark',
    terminal: {
      black: '#073642',
      blue: '#268bd2',
      brightBlack: '#586e75',
      brightBlue: '#268bd2',
      brightCyan: '#2aa198',
      brightGreen: '#859900',
      brightMagenta: '#6c71c4',
      brightRed: '#cb4b16',
      brightWhite: '#fdf6e3',
      brightYellow: '#b58900',
      cyan: '#2aa198',
      green: '#859900',
      magenta: '#d33682',
      red: '#dc322f',
      white: '#eee8d5',
      yellow: '#b58900',
    },
  },
  {
    colors: {
      background: '#282c34',
      border: '#3e4451',
      card: '#21252b',
      cardForeground: '#e6e6e6',
      destructive: '#f28b82',
      destructiveForeground: '#282c34',
      destructiveHover: '#e06c75',
      focus: '#e5c07b',
      foreground: '#e6e6e6',
      input: '#2c313c',
      muted: '#2c313c',
      mutedForeground: '#c8c8c8',
      mutedHover: '#3a3f4b',
      placeholder: '#9da5b4',
      primary: '#8cc8ff',
      primaryForeground: '#282c34',
      primaryHover: '#61afef',
      success: '#98c379',
      successForeground: '#282c34',
      warning: '#e5c07b',
      warningForeground: '#282c34',
    },
    id: 'one-dark',
    mode: 'dark',
    name: 'One Dark',
    terminal: {
      black: '#3f4451',
      blue: '#61afef',
      brightBlack: '#4f5666',
      brightBlue: '#61afef',
      brightCyan: '#56b6c2',
      brightGreen: '#98c379',
      brightMagenta: '#c678dd',
      brightRed: '#be5046',
      brightWhite: '#e6e6e6',
      brightYellow: '#d19a66',
      cyan: '#56b6c2',
      green: '#98c379',
      magenta: '#c678dd',
      red: '#e06c75',
      white: '#abb2bf',
      yellow: '#e5c07b',
    },
  },
];
// Stryker restore all

function applyThemeToDOM(theme: Theme): void {
  const root = document.documentElement;

  // Set CSS variables
  for (const [key, value] of Object.entries(theme.colors)) {
    const cssVar = `--color-${toKebabCase(key)}`;
    root.style.setProperty(cssVar, value);
  }

  // Update dark mode class
  root.classList.toggle('dark', theme.mode === 'dark');

  // Update meta theme-color
  let metaTheme = document.querySelector('meta[name="theme-color"]');
  if (!metaTheme) {
    metaTheme = document.createElement('meta');
    metaTheme.setAttribute('name', 'theme-color');
    document.head.append(metaTheme);
  }
  metaTheme.setAttribute('content', theme.colors.background);
}

// Stryker disable all: Pure data constant
// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
const FALLBACK_THEME: Theme = THEMES[0]!;
// Stryker restore all

function createThemeStore() {
  const stored = loadValidated('theme', z.string());
  const defaultTheme = stored ?? (getSystemPreference() === 'dark' ? 'default-dark' : 'default-light');
  let currentThemeId = $state(defaultTheme);

  // Apply theme on initialization
  if (typeof document !== 'undefined') {
    const theme = THEMES.find((t) => t.id === currentThemeId) ?? FALLBACK_THEME;
    applyThemeToDOM(theme);
  }

  return {
    setTheme(themeId: string) {
      const theme = THEMES.find((t) => t.id === themeId);
      if (!theme) return;

      currentThemeId = themeId;
      save('theme', themeId);
      applyThemeToDOM(theme);
    },
    get theme() {
      return THEMES.find((t) => t.id === currentThemeId) ?? FALLBACK_THEME;
    },
    get themeId() {
      return currentThemeId;
    },

    get themes() {
      return THEMES;
    },
  };
}

function getSystemPreference(): 'dark' | 'light' {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function toKebabCase(str: string): string {
  return str.replaceAll(/([A-Z])/g, '-$1').toLowerCase();
}

export const themeStore = createThemeStore();
