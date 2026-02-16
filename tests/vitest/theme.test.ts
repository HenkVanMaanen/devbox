import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

describe('theme store', () => {
  beforeEach(() => {
    vi.resetModules();
    localStorage.clear();

    // Reset document state
    document.documentElement.removeAttribute('style');
    document.documentElement.classList.remove('dark');
    const existingMeta = document.querySelector('meta[name="theme-color"]');
    if (existingMeta) {
      existingMeta.remove();
    }

    // Mock matchMedia for system preference (default: dark)
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: vi.fn().mockImplementation((query: string) => ({
        matches: query === '(prefers-color-scheme: dark)',
        addEventListener: vi.fn(),
      })),
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  async function getStore() {
    const mod = await import('$lib/stores/theme.svelte');
    return mod;
  }

  it('themes getter returns all 6 themes', async () => {
    const { themeStore } = await getStore();
    expect(themeStore.themes).toHaveLength(6);
  });

  it('themes contain expected theme ids', async () => {
    const { themeStore } = await getStore();
    const ids = themeStore.themes.map((t) => t.id);
    expect(ids).toContain('default-dark');
    expect(ids).toContain('default-light');
    expect(ids).toContain('nord-dark');
    expect(ids).toContain('dracula');
    expect(ids).toContain('solarized-dark');
    expect(ids).toContain('one-dark');
  });

  it('initial theme is default-dark when system prefers dark', async () => {
    const { themeStore } = await getStore();
    expect(themeStore.themeId).toBe('default-dark');
  });

  it('initial theme is default-light when system prefers light', async () => {
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: vi.fn().mockImplementation(() => ({
        matches: false,
        addEventListener: vi.fn(),
      })),
    });

    const { themeStore } = await getStore();
    expect(themeStore.themeId).toBe('default-light');
  });

  it('initial theme loads from localStorage when saved', async () => {
    localStorage.setItem('devbox_theme', JSON.stringify('dracula'));

    const { themeStore } = await getStore();
    expect(themeStore.themeId).toBe('dracula');
  });

  it('setTheme changes current theme', async () => {
    const { themeStore } = await getStore();
    expect(themeStore.themeId).toBe('default-dark');

    themeStore.setTheme('nord-dark');
    expect(themeStore.themeId).toBe('nord-dark');
  });

  it('setTheme with invalid id does nothing', async () => {
    const { themeStore } = await getStore();
    const originalId = themeStore.themeId;

    themeStore.setTheme('nonexistent-theme');
    expect(themeStore.themeId).toBe(originalId);
  });

  it('theme getter returns current theme object', async () => {
    const { themeStore } = await getStore();
    const theme = themeStore.theme;
    expect(theme.id).toBe('default-dark');
    expect(theme.name).toBe('Default Dark');
    expect(theme.mode).toBe('dark');
    expect(theme.colors).toBeDefined();
    expect(theme.terminal).toBeDefined();
  });

  it('theme getter updates after setTheme', async () => {
    const { themeStore } = await getStore();
    themeStore.setTheme('dracula');
    expect(themeStore.theme.id).toBe('dracula');
    expect(themeStore.theme.name).toBe('Dracula');
  });

  it('themeId getter returns current id string', async () => {
    const { themeStore } = await getStore();
    expect(typeof themeStore.themeId).toBe('string');
    expect(themeStore.themeId).toBe('default-dark');
  });

  it('setTheme applies CSS variables to document.documentElement', async () => {
    const { themeStore } = await getStore();
    themeStore.setTheme('dracula');

    const root = document.documentElement;
    expect(root.style.getPropertyValue('--color-background')).toBe('#282a36');
    expect(root.style.getPropertyValue('--color-foreground')).toBe('#f8f8f2');
    expect(root.style.getPropertyValue('--color-primary')).toBe('#bd93f9');
  });

  it('setTheme converts camelCase color keys to kebab-case CSS variables', async () => {
    const { themeStore } = await getStore();
    themeStore.setTheme('default-dark');

    const root = document.documentElement;
    expect(root.style.getPropertyValue('--color-card-foreground')).toBe('#f5f5f5');
    expect(root.style.getPropertyValue('--color-muted-foreground')).toBe('#d4d4d8');
    expect(root.style.getPropertyValue('--color-primary-hover')).toBe('#3b82f6');
    expect(root.style.getPropertyValue('--color-destructive-foreground')).toBe('#0a0a0b');
  });

  it('setTheme toggles dark class on documentElement for dark theme', async () => {
    const { themeStore } = await getStore();
    themeStore.setTheme('dracula');
    expect(document.documentElement.classList.contains('dark')).toBe(true);
  });

  it('setTheme removes dark class for light theme', async () => {
    const { themeStore } = await getStore();

    // First set a dark theme (initialization already applies one)
    themeStore.setTheme('dracula');
    expect(document.documentElement.classList.contains('dark')).toBe(true);

    // Switch to light
    themeStore.setTheme('default-light');
    expect(document.documentElement.classList.contains('dark')).toBe(false);
  });

  it('setTheme creates meta theme-color element if missing', async () => {
    // Ensure no meta theme-color exists
    const existing = document.querySelector('meta[name="theme-color"]');
    expect(existing).toBeNull();

    const { themeStore } = await getStore();
    themeStore.setTheme('nord-dark');

    const meta = document.querySelector('meta[name="theme-color"]');
    expect(meta).not.toBeNull();
    expect(meta?.getAttribute('content')).toBe('#2e3440');
  });

  it('setTheme updates existing meta theme-color element', async () => {
    const { themeStore } = await getStore();

    themeStore.setTheme('dracula');
    let meta = document.querySelector('meta[name="theme-color"]');
    expect(meta?.getAttribute('content')).toBe('#282a36');

    themeStore.setTheme('solarized-dark');
    meta = document.querySelector('meta[name="theme-color"]');
    expect(meta?.getAttribute('content')).toBe('#002b36');
  });

  it('setTheme saves theme id to localStorage', async () => {
    const { themeStore } = await getStore();
    themeStore.setTheme('one-dark');

    const stored = localStorage.getItem('devbox_theme');
    expect(stored).toBe(JSON.stringify('one-dark'));
  });

  it('THEMES export contains all 6 themes', async () => {
    const { THEMES } = await getStore();
    expect(THEMES).toHaveLength(6);
  });

  it('each theme has required properties', async () => {
    const { THEMES } = await getStore();
    for (const theme of THEMES) {
      expect(theme.id).toBeDefined();
      expect(theme.name).toBeDefined();
      expect(theme.mode).toMatch(/^(dark|light)$/);
      expect(theme.colors).toBeDefined();
      expect(theme.colors.background).toBeDefined();
      expect(theme.colors.foreground).toBeDefined();
      expect(theme.terminal).toBeDefined();
    }
  });

  it('initialization applies theme CSS variables to DOM', async () => {
    // On import, the store applies the initial theme to the DOM
    await getStore();

    const root = document.documentElement;
    // default-dark is the initial theme (system prefers dark)
    expect(root.style.getPropertyValue('--color-background')).toBe('#0a0a0b');
    expect(root.style.getPropertyValue('--color-foreground')).toBe('#f5f5f5');
  });

  it('initialization applies dark class for dark system preference', async () => {
    await getStore();
    expect(document.documentElement.classList.contains('dark')).toBe(true);
  });

  it('initialization does not apply dark class for light system preference', async () => {
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: vi.fn().mockImplementation(() => ({
        matches: false,
        addEventListener: vi.fn(),
      })),
    });

    await getStore();
    expect(document.documentElement.classList.contains('dark')).toBe(false);
  });
});
