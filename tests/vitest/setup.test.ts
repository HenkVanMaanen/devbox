import { beforeEach, describe, expect, it, vi } from 'vitest';

describe('setup store', () => {
  beforeEach(() => {
    vi.resetModules();
    localStorage.clear();
  });

  async function getStore() {
    const { setupStore } = await import('$lib/stores/setup.svelte');
    return setupStore;
  }

  it('isComplete returns false when localStorage is empty', async () => {
    const store = await getStore();
    expect(store.isComplete).toBe(false);
  });

  it('isComplete returns true when flag is set in localStorage', async () => {
    localStorage.setItem('devbox_setup_complete', JSON.stringify(true));
    const store = await getStore();
    expect(store.isComplete).toBe(true);
  });

  it('markComplete persists to localStorage', async () => {
    const store = await getStore();
    expect(store.isComplete).toBe(false);
    store.markComplete();
    expect(store.isComplete).toBe(true);
    expect(JSON.parse(localStorage.getItem('devbox_setup_complete')!)).toBe(true);
  });

  it('auto-detects setup complete when token and auth users exist', async () => {
    localStorage.setItem('devbox_hetzner_token', JSON.stringify('test-token'));
    localStorage.setItem(
      'devbox_config',
      JSON.stringify({
        auth: { users: [{ passwordHash: '$2a$10$hash', username: 'alice' }] },
      }),
    );
    const store = await getStore();
    expect(store.isComplete).toBe(true);
    // Should also persist the flag
    expect(JSON.parse(localStorage.getItem('devbox_setup_complete')!)).toBe(true);
  });

  it('does not auto-detect when only token exists (no users)', async () => {
    localStorage.setItem('devbox_hetzner_token', JSON.stringify('test-token'));
    const store = await getStore();
    expect(store.isComplete).toBe(false);
  });

  it('does not auto-detect when only users exist (no token)', async () => {
    localStorage.setItem(
      'devbox_config',
      JSON.stringify({
        auth: { users: [{ passwordHash: '$2a$10$hash', username: 'alice' }] },
      }),
    );
    const store = await getStore();
    expect(store.isComplete).toBe(false);
  });

  it('does not auto-detect when users array is empty', async () => {
    localStorage.setItem('devbox_hetzner_token', JSON.stringify('test-token'));
    localStorage.setItem('devbox_config', JSON.stringify({ auth: { users: [] } }));
    const store = await getStore();
    expect(store.isComplete).toBe(false);
  });

  it('does not auto-detect when token is empty string', async () => {
    localStorage.setItem('devbox_hetzner_token', JSON.stringify(''));
    localStorage.setItem(
      'devbox_config',
      JSON.stringify({
        auth: { users: [{ passwordHash: '$2a$10$hash', username: 'alice' }] },
      }),
    );
    const store = await getStore();
    expect(store.isComplete).toBe(false);
  });

  it('skips auto-detect when already marked complete', async () => {
    localStorage.setItem('devbox_setup_complete', JSON.stringify(true));
    // No token or config set — should still be complete from the flag
    const store = await getStore();
    expect(store.isComplete).toBe(true);
  });
});
