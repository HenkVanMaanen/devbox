import { beforeEach, describe, expect, it, vi } from 'vitest';

describe('config store', () => {
  beforeEach(() => {
    vi.resetModules();
    localStorage.clear();
  });

  async function getStore() {
    const { configStore } = await import('$lib/stores/config.svelte');
    return configStore;
  }

  it('loads default config when localStorage is empty', async () => {
    const store = await getStore();
    expect(store.value).toBeDefined();
    expect(store.value.autoDelete.enabled).toBe(true);
    expect(store.value.autoDelete.timeoutMinutes).toBe(90);
    expect(store.value.autoDelete.warningMinutes).toBe(5);
  });

  it('loads and merges config from localStorage', async () => {
    localStorage.setItem(
      'devbox_config',
      JSON.stringify({ autoDelete: { enabled: false, timeoutMinutes: 30, warningMinutes: 2 } }),
    );
    const store = await getStore();
    // Overridden values
    expect(store.value.autoDelete.enabled).toBe(false);
    expect(store.value.autoDelete.timeoutMinutes).toBe(30);
    expect(store.value.autoDelete.warningMinutes).toBe(2);
    // Merged defaults still present
    expect(store.value.hetzner.location).toBe('fsn1');
    expect(store.value.chezmoi.repoUrl).toBe('');
  });

  it('falls back to defaults on invalid localStorage data', async () => {
    localStorage.setItem('devbox_config', 'not-json!!!');
    const store = await getStore();
    expect(store.value.autoDelete.enabled).toBe(true);
    expect(store.value.hetzner.location).toBe('fsn1');
  });

  it('get() returns nested value by dot-notation path', async () => {
    const store = await getStore();
    expect(store.get('autoDelete.enabled')).toBe(true);
    expect(store.get('hetzner.location')).toBe('fsn1');
    expect(store.get('git.credential.host')).toBe('github.com');
  });

  it('set() sets nested value by dot-notation path', async () => {
    const store = await getStore();
    store.set('hetzner.location', 'nbg1');
    expect(store.value.hetzner.location).toBe('nbg1');
    expect(store.get('hetzner.location')).toBe('nbg1');
  });

  it('save() persists config to localStorage', async () => {
    const store = await getStore();
    store.set('hetzner.location', 'ash');
    store.save();

    const saved = JSON.parse(localStorage.getItem('devbox_config')!) as Record<string, unknown>;
    expect(saved).toBeDefined();
    expect((saved['hetzner'] as Record<string, unknown>)['location']).toBe('ash');
  });

  it('reset() restores defaults and saves to localStorage', async () => {
    const store = await getStore();
    store.set('hetzner.location', 'nbg1');
    store.set('autoDelete.enabled', false);
    store.reset();

    expect(store.value.hetzner.location).toBe('fsn1');
    expect(store.value.autoDelete.enabled).toBe(true);

    // Also persisted
    const saved = JSON.parse(localStorage.getItem('devbox_config')!) as Record<string, unknown>;
    expect(saved).toBeDefined();
    expect((saved['hetzner'] as Record<string, unknown>)['location']).toBe('fsn1');
  });

  it('snapshot() returns a deep clone of current config', async () => {
    const store = await getStore();
    const snap = store.snapshot();

    // Values match
    expect(snap.hetzner.location).toBe(store.value.hetzner.location);

    // Mutating snapshot does not affect store
    snap.hetzner.location = 'changed';
    expect(store.value.hetzner.location).toBe('fsn1');
  });

  it('isDirty() returns false for matching snapshot', async () => {
    const store = await getStore();
    const snap = store.snapshot();
    expect(store.isDirty(snap)).toBe(false);
  });

  it('isDirty() returns true after modification', async () => {
    const store = await getStore();
    const snap = store.snapshot();
    store.set('hetzner.location', 'nbg1');
    expect(store.isDirty(snap)).toBe(true);
  });

  it('restore() applies a snapshot', async () => {
    const store = await getStore();
    const snap = store.snapshot();

    store.set('hetzner.location', 'nbg1');
    expect(store.value.hetzner.location).toBe('nbg1');

    store.restore(snap);
    expect(store.value.hetzner.location).toBe('fsn1');
  });

  it('value getter returns current config', async () => {
    const store = await getStore();
    const config = store.value;
    expect(config).toBeDefined();
    expect(config.autoDelete).toBeDefined();
    expect(config.hetzner).toBeDefined();
    expect(config.ssh).toBeDefined();
  });

  it('value setter replaces config', async () => {
    const store = await getStore();
    const snap = store.snapshot();
    snap.hetzner.location = 'hel1';
    snap.autoDelete.enabled = false;

    store.value = snap;

    expect(store.value.hetzner.location).toBe('hel1');
    expect(store.value.autoDelete.enabled).toBe(false);
  });

  it('has expected default values', async () => {
    const store = await getStore();
    expect(store.value.autoDelete.enabled).toBe(true);
    expect(store.value.autoDelete.timeoutMinutes).toBe(90);
    expect(store.value.autoDelete.warningMinutes).toBe(5);
    expect(store.value.hetzner.location).toBe('fsn1');
    expect(store.value.hetzner.baseImage).toBe('ubuntu-24.04');
    expect(store.value.hetzner.serverType).toBe('cx22');
    expect(store.value.chezmoi.ageKey).toBe('');
    expect(store.value.chezmoi.repoUrl).toBe('');
    expect(store.value.customCloudInit.mode).toBe('merge');
    expect(store.value.customCloudInit.yaml).toBe('');
    expect(store.value.git.credential.host).toBe('github.com');
    expect(store.value.services.dnsService).toBe('sslip.io');
    expect(store.value.services.acmeProvider).toBe('zerossl');
    expect(store.value.ssh.keys).toEqual([]);
  });

  it('restore() deep clones the snapshot so later mutations do not leak', async () => {
    const store = await getStore();
    const snap = store.snapshot();
    store.restore(snap);

    // Mutate the original snapshot object after restore
    snap.hetzner.location = 'mutated';
    expect(store.value.hetzner.location).toBe('fsn1');
  });
});
