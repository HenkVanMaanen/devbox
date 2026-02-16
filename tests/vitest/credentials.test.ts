import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('$lib/api/hetzner', () => ({
  validateToken: vi.fn(),
}));

describe('credentials store', () => {
  beforeEach(() => {
    vi.resetModules();
    localStorage.clear();
  });

  async function getStore() {
    const { credentialsStore } = await import('$lib/stores/credentials.svelte');
    return credentialsStore;
  }

  async function getMockHetzner() {
    const hetzner = await import('$lib/api/hetzner');
    return hetzner.validateToken as ReturnType<typeof vi.fn>;
  }

  it('initial token is empty when localStorage is empty', async () => {
    const store = await getStore();
    expect(store.token).toBe('');
  });

  it('loads token from localStorage', async () => {
    localStorage.setItem('devbox_hetzner_token', JSON.stringify('my-secret-token'));
    const store = await getStore();
    expect(store.token).toBe('my-secret-token');
  });

  it('hasToken returns false when token is empty', async () => {
    const store = await getStore();
    expect(store.hasToken).toBe(false);
  });

  it('hasToken returns true when token is set', async () => {
    const store = await getStore();
    store.token = 'some-token';
    expect(store.hasToken).toBe(true);
  });

  it('setting token updates the value', async () => {
    const store = await getStore();
    store.token = 'new-token';
    expect(store.token).toBe('new-token');
  });

  it('save() persists token to localStorage', async () => {
    const store = await getStore();
    store.token = 'persist-me';
    store.save();

    const saved = JSON.parse(localStorage.getItem('devbox_hetzner_token')!) as string;
    expect(saved).toBe('persist-me');
  });

  it('clear() empties token and removes from localStorage', async () => {
    const store = await getStore();
    store.token = 'to-be-cleared';
    store.save();
    expect(localStorage.getItem('devbox_hetzner_token')).not.toBeNull();

    store.clear();
    expect(store.token).toBe('');
    expect(store.hasToken).toBe(false);
    expect(localStorage.getItem('devbox_hetzner_token')).toBeNull();
  });

  it('validate() returns false when token is empty', async () => {
    const store = await getStore();
    const result = await store.validate();
    expect(result).toBe(false);
  });

  it('validate() returns true when API validates token', async () => {
    const store = await getStore();
    const mockValidate = await getMockHetzner();
    mockValidate.mockResolvedValue(true);

    store.token = 'valid-token';
    const result = await store.validate();

    expect(result).toBe(true);
    expect(mockValidate).toHaveBeenCalledWith('valid-token');
  });

  it('validate() returns false when API rejects token', async () => {
    const store = await getStore();
    const mockValidate = await getMockHetzner();
    mockValidate.mockResolvedValue(false);

    store.token = 'invalid-token';
    const result = await store.validate();

    expect(result).toBe(false);
    expect(mockValidate).toHaveBeenCalledWith('invalid-token');
  });

  it('validating is true during validation', async () => {
    const store = await getStore();
    const mockValidate = await getMockHetzner();

    // Create a deferred promise so we can check state mid-flight
    let resolveValidation!: (value: boolean) => void;
    mockValidate.mockReturnValue(
      new Promise<boolean>((resolve) => {
        resolveValidation = resolve;
      }),
    );

    store.token = 'some-token';
    const validatePromise = store.validate();

    expect(store.validating).toBe(true);

    resolveValidation(true);
    await validatePromise;

    expect(store.validating).toBe(false);
  });

  it('validating is false after validation completes', async () => {
    const store = await getStore();
    const mockValidate = await getMockHetzner();
    mockValidate.mockResolvedValue(true);

    store.token = 'some-token';
    await store.validate();

    expect(store.validating).toBe(false);
  });
});
