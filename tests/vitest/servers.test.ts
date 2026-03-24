import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { Server } from '$lib/types';

const mockSwrFetch = vi.fn();
const mockBackgroundRefresh = vi.fn();
const mockClearSwrCache = vi.fn();
const mockPeekCache = vi.fn();

vi.mock('$lib/api/hetzner', () => ({
  createServer: vi.fn(),
  deleteServer: vi.fn(),
  getServer: vi.fn(),
  listImages: vi.fn(),
  listLocations: vi.fn(),
  listServers: vi.fn(),
  listServerTypes: vi.fn(),
  listSSHKeys: vi.fn(),
  waitForRunning: vi.fn(),
}));

vi.mock('$lib/utils/swr-cache', () => ({
  backgroundRefresh: mockBackgroundRefresh,
  CACHE_KEYS: {
    images: 'devbox_cache_images',
    locations: 'devbox_cache_locations',
    servers: 'devbox_cache_servers',
    serverTypes: 'devbox_cache_server_types',
  },
  clearSwrCache: mockClearSwrCache,
  peekCache: mockPeekCache,
  swrFetch: mockSwrFetch,
}));

const mockServer: Server = {
  created: '2024-01-01',
  datacenter: { name: 'fsn1-dc14', location: { city: 'Falkenstein', country: 'DE' } },
  id: 1,
  labels: { managed: 'devbox', progress: 'ready' },
  name: 'test-server',
  public_net: { ipv4: { ip: '1.2.3.4' }, ipv6: { ip: '2001:db8::1' } },
  server_type: { name: 'cx22', description: 'CX22', cores: 2, memory: 4, disk: 40 },
  status: 'running',
};

const mockNonDevboxServer: Server = {
  ...mockServer,
  id: 2,
  labels: { managed: 'other' },
  name: 'non-devbox',
};

const mockProvisioningServer: Server = {
  ...mockServer,
  id: 3,
  labels: { managed: 'devbox', progress: 'installing' },
  name: 'provisioning-server',
};

describe('servers store', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    localStorage.clear();
  });

  async function getStore() {
    const { serversStore } = await import('$lib/stores/servers.svelte');
    return serversStore;
  }

  async function getHetzner() {
    return await import('$lib/api/hetzner');
  }

  it('has empty initial state', async () => {
    const store = await getStore();
    expect(store.servers).toEqual([]);
    expect(store.serverTypes).toEqual([]);
    expect(store.locations).toEqual([]);
    expect(store.images).toEqual([]);
    expect(store.loading).toBe(false);
    expect(store.creating).toBe(false);
    expect(store.createProgress).toBe('');
    expect(store.error).toBeNull();
  });

  it('clearOptions clears serverTypes, locations, images, and SWR cache', async () => {
    const store = await getStore();

    // Load some options first
    mockSwrFetch.mockImplementation(async (opts: { key: string; onData: (data: unknown[]) => void }) => {
      if (opts.key === 'devbox_cache_server_types') opts.onData([{ id: 1, name: 'cx22' }]);
      if (opts.key === 'devbox_cache_locations') opts.onData([{ id: 1, name: 'fsn1' }]);
      if (opts.key === 'devbox_cache_images') opts.onData([{ id: 1, name: 'ubuntu-24.04' }]);
    });
    await store.loadOptions('test-token');
    expect(store.serverTypes).toHaveLength(1);

    store.clearOptions();
    expect(store.serverTypes).toEqual([]);
    expect(store.locations).toEqual([]);
    expect(store.images).toEqual([]);
    expect(mockClearSwrCache).toHaveBeenCalled();
  });

  it('load() with empty token sets empty servers', async () => {
    const store = await getStore();
    await store.load('');
    expect(store.servers).toEqual([]);
    expect(store.error).toBeNull();
    expect(mockSwrFetch).not.toHaveBeenCalled();
  });

  it('load() calls swrFetch and populates servers via onData', async () => {
    mockPeekCache.mockReturnValue(false);
    mockSwrFetch.mockImplementation(async (opts: { onData: (data: Server[]) => void }) => {
      opts.onData([mockServer, mockNonDevboxServer]);
    });

    const store = await getStore();
    await store.load('test-token');

    expect(mockSwrFetch).toHaveBeenCalledOnce();
    const callArg = mockSwrFetch.mock.calls[0]?.[0];
    expect(callArg.key).toBe('devbox_cache_servers');

    // The store filters to devbox servers internally via onData
    expect(store.servers).toHaveLength(1);
    expect(store.servers[0]?.name).toBe('test-server');
  });

  it('load() sets error on failure', async () => {
    mockPeekCache.mockReturnValue(false);
    mockSwrFetch.mockRejectedValue(new Error('Network error'));

    const store = await getStore();
    await store.load('test-token');

    expect(store.error).toBe('Network error');
    expect(store.servers).toEqual([]);
  });

  it('load() sets generic error for non-Error throws', async () => {
    mockPeekCache.mockReturnValue(false);
    mockSwrFetch.mockRejectedValue('something');

    const store = await getStore();
    await store.load('test-token');

    expect(store.error).toBe('Failed to load servers');
  });

  it('devboxServers filters by managed=devbox label', async () => {
    mockPeekCache.mockReturnValue(false);
    mockSwrFetch.mockImplementation(async (opts: { onData: (data: Server[]) => void }) => {
      opts.onData([mockServer, mockNonDevboxServer]);
    });

    const store = await getStore();
    await store.load('test-token');

    // servers already filtered by load's onData (filterDevbox)
    // devboxServers getter re-filters (redundant but tested)
    expect(store.devboxServers).toHaveLength(1);
    expect(store.devboxServers[0]?.labels['managed']).toBe('devbox');
  });

  it('loading getter reflects fetch state', async () => {
    mockPeekCache.mockReturnValue(false);
    mockSwrFetch.mockImplementation(async () => {
      // Simulate async completion
    });

    const store = await getStore();
    // Before load, loading is false
    expect(store.loading).toBe(false);

    await store.load('test-token');
    // After load completes, loading should be false
    expect(store.loading).toBe(false);
  });

  it('create() calls hetzner.createServer and waitForRunning', async () => {
    const hetznerMod = await getHetzner();
    const createdServer: Server = { ...mockServer, id: 10, status: 'initializing' };
    const runningServer: Server = { ...mockServer, id: 10, status: 'running' };

    vi.mocked(hetznerMod.createServer).mockResolvedValue(createdServer);
    vi.mocked(hetznerMod.waitForRunning).mockResolvedValue(runningServer);
    mockBackgroundRefresh.mockResolvedValue(undefined);

    const store = await getStore();
    const result = await store.create('test-token', {
      image: 'ubuntu-24.04',
      labels: { managed: 'devbox' },
      location: 'fsn1',
      name: 'new-server',
      serverType: 'cx22',
      sshKeys: [1],
      userData: '#cloud-config',
    });

    expect(hetznerMod.createServer).toHaveBeenCalledOnce();
    expect(hetznerMod.waitForRunning).toHaveBeenCalledWith('test-token', 10);
    expect(result.status).toBe('running');
    expect(result.id).toBe(10);

    // Creating state should be reset after completion
    expect(store.creating).toBe(false);
    expect(store.createProgress).toBe('');
  });

  it('delete() optimistic removal and rollback on failure', async () => {
    // First load a server
    mockPeekCache.mockReturnValue(false);
    mockSwrFetch.mockImplementation(async (opts: { onData: (data: Server[]) => void }) => {
      opts.onData([mockServer]);
    });

    const store = await getStore();
    await store.load('test-token');
    expect(store.servers).toHaveLength(1);

    // Make delete fail
    const hetznerMod = await getHetzner();
    vi.mocked(hetznerMod.deleteServer).mockRejectedValue(new Error('Delete failed'));

    await expect(store.delete('test-token', 1)).rejects.toThrow('Delete failed');

    // Server should be restored (rolled back)
    expect(store.servers).toHaveLength(1);
    expect(store.servers[0]?.id).toBe(1);
  });

  it('delete() removes server on success', async () => {
    // Load a server first
    mockPeekCache.mockReturnValue(false);
    mockSwrFetch.mockImplementation(async (opts: { onData: (data: Server[]) => void }) => {
      opts.onData([mockServer]);
    });

    const store = await getStore();
    await store.load('test-token');
    expect(store.servers).toHaveLength(1);

    const hetznerMod = await getHetzner();
    vi.mocked(hetznerMod.deleteServer).mockResolvedValue(undefined);
    mockBackgroundRefresh.mockResolvedValue(undefined);

    await store.delete('test-token', 1);

    expect(store.servers).toHaveLength(0);
    expect(hetznerMod.deleteServer).toHaveBeenCalledWith('test-token', 1);
  });
});
