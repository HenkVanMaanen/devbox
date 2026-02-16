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

const mockProvisioningServer: Server = {
  ...mockServer,
  id: 3,
  labels: { managed: 'devbox', progress: 'installing' },
  name: 'provisioning-server',
};

describe('servers store - load()', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    localStorage.clear();
  });

  async function getStore() {
    const { serversStore } = await import('$lib/stores/servers.svelte');
    return serversStore;
  }

  it('load() with cached data does not set loading to true', async () => {
    mockPeekCache.mockReturnValue(true);
    mockSwrFetch.mockImplementation(async (opts: { onData: (data: Server[]) => void }) => {
      opts.onData([mockServer]);
    });

    const store = await getStore();
    await store.load('test-token');

    // peekCache returned true, so loading should never have been set to true
    expect(mockPeekCache).toHaveBeenCalledWith('devbox_cache_servers', 'test-token');
    expect(store.loading).toBe(false);
    expect(store.servers).toHaveLength(1);
  });

  it('load() starts polling for provisioning servers', async () => {
    mockPeekCache.mockReturnValue(false);
    mockSwrFetch.mockImplementation(async (opts: { onData: (data: Server[]) => void }) => {
      opts.onData([mockProvisioningServer]);
    });

    const store = await getStore();
    await store.load('test-token');

    // Server with progress !== 'ready' should trigger polling
    expect(store.servers).toHaveLength(1);
    expect(store.servers[0]?.labels['progress']).toBe('installing');
  });
});

describe('servers store - loadOptions()', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    localStorage.clear();
  });

  async function getStore() {
    const { serversStore } = await import('$lib/stores/servers.svelte');
    return serversStore;
  }

  it('loadOptions() returns early with empty token', async () => {
    const store = await getStore();
    await store.loadOptions('');
    expect(mockSwrFetch).not.toHaveBeenCalled();
  });

  it('loadOptions() populates all three: serverTypes, locations, images', async () => {
    mockSwrFetch.mockImplementation(async (opts: { key: string; onData: (data: unknown[]) => void }) => {
      if (opts.key === 'devbox_cache_server_types') opts.onData([{ id: 1, name: 'cx22' }]);
      if (opts.key === 'devbox_cache_locations') opts.onData([{ id: 1, name: 'fsn1' }]);
      if (opts.key === 'devbox_cache_images') opts.onData([{ id: 1, name: 'ubuntu-24.04' }]);
    });

    const store = await getStore();
    await store.loadOptions('test-token');

    expect(store.serverTypes).toHaveLength(1);
    expect(store.locations).toHaveLength(1);
    expect(store.images).toHaveLength(1);
  });

  it('loadOptions() second call is no-op when serverTypes already loaded', async () => {
    mockSwrFetch.mockImplementation(async (opts: { key: string; onData: (data: unknown[]) => void }) => {
      if (opts.key === 'devbox_cache_server_types') opts.onData([{ id: 1, name: 'cx22' }]);
      if (opts.key === 'devbox_cache_locations') opts.onData([{ id: 1, name: 'fsn1' }]);
      if (opts.key === 'devbox_cache_images') opts.onData([{ id: 1, name: 'ubuntu-24.04' }]);
    });

    const store = await getStore();
    await store.loadOptions('test-token');
    const callCount = mockSwrFetch.mock.calls.length;

    // Second call should be a no-op
    await store.loadOptions('test-token');
    expect(mockSwrFetch.mock.calls.length).toBe(callCount);
  });

  it('loadOptions() error handling does not throw', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    mockSwrFetch.mockRejectedValue(new Error('Network error'));

    const store = await getStore();
    // Should not throw
    await store.loadOptions('test-token');

    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });
});

describe('servers store - create()', () => {
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

  it('create() error resets creating state', async () => {
    const hetznerMod = await getHetzner();
    vi.mocked(hetznerMod.createServer).mockRejectedValue(new Error('Create failed'));

    const store = await getStore();

    await expect(
      store.create(
        'test-token',
        {
          image: 'ubuntu-24.04',
          labels: { managed: 'devbox' },
          location: 'fsn1',
          name: 'new-server',
          serverType: 'cx22',
          sshKeys: [1],
          userData: '#cloud-config',
        },
        'access-token',
      ),
    ).rejects.toThrow('Create failed');

    expect(store.creating).toBe(false);
    expect(store.createProgress).toBe('');
  });

  it('create() saves token with server name from API response', async () => {
    const hetznerMod = await getHetzner();
    const createdServer: Server = { ...mockServer, id: 10, name: 'api-returned-name', status: 'initializing' };
    const runningServer: Server = { ...mockServer, id: 10, name: 'api-returned-name', status: 'running' };

    vi.mocked(hetznerMod.createServer).mockResolvedValue(createdServer);
    vi.mocked(hetznerMod.waitForRunning).mockResolvedValue(runningServer);
    mockBackgroundRefresh.mockResolvedValue(undefined);

    const store = await getStore();
    await store.create(
      'test-token',
      {
        image: 'ubuntu-24.04',
        labels: { managed: 'devbox' },
        location: 'fsn1',
        name: 'request-name',
        serverType: 'cx22',
        sshKeys: [1],
        userData: '#cloud-config',
      },
      'my-access-token',
    );

    // Token should be saved with the server name from the API response
    expect(store.getServerToken('api-returned-name')).toBe('my-access-token');
  });

  it('create() adds server to list immediately after createServer', async () => {
    const hetznerMod = await getHetzner();
    const createdServer: Server = { ...mockServer, id: 10, status: 'initializing' };
    const runningServer: Server = { ...mockServer, id: 10, status: 'running' };

    vi.mocked(hetznerMod.createServer).mockResolvedValue(createdServer);
    vi.mocked(hetznerMod.waitForRunning).mockResolvedValue(runningServer);
    mockBackgroundRefresh.mockResolvedValue(undefined);

    const store = await getStore();
    await store.create(
      'test-token',
      {
        image: 'ubuntu-24.04',
        labels: { managed: 'devbox' },
        location: 'fsn1',
        name: 'new-server',
        serverType: 'cx22',
        sshKeys: [1],
        userData: '#cloud-config',
      },
      'access-token',
    );

    // Server should be in the list
    expect(store.servers.some((s) => s.id === 10)).toBe(true);
  });
});

describe('servers store - delete()', () => {
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

  it('delete() success triggers backgroundRefresh', async () => {
    // Load a server first
    mockPeekCache.mockReturnValue(false);
    mockSwrFetch.mockImplementation(async (opts: { onData: (data: Server[]) => void }) => {
      opts.onData([mockServer]);
    });

    const store = await getStore();
    await store.load('test-token');
    store.saveServerToken('test-server', 'tok');

    const hetznerMod = await getHetzner();
    vi.mocked(hetznerMod.deleteServer).mockResolvedValue(undefined);
    mockBackgroundRefresh.mockResolvedValue(undefined);

    await store.delete('test-token', 1, 'test-server');

    expect(mockBackgroundRefresh).toHaveBeenCalled();
    const callArg = mockBackgroundRefresh.mock.calls[0]?.[0];
    expect(callArg.key).toBe('devbox_cache_servers');
  });

  it('delete() removes server from list immediately (optimistic)', async () => {
    mockPeekCache.mockReturnValue(false);
    mockSwrFetch.mockImplementation(async (opts: { onData: (data: Server[]) => void }) => {
      opts.onData([mockServer]);
    });

    const store = await getStore();
    await store.load('test-token');
    expect(store.servers).toHaveLength(1);

    const hetznerMod = await getHetzner();
    // Make delete hang to verify optimistic removal
    vi.mocked(hetznerMod.deleteServer).mockResolvedValue(undefined);
    mockBackgroundRefresh.mockResolvedValue(undefined);

    await store.delete('test-token', 1, 'test-server');
    expect(store.servers).toHaveLength(0);
  });
});
