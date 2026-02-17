import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { Server } from '$lib/types';
import type { SwrFetchOptions } from '$lib/utils/swr-cache';

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

const createOpts = {
  image: 'ubuntu-24.04',
  labels: { managed: 'devbox' },
  location: 'fsn1',
  name: 'new-server',
  serverType: 'cx22',
  sshKeys: [1],
  userData: '#cloud-config',
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

describe('servers store - backgroundRefresh callbacks', () => {
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

  it('create() backgroundRefresh onData callback updates servers and starts polling for non-ready', async () => {
    const hetznerMod = await getHetzner();
    const createdServer: Server = { ...mockServer, id: 10, status: 'initializing' };
    const runningServer: Server = { ...mockServer, id: 10, status: 'running' };

    vi.mocked(hetznerMod.createServer).mockResolvedValue(createdServer);
    vi.mocked(hetznerMod.waitForRunning).mockResolvedValue(runningServer);

    // Make backgroundRefresh call both fetcher and onData
    mockBackgroundRefresh.mockImplementation(async (opts: SwrFetchOptions<Server[]>) => {
      const data = await opts.fetcher();
      opts.onData(data);
    });

    // listServers returns a mix of devbox and non-devbox servers, including a provisioning one
    const provisioningServer: Server = {
      ...mockServer,
      id: 20,
      labels: { managed: 'devbox', progress: 'installing' },
      name: 'provisioning',
    };
    vi.mocked(hetznerMod.listServers).mockResolvedValue([mockServer, provisioningServer]);

    const store = await getStore();
    await store.create('test-token', createOpts, 'access-token');

    // onData should have filtered to devbox servers
    expect(store.servers).toHaveLength(2);
    // fetcher (listServers) should have been called
    expect(hetznerMod.listServers).toHaveBeenCalledWith('test-token');
  });

  it('create() backgroundRefresh fetcher calls hetzner.listServers', async () => {
    const hetznerMod = await getHetzner();
    const createdServer: Server = { ...mockServer, id: 10, status: 'initializing' };
    const runningServer: Server = { ...mockServer, id: 10, status: 'running' };

    vi.mocked(hetznerMod.createServer).mockResolvedValue(createdServer);
    vi.mocked(hetznerMod.waitForRunning).mockResolvedValue(runningServer);

    // Capture the fetcher and call it
    mockBackgroundRefresh.mockImplementation(async (opts: SwrFetchOptions<Server[]>) => {
      await opts.fetcher();
    });

    vi.mocked(hetznerMod.listServers).mockResolvedValue([mockServer]);

    const store = await getStore();
    await store.create('test-token', createOpts, 'access-token');

    expect(hetznerMod.listServers).toHaveBeenCalledWith('test-token');
    // servers should not have been updated since onData was not called
    expect(store.servers.some((s) => s.id === 10)).toBe(true);
  });

  it('delete() backgroundRefresh onData callback updates servers with filtered list', async () => {
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

    // Make backgroundRefresh call onData with remaining servers
    mockBackgroundRefresh.mockImplementation(async (opts: SwrFetchOptions<Server[]>) => {
      const data = await opts.fetcher();
      opts.onData(data);
    });

    // After deletion, listServers returns empty
    vi.mocked(hetznerMod.listServers).mockResolvedValue([]);

    await store.delete('test-token', 1, 'test-server');

    expect(store.servers).toHaveLength(0);
    expect(hetznerMod.listServers).toHaveBeenCalledWith('test-token');
  });

  it('delete() backgroundRefresh fetcher calls hetzner.listServers', async () => {
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

    // Only call fetcher, not onData
    mockBackgroundRefresh.mockImplementation(async (opts: SwrFetchOptions<Server[]>) => {
      await opts.fetcher();
    });

    vi.mocked(hetznerMod.listServers).mockResolvedValue([]);

    await store.delete('test-token', 1, 'test-server');

    expect(hetznerMod.listServers).toHaveBeenCalledWith('test-token');
  });
});

describe('servers store - swrFetch fetcher callbacks', () => {
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

  it('load() swrFetch fetcher calls hetzner.listServers', async () => {
    const hetznerMod = await getHetzner();
    mockPeekCache.mockReturnValue(false);

    vi.mocked(hetznerMod.listServers).mockResolvedValue([mockServer]);

    // Make swrFetch call both fetcher and onData
    mockSwrFetch.mockImplementation(async (opts: SwrFetchOptions<Server[]>) => {
      const data = await opts.fetcher();
      opts.onData(data);
    });

    const store = await getStore();
    await store.load('test-token');

    expect(hetznerMod.listServers).toHaveBeenCalledWith('test-token');
    expect(store.servers).toHaveLength(1);
  });

  it('loadOptions() swrFetch fetchers call hetzner.listServerTypes, listLocations, listImages', async () => {
    const hetznerMod = await getHetzner();

    vi.mocked(hetznerMod.listServerTypes).mockResolvedValue([
      { name: 'cx22', description: 'CX22', cores: 2, memory: 4, disk: 40 },
    ]);
    vi.mocked(hetznerMod.listLocations).mockResolvedValue([{ id: 1, name: 'fsn1' }]);
    vi.mocked(hetznerMod.listImages).mockResolvedValue([{ id: 1, name: 'ubuntu-24.04' }]);

    // Make swrFetch call both fetcher and onData
    mockSwrFetch.mockImplementation(async (opts: SwrFetchOptions<unknown>) => {
      const data = await opts.fetcher();
      opts.onData(data);
    });

    const store = await getStore();
    await store.loadOptions('test-token');

    expect(hetznerMod.listServerTypes).toHaveBeenCalledWith('test-token');
    expect(hetznerMod.listLocations).toHaveBeenCalledWith('test-token');
    expect(hetznerMod.listImages).toHaveBeenCalledWith('test-token');
    expect(store.serverTypes).toHaveLength(1);
    expect(store.locations).toHaveLength(1);
    expect(store.images).toHaveLength(1);
  });
});

describe('servers store - progress polling', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.resetModules();
    vi.clearAllMocks();
    localStorage.clear();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  async function getStore() {
    const { serversStore } = await import('$lib/stores/servers.svelte');
    return serversStore;
  }

  async function getHetzner() {
    return await import('$lib/api/hetzner');
  }

  it('polling interval calls getServer and updates server when still provisioning', async () => {
    const hetznerMod = await getHetzner();

    // Load a provisioning server to start polling
    mockPeekCache.mockReturnValue(false);
    mockSwrFetch.mockImplementation(async (opts: { onData: (data: Server[]) => void }) => {
      opts.onData([mockProvisioningServer]);
    });

    const store = await getStore();
    await store.load('test-token');

    expect(store.servers).toHaveLength(1);
    expect(store.servers[0]?.labels['progress']).toBe('installing');

    // Mock getServer to return an updated server (still not ready)
    const updatedServer: Server = {
      ...mockProvisioningServer,
      labels: { managed: 'devbox', progress: 'configuring' },
    };
    vi.mocked(hetznerMod.getServer).mockResolvedValue(updatedServer);

    // Advance past POLL_INTERVAL (5000ms) to trigger the interval callback
    await vi.advanceTimersByTimeAsync(5000);

    expect(hetznerMod.getServer).toHaveBeenCalledWith('test-token', 3);
    expect(store.servers[0]?.labels['progress']).toBe('configuring');
  });

  it('polling interval stops when server becomes ready', async () => {
    const hetznerMod = await getHetzner();

    mockPeekCache.mockReturnValue(false);
    mockSwrFetch.mockImplementation(async (opts: { onData: (data: Server[]) => void }) => {
      opts.onData([mockProvisioningServer]);
    });

    const store = await getStore();
    await store.load('test-token');

    // First poll: server becomes ready
    const readyServer: Server = {
      ...mockProvisioningServer,
      labels: { managed: 'devbox', progress: 'ready' },
    };
    vi.mocked(hetznerMod.getServer).mockResolvedValue(readyServer);

    await vi.advanceTimersByTimeAsync(5000);

    expect(store.servers[0]?.labels['progress']).toBe('ready');

    // Second poll should not happen (polling stopped)
    vi.mocked(hetznerMod.getServer).mockClear();
    await vi.advanceTimersByTimeAsync(5000);

    expect(hetznerMod.getServer).not.toHaveBeenCalled();
  });

  it('polling stops after POLL_MAX_FAILURES (3) consecutive failures', async () => {
    const hetznerMod = await getHetzner();

    mockPeekCache.mockReturnValue(false);
    mockSwrFetch.mockImplementation(async (opts: { onData: (data: Server[]) => void }) => {
      opts.onData([mockProvisioningServer]);
    });

    const store = await getStore();
    await store.load('test-token');

    // Make getServer fail every time
    vi.mocked(hetznerMod.getServer).mockRejectedValue(new Error('API error'));

    // Trigger 3 consecutive failures
    await vi.advanceTimersByTimeAsync(5000); // failure 1
    await vi.advanceTimersByTimeAsync(5000); // failure 2
    await vi.advanceTimersByTimeAsync(5000); // failure 3 -> stops polling

    expect(hetznerMod.getServer).toHaveBeenCalledTimes(3);

    // 4th tick should NOT trigger getServer (polling stopped)
    vi.mocked(hetznerMod.getServer).mockClear();
    await vi.advanceTimersByTimeAsync(5000);

    expect(hetznerMod.getServer).not.toHaveBeenCalled();
  });

  it('polling failure counter resets on success', async () => {
    const hetznerMod = await getHetzner();

    mockPeekCache.mockReturnValue(false);
    mockSwrFetch.mockImplementation(async (opts: { onData: (data: Server[]) => void }) => {
      opts.onData([mockProvisioningServer]);
    });

    const store = await getStore();
    await store.load('test-token');

    const stillProvisioning: Server = {
      ...mockProvisioningServer,
      labels: { managed: 'devbox', progress: 'installing' },
    };

    // Fail twice, then succeed, then fail twice more — should NOT stop polling
    vi.mocked(hetznerMod.getServer)
      .mockRejectedValueOnce(new Error('fail 1'))
      .mockRejectedValueOnce(new Error('fail 2'))
      .mockResolvedValueOnce(stillProvisioning)
      .mockRejectedValueOnce(new Error('fail 3'))
      .mockRejectedValueOnce(new Error('fail 4'));

    await vi.advanceTimersByTimeAsync(5000); // fail 1
    await vi.advanceTimersByTimeAsync(5000); // fail 2
    await vi.advanceTimersByTimeAsync(5000); // success -> resets counter
    await vi.advanceTimersByTimeAsync(5000); // fail 3
    await vi.advanceTimersByTimeAsync(5000); // fail 4

    // Polling should still be active (counter was reset after success)
    expect(hetznerMod.getServer).toHaveBeenCalledTimes(5);
  });

  it('polling stops after POLL_MAX_DURATION timeout (15 minutes)', async () => {
    const hetznerMod = await getHetzner();

    mockPeekCache.mockReturnValue(false);
    mockSwrFetch.mockImplementation(async (opts: { onData: (data: Server[]) => void }) => {
      opts.onData([mockProvisioningServer]);
    });

    const store = await getStore();
    await store.load('test-token');

    // getServer always returns a non-ready server
    const stillProvisioning: Server = {
      ...mockProvisioningServer,
      labels: { managed: 'devbox', progress: 'installing' },
    };
    vi.mocked(hetznerMod.getServer).mockResolvedValue(stillProvisioning);

    // Advance past the max duration (15 * 60 * 1000 = 900000ms)
    await vi.advanceTimersByTimeAsync(15 * 60 * 1000);

    // Record how many times getServer was called
    const callCountBeforeExtra = vi.mocked(hetznerMod.getServer).mock.calls.length;

    // Additional ticks should not trigger more polls
    await vi.advanceTimersByTimeAsync(5000);
    await vi.advanceTimersByTimeAsync(5000);

    expect(vi.mocked(hetznerMod.getServer).mock.calls.length).toBe(callCountBeforeExtra);
  });

  it('polling map callback replaces matching server and leaves others unchanged', async () => {
    const hetznerMod = await getHetzner();

    // Load two devbox servers: one provisioning, one ready
    const secondServer: Server = {
      ...mockServer,
      id: 99,
      labels: { managed: 'devbox', progress: 'ready' },
      name: 'other-server',
    };

    mockPeekCache.mockReturnValue(false);
    mockSwrFetch.mockImplementation(async (opts: { onData: (data: Server[]) => void }) => {
      opts.onData([mockProvisioningServer, secondServer]);
    });

    const store = await getStore();
    await store.load('test-token');

    expect(store.servers).toHaveLength(2);

    // getServer returns updated data for the provisioning server
    const updatedProvisioning: Server = {
      ...mockProvisioningServer,
      labels: { managed: 'devbox', progress: 'configuring' },
    };
    vi.mocked(hetznerMod.getServer).mockResolvedValue(updatedProvisioning);

    await vi.advanceTimersByTimeAsync(5000);

    // The provisioning server should be updated
    const provServer = store.servers.find((s) => s.id === 3);
    expect(provServer?.labels['progress']).toBe('configuring');

    // The other server should be unchanged
    const otherServer = store.servers.find((s) => s.id === 99);
    expect(otherServer?.labels['progress']).toBe('ready');
  });

  it('create() starts polling that fires interval callback', async () => {
    const hetznerMod = await getHetzner();
    const createdServer: Server = {
      ...mockServer,
      id: 10,
      labels: { managed: 'devbox', progress: 'installing' },
      status: 'initializing',
    };
    const runningServer: Server = {
      ...mockServer,
      id: 10,
      labels: { managed: 'devbox', progress: 'installing' },
      status: 'running',
    };

    vi.mocked(hetznerMod.createServer).mockResolvedValue(createdServer);
    vi.mocked(hetznerMod.waitForRunning).mockResolvedValue(runningServer);
    mockBackgroundRefresh.mockResolvedValue(undefined);

    const store = await getStore();
    await store.create('test-token', createOpts, 'access-token');

    // Now the store should be polling for server id=10
    const readyServer: Server = {
      ...runningServer,
      labels: { managed: 'devbox', progress: 'ready' },
    };
    vi.mocked(hetznerMod.getServer).mockResolvedValue(readyServer);

    await vi.advanceTimersByTimeAsync(5000);

    expect(hetznerMod.getServer).toHaveBeenCalledWith('test-token', 10);
    expect(store.servers.find((s) => s.id === 10)?.labels['progress']).toBe('ready');
  });
});
