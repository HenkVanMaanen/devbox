// Servers store using Svelte 5 runes

import type { Server, ServerType, Location, Image } from '$lib/types';
import * as hetzner from '$lib/api/hetzner';
import { load, save } from '$lib/utils/storage';
import {
  swrFetch,
  backgroundRefresh,
  peekCache,
  clearSwrCache,
  CACHE_KEYS,
} from '$lib/utils/swr-cache';

const filterDevbox = (allServers: Server[]): Server[] =>
  allServers.filter((s) => s.labels?.['managed'] === 'devbox');

const POLL_INTERVAL = 5000;
const POLL_MAX_DURATION = 15 * 60 * 1000; // 15 minutes
const POLL_MAX_FAILURES = 3;

function createServersStore() {
  let servers = $state<Server[]>([]);
  let serverTypes = $state<ServerType[]>([]);
  let locations = $state<Location[]>([]);
  let images = $state<Image[]>([]);
  let loading = $state(false);
  let creating = $state(false);
  let createProgress = $state('');
  let error = $state<string | null>(null);

  // Server tokens stored separately (not visible in Hetzner API)
  let serverTokens = $state<Record<string, string>>(load('serverTokens') ?? {});

  // Progress polling timers
  const pollingTimers = new Map<number, { interval: ReturnType<typeof setInterval>; timeout: ReturnType<typeof setTimeout> }>();

  function startProgressPolling(token: string, serverId: number): void {
    if (pollingTimers.has(serverId)) return;

    let failures = 0;

    const interval = setInterval(async () => {
      try {
        const updated = await hetzner.getServer(token, serverId);
        failures = 0;
        servers = servers.map((s) => (s.id === serverId ? updated : s));
        if (updated.labels?.['progress'] === 'ready') {
          stopProgressPolling(serverId);
        }
      } catch {
        failures++;
        if (failures >= POLL_MAX_FAILURES) {
          stopProgressPolling(serverId);
        }
      }
    }, POLL_INTERVAL);

    const timeout = setTimeout(() => {
      stopProgressPolling(serverId);
    }, POLL_MAX_DURATION);

    pollingTimers.set(serverId, { interval, timeout });
  }

  function stopProgressPolling(serverId: number): void {
    const entry = pollingTimers.get(serverId);
    if (!entry) return;
    clearInterval(entry.interval);
    clearTimeout(entry.timeout);
    pollingTimers.delete(serverId);
  }

  function stopAllPolling(): void {
    for (const id of [...pollingTimers.keys()]) {
      stopProgressPolling(id);
    }
  }

  return {
    get servers() {
      return servers;
    },
    get serverTypes() {
      return serverTypes;
    },
    get locations() {
      return locations;
    },
    get images() {
      return images;
    },
    get loading() {
      return loading;
    },
    get creating() {
      return creating;
    },
    get createProgress() {
      return createProgress;
    },
    get error() {
      return error;
    },

    // Get devbox servers only
    get devboxServers() {
      return servers.filter((s) => s.labels?.['managed'] === 'devbox');
    },

    // Get all server tokens (for export)
    get serverTokens() {
      return serverTokens;
    },

    // Get server access token
    getServerToken(serverName: string): string | undefined {
      return serverTokens[serverName];
    },

    // Save server access token
    saveServerToken(serverName: string, token: string): void {
      serverTokens[serverName] = token;
      save('serverTokens', serverTokens);
    },

    // Remove server access token
    removeServerToken(serverName: string): void {
      delete serverTokens[serverName];
      save('serverTokens', serverTokens);
    },

    // Load servers from Hetzner
    async load(token: string): Promise<void> {
      if (!token) {
        servers = [];
        error = null;
        return;
      }

      // Only show loading spinner when there's no cached data
      if (!peekCache(CACHE_KEYS.servers, token)) {
        loading = true;
      }
      error = null;

      try {
        await swrFetch({
          key: CACHE_KEYS.servers,
          token,
          fetcher: () => hetzner.listServers(token),
          onData: (allServers) => {
            const devbox = filterDevbox(allServers);
            servers = devbox;
            // Start polling for any server still provisioning
            for (const s of devbox) {
              if (s.labels?.['progress'] && s.labels['progress'] !== 'ready') {
                startProgressPolling(token, s.id);
              }
            }
          },
        });
      } catch (e) {
        error = e instanceof Error ? e.message : 'Failed to load servers';
        servers = [];
      } finally {
        loading = false;
      }
    },

    // Load Hetzner options (server types, locations, images)
    async loadOptions(token: string): Promise<void> {
      if (!token || serverTypes.length > 0) return;

      try {
        await Promise.all([
          swrFetch({
            key: CACHE_KEYS.serverTypes,
            token,
            fetcher: () => hetzner.listServerTypes(token),
            onData: (types) => {
              serverTypes = types;
            },
          }),
          swrFetch({
            key: CACHE_KEYS.locations,
            token,
            fetcher: () => hetzner.listLocations(token),
            onData: (locs) => {
              locations = locs;
            },
          }),
          swrFetch({
            key: CACHE_KEYS.images,
            token,
            fetcher: () => hetzner.listImages(token),
            onData: (imgs) => {
              images = imgs;
            },
          }),
        ]);
      } catch (e) {
        console.error('Failed to load Hetzner options:', e);
      }
    },

    // Create a new server
    async create(
      token: string,
      opts: hetzner.CreateServerOptions,
      accessToken: string
    ): Promise<Server> {
      creating = true;
      createProgress = 'Creating server...';

      try {
        createProgress = 'Provisioning server...';
        const server = await hetzner.createServer(token, opts);

        // Save access token and show server card immediately
        this.saveServerToken(server.name, accessToken);
        servers = [...servers.filter((s) => s.id !== server.id), server];

        createProgress = 'Waiting for server to start...';
        const running = await hetzner.waitForRunning(token, server.id);

        // Update with running server data
        servers = servers.map((s) => (s.id === running.id ? running : s));

        // Start polling for cloud-init progress
        startProgressPolling(token, running.id);

        // Sync cache with API reality in background
        backgroundRefresh({
          key: CACHE_KEYS.servers,
          token,
          fetcher: () => hetzner.listServers(token),
          onData: (allServers) => {
            const devbox = filterDevbox(allServers);
            servers = devbox;
            for (const s of devbox) {
              if (s.labels?.['progress'] && s.labels['progress'] !== 'ready') {
                startProgressPolling(token, s.id);
              }
            }
          },
        });

        return running;
      } finally {
        creating = false;
        createProgress = '';
      }
    },

    // Delete a server (optimistic)
    async delete(token: string, id: number, name: string): Promise<void> {
      // Optimistic: remove server from UI immediately
      const previousServers = [...servers];
      servers = servers.filter((s) => s.id !== id);

      try {
        await hetzner.deleteServer(token, id);
        stopProgressPolling(id);
        this.removeServerToken(name);

        // Sync cache with API reality in background
        backgroundRefresh({
          key: CACHE_KEYS.servers,
          token,
          fetcher: () => hetzner.listServers(token),
          onData: (allServers) => {
            servers = filterDevbox(allServers);
          },
        });
      } catch (e) {
        // Rollback: restore previous server list
        servers = previousServers;
        throw e;
      }
    },

    // Clear options (e.g., when token changes)
    clearOptions(): void {
      stopAllPolling();
      serverTypes = [];
      locations = [];
      images = [];
      clearSwrCache(Object.values(CACHE_KEYS));
    },
  };
}

export const serversStore = createServersStore();
