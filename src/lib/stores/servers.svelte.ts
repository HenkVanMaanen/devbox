// Servers store using Svelte 5 runes

import type { Server, ServerType, Location, Image } from '$lib/types';
import * as hetzner from '$lib/api/hetzner';
import { load, save } from '$lib/utils/storage';

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
      return servers.filter((s) => s.labels?.managed === 'devbox');
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

      loading = true;
      error = null;

      try {
        const allServers = await hetzner.listServers(token);
        servers = allServers.filter((s) => s.labels?.managed === 'devbox');
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
        const [types, locs, imgs] = await Promise.all([
          hetzner.listServerTypes(token),
          hetzner.listLocations(token),
          hetzner.listImages(token),
        ]);
        serverTypes = types;
        locations = locs;
        images = imgs;
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

        createProgress = 'Waiting for server to start...';
        const running = await hetzner.waitForRunning(token, server.id);

        // Save access token locally
        this.saveServerToken(running.name, accessToken);

        // Refresh server list
        await this.load(token);

        return running;
      } finally {
        creating = false;
        createProgress = '';
      }
    },

    // Delete a server
    async delete(token: string, id: number, name: string): Promise<void> {
      loading = true;
      try {
        await hetzner.deleteServer(token, id);
        this.removeServerToken(name);
        await this.load(token);
      } finally {
        loading = false;
      }
    },

    // Clear options (e.g., when token changes)
    clearOptions(): void {
      serverTypes = [];
      locations = [];
      images = [];
    },
  };
}

export const serversStore = createServersStore();
