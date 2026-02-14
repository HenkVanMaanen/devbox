// Hetzner Cloud API client

import type { Image, Location, Server, ServerType } from '$lib/types';

const API_BASE = 'https://api.hetzner.cloud/v1';

export interface CreateServerOptions {
  image: string;
  labels?: Record<string, string>;
  location: string;
  name: string;
  serverType: string;
  sshKeys: number[];
  userData: string;
}

// SSH Keys
export interface HetznerSSHKey {
  fingerprint: string;
  id: number;
  name: string;
  public_key: string;
}

class HetznerApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = 'HetznerApiError';
  }
}

export async function createServer(token: string, opts: CreateServerOptions): Promise<Server> {
  const data = await request<{ server: Server }>(token, '/servers', {
    body: JSON.stringify({
      image: opts.image,
      labels: opts.labels ?? {},
      location: opts.location,
      name: opts.name,
      server_type: opts.serverType,
      ssh_keys: opts.sshKeys,
      start_after_create: true,
      user_data: opts.userData,
    }),
    method: 'POST',
  });
  return data.server;
}

export async function createSSHKey(token: string, name: string, publicKey: string): Promise<HetznerSSHKey> {
  const data = await request<{ ssh_key: HetznerSSHKey }>(token, '/ssh_keys', {
    body: JSON.stringify({ name, public_key: publicKey }),
    method: 'POST',
  });
  return data.ssh_key;
}

export async function deleteServer(token: string, id: number): Promise<void> {
  await request(token, `/servers/${id}`, { method: 'DELETE' });
}

export async function ensureSSHKey(token: string, name: string, publicKey: string): Promise<HetznerSSHKey> {
  // Normalize: compare only key type + key data, ignore comments and extra whitespace
  const normalize = (k: string) => k.trim().split(/\s+/).slice(0, 2).join(' ');
  const keys = await listSSHKeys(token);
  const existing = keys.find((k) => normalize(k.public_key) === normalize(publicKey));
  if (existing) return existing;
  try {
    return await createSSHKey(token, name, publicKey);
  } catch (error) {
    // Handle race condition or normalization mismatch — re-fetch and match
    if (error instanceof Error && error.message.includes('uniqueness_error')) {
      const refreshed = await listSSHKeys(token);
      const match = refreshed.find((k) => normalize(k.public_key) === normalize(publicKey));
      if (match) return match;
    }
    throw error;
  }
}

export async function getServer(token: string, serverId: number): Promise<Server> {
  const data = await request<{ server: Server }>(token, `/servers/${serverId}`);
  return data.server;
}

// Images
export async function listImages(token: string): Promise<Image[]> {
  const data = await request<{ images: Image[] }>(token, '/images?type=system');
  return data.images;
}

// Locations
export async function listLocations(token: string): Promise<Location[]> {
  const data = await request<{ locations: Location[] }>(token, '/locations');
  return data.locations;
}

// Servers
export async function listServers(token: string): Promise<Server[]> {
  const data = await request<{ servers: Server[] }>(token, '/servers');
  return data.servers;
}

// Server Types
export async function listServerTypes(token: string): Promise<ServerType[]> {
  const data = await request<{ server_types: ServerType[] }>(token, '/server_types');
  return data.server_types;
}

export async function listSSHKeys(token: string): Promise<HetznerSSHKey[]> {
  const data = await request<{ ssh_keys: HetznerSSHKey[] }>(token, '/ssh_keys');
  return data.ssh_keys;
}

export async function rebuildServer(token: string, id: number, image: string): Promise<void> {
  await request(token, `/servers/${id}/actions/rebuild`, {
    body: JSON.stringify({ image }),
    method: 'POST',
  });
}

// Token validation
export async function validateToken(token: string): Promise<boolean> {
  try {
    await request(token, '/servers?per_page=1');
    return true;
  } catch {
    return false;
  }
}

export async function waitForRunning(
  token: string,
  serverId: number,
  maxAttempts = 60,
  interval = 2000,
): Promise<Server> {
  for (let i = 0; i < maxAttempts; i++) {
    const server = await getServer(token, serverId);
    if (server.status === 'running') {
      return server;
    }
    await new Promise((resolve) => setTimeout(resolve, interval));
  }
  throw new Error('Timeout waiting for server to start');
}

async function request<T>(token: string, endpoint: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
  };
  if (options.headers) {
    Object.assign(headers, options.headers);
  }

  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    const error = (await res.json().catch(() => ({ error: { message: res.statusText } }))) as {
      error?: { message?: string };
    };
    throw new HetznerApiError(res.status, error.error?.message ?? res.statusText);
  }

  if (res.status === 204) {
    return {} as T;
  }

  return res.json() as Promise<T>;
}
