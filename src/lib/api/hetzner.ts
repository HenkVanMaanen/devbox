// Hetzner Cloud API client

import type { Server, ServerType, Location, Image } from '$lib/types';

const API_BASE = 'https://api.hetzner.cloud/v1';

class HetznerApiError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
    this.name = 'HetznerApiError';
  }
}

async function request<T>(
  token: string,
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: { message: res.statusText } }));
    throw new HetznerApiError(res.status, error.error?.message || res.statusText);
  }

  if (res.status === 204) {
    return {} as T;
  }

  return res.json();
}

// Servers
export async function listServers(token: string): Promise<Server[]> {
  const data = await request<{ servers: Server[] }>(token, '/servers');
  return data.servers;
}

export interface CreateServerOptions {
  name: string;
  serverType: string;
  image: string;
  location: string;
  sshKeys: number[];
  userData: string;
  labels?: Record<string, string>;
}

export async function createServer(token: string, opts: CreateServerOptions): Promise<Server> {
  const data = await request<{ server: Server }>(token, '/servers', {
    method: 'POST',
    body: JSON.stringify({
      name: opts.name,
      server_type: opts.serverType,
      image: opts.image,
      location: opts.location,
      ssh_keys: opts.sshKeys,
      user_data: opts.userData,
      labels: opts.labels || {},
      start_after_create: true,
    }),
  });
  return data.server;
}

export async function deleteServer(token: string, id: number): Promise<void> {
  await request(token, `/servers/${id}`, { method: 'DELETE' });
}

export async function rebuildServer(token: string, id: number, image: string): Promise<void> {
  await request(token, `/servers/${id}/actions/rebuild`, {
    method: 'POST',
    body: JSON.stringify({ image }),
  });
}

export async function waitForRunning(
  token: string,
  serverId: number,
  maxAttempts = 60,
  interval = 2000
): Promise<Server> {
  for (let i = 0; i < maxAttempts; i++) {
    const data = await request<{ server: Server }>(token, `/servers/${serverId}`);
    if (data.server.status === 'running') {
      return data.server;
    }
    await new Promise((resolve) => setTimeout(resolve, interval));
  }
  throw new Error('Timeout waiting for server to start');
}

// Server Types
export async function listServerTypes(token: string): Promise<ServerType[]> {
  const data = await request<{ server_types: ServerType[] }>(token, '/server_types');
  return data.server_types;
}

// Locations
export async function listLocations(token: string): Promise<Location[]> {
  const data = await request<{ locations: Location[] }>(token, '/locations');
  return data.locations;
}

// Images
export async function listImages(token: string): Promise<Image[]> {
  const data = await request<{ images: Image[] }>(token, '/images?type=system');
  return data.images;
}

// SSH Keys
export interface HetznerSSHKey {
  id: number;
  name: string;
  fingerprint: string;
  public_key: string;
}

export async function listSSHKeys(token: string): Promise<HetznerSSHKey[]> {
  const data = await request<{ ssh_keys: HetznerSSHKey[] }>(token, '/ssh_keys');
  return data.ssh_keys;
}

export async function createSSHKey(
  token: string,
  name: string,
  publicKey: string
): Promise<HetznerSSHKey> {
  const data = await request<{ ssh_key: HetznerSSHKey }>(token, '/ssh_keys', {
    method: 'POST',
    body: JSON.stringify({ name, public_key: publicKey }),
  });
  return data.ssh_key;
}

export async function ensureSSHKey(
  token: string,
  name: string,
  publicKey: string
): Promise<HetznerSSHKey> {
  const keys = await listSSHKeys(token);
  const existing = keys.find((k) => k.public_key.trim() === publicKey.trim());
  if (existing) return existing;
  return createSSHKey(token, name, publicKey);
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
