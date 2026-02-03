// Hetzner Cloud API client - direct browser fetch to api.hetzner.cloud

const API_BASE = 'https://api.hetzner.cloud/v1';

// API request helper
async function apiRequest(token, method, endpoint, body = null) {
    const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
    };

    const options = { method, headers };
    if (body) {
        options.body = JSON.stringify(body);
    }

    const response = await fetch(`${API_BASE}${endpoint}`, options);

    if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.error?.message || `HTTP ${response.status}`);
    }

    // Handle 204 No Content
    if (response.status === 204) {
        return null;
    }

    return response.json();
}

// Paginated GET - fetches all pages for list endpoints
async function apiRequestAll(token, endpoint, resultKey) {
    let allItems = [];
    let page = 1;
    const perPage = 50;

    while (true) {
        const separator = endpoint.includes('?') ? '&' : '?';
        const data = await apiRequest(token, 'GET', `${endpoint}${separator}page=${page}&per_page=${perPage}`);
        const items = data[resultKey] || [];
        allItems = allItems.concat(items);

        if (!data.meta?.pagination || page >= data.meta.pagination.last_page) {
            break;
        }
        page++;
    }

    return allItems;
}

// List all servers
export async function listServers(token) {
    return apiRequestAll(token, '/servers', 'servers');
}

// Get server by ID
export async function getServer(token, serverId) {
    const data = await apiRequest(token, 'GET', `/servers/${serverId}`);
    return data.server;
}

// Get server by name
export async function getServerByName(token, name) {
    const servers = await listServers(token);
    return servers.find(s => s.name === name) || null;
}

// Create server
export async function createServer(token, options) {
    const { name, serverType, image, location, sshKeys, userData, labels } = options;

    const body = {
        name,
        server_type: serverType,
        image,
        location,
        user_data: userData
    };

    // Only include ssh_keys if provided
    if (sshKeys && sshKeys.length > 0) {
        body.ssh_keys = sshKeys;
    }

    if (labels) {
        body.labels = labels;
    }

    const data = await apiRequest(token, 'POST', '/servers', body);
    return data.server;
}

// Delete server
export async function deleteServer(token, serverId) {
    await apiRequest(token, 'DELETE', `/servers/${serverId}`);
}

// List server types
export async function listServerTypes(token) {
    return apiRequestAll(token, '/server_types', 'server_types');
}

// List locations
export async function listLocations(token) {
    return apiRequestAll(token, '/locations', 'locations');
}

// List images (system images only)
export async function listImages(token) {
    return apiRequestAll(token, '/images?type=system&status=available', 'images');
}

// List SSH keys
export async function listSSHKeys(token) {
    return apiRequestAll(token, '/ssh_keys', 'ssh_keys');
}

// Get SSH key by name
export async function getSSHKeyByName(token, name) {
    const keys = await listSSHKeys(token);
    return keys.find(k => k.name === name) || null;
}

// Create SSH key
export async function createSSHKey(token, name, publicKey) {
    const data = await apiRequest(token, 'POST', '/ssh_keys', {
        name,
        public_key: publicKey
    });
    return data.ssh_key;
}

// Update SSH key
export async function updateSSHKey(token, keyId, name, publicKey) {
    await apiRequest(token, 'DELETE', `/ssh_keys/${keyId}`);
    return await createSSHKey(token, name, publicKey);
}

// Ensure SSH key exists (create or update if content changed)
export async function ensureSSHKey(token, name, publicKey) {
    let key = await getSSHKeyByName(token, name);
    if (!key) {
        key = await createSSHKey(token, name, publicKey);
    } else if (key.public_key.trim() !== publicKey.trim()) {
        key = await updateSSHKey(token, key.id, name, publicKey);
    }
    return key;
}

// Poll server until running
export async function waitForRunning(token, serverId, timeoutMs = 120000) {
    const startTime = Date.now();
    const pollInterval = 2000;
    const errorStates = new Set(['error', 'deleting']);

    while (Date.now() - startTime < timeoutMs) {
        const server = await getServer(token, serverId);
        if (server.status === 'running') {
            return server;
        }
        if (errorStates.has(server.status)) {
            throw new Error(`Server entered ${server.status} state`);
        }
        await new Promise(resolve => setTimeout(resolve, pollInterval));
    }

    throw new Error('Timeout waiting for server to start');
}

// Validate token (try listing servers)
export async function validateToken(token) {
    try {
        await listServers(token);
        return true;
    } catch (e) {
        return false;
    }
}

// Format IP for sslip.io (dots to dashes)
export function formatIPForDNS(ip) {
    return ip.replace(/\./g, '-');
}

// Get service URLs for a server
// Domain format: {port}.{ip}.{dns} (e.g., 65532.1-2-3-4.sslip.io)
export function getServiceURLs(serverName, ip, config, accessToken) {
    if (!config?.services) return { overview: null, code: null, terminal: null };
    const ipFormatted = formatIPForDNS(ip);
    const dns = config.services.dnsService || 'sslip.io';
    const token = accessToken || config.services.accessToken;

    const buildURL = (port) => {
        const host = port
            ? `${port}.${ipFormatted}.${dns}`
            : `${ipFormatted}.${dns}`;
        return `https://devbox:${encodeURIComponent(token)}@${host}/`;
    };

    return {
        overview: buildURL(),
        code: config.services.codeServer ? buildURL(65532) : null,
        terminal: config.services.shellTerminal ? buildURL(65534) : null
    };
}
