import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// Mock fetch
let fetchMock;
globalThis.fetch = async (url, options) => fetchMock(url, options);

const hetzner = await import('../web/js/hetzner.js');

describe('hetzner.js', () => {
    beforeEach(() => {
        fetchMock = null;
    });

    function mockFetch(status, body) {
        fetchMock = async (url, options) => ({
            ok: status >= 200 && status < 300,
            status,
            json: async () => body,
        });
    }

    function mockFetchSequence(responses) {
        let call = 0;
        fetchMock = async () => {
            const r = responses[call++] || responses[responses.length - 1];
            return { ok: r.status >= 200 && r.status < 300, status: r.status, json: async () => r.body };
        };
    }

    describe('listServers', () => {
        it('returns server list', async () => {
            mockFetch(200, { servers: [{ id: 1, name: 'test' }] });
            const servers = await hetzner.listServers('token');
            assert.equal(servers.length, 1);
            assert.equal(servers[0].name, 'test');
        });

        it('returns empty array when no servers field', async () => {
            mockFetch(200, {});
            const servers = await hetzner.listServers('token');
            assert.deepEqual(servers, []);
        });

        it('throws on API error', async () => {
            mockFetch(401, { error: { message: 'Unauthorized' } });
            await assert.rejects(
                () => hetzner.listServers('bad-token'),
                { message: 'Unauthorized' }
            );
        });

        it('handles non-JSON error response', async () => {
            fetchMock = async () => ({
                ok: false,
                status: 500,
                json: async () => { throw new Error('not json'); }
            });
            await assert.rejects(
                () => hetzner.listServers('token'),
                { message: 'HTTP 500' }
            );
        });
    });

    describe('getServer', () => {
        it('returns server by ID', async () => {
            mockFetch(200, { server: { id: 42, name: 'mybox' } });
            const server = await hetzner.getServer('token', 42);
            assert.equal(server.id, 42);
        });
    });

    describe('getServerByName', () => {
        it('finds server by name', async () => {
            mockFetch(200, { servers: [{ id: 1, name: 'a' }, { id: 2, name: 'b' }] });
            const server = await hetzner.getServerByName('token', 'b');
            assert.equal(server.id, 2);
        });

        it('returns null when not found', async () => {
            mockFetch(200, { servers: [{ id: 1, name: 'a' }] });
            const server = await hetzner.getServerByName('token', 'missing');
            assert.equal(server, null);
        });
    });

    describe('createServer', () => {
        it('sends correct body', async () => {
            let capturedBody;
            fetchMock = async (url, options) => {
                capturedBody = JSON.parse(options.body);
                return { ok: true, status: 200, json: async () => ({ server: { id: 99 } }) };
            };

            await hetzner.createServer('token', {
                name: 'dev1',
                serverType: 'cpx21',
                image: 'debian-12',
                location: 'fsn1',
                sshKeys: [123],
                userData: '#cloud-config'
            });

            assert.equal(capturedBody.name, 'dev1');
            assert.equal(capturedBody.server_type, 'cpx21');
            assert.equal(capturedBody.image, 'debian-12');
            assert.equal(capturedBody.location, 'fsn1');
            assert.deepEqual(capturedBody.ssh_keys, [123]);
            assert.equal(capturedBody.user_data, '#cloud-config');
        });

        it('omits ssh_keys when empty', async () => {
            let capturedBody;
            fetchMock = async (url, options) => {
                capturedBody = JSON.parse(options.body);
                return { ok: true, status: 200, json: async () => ({ server: { id: 99 } }) };
            };

            await hetzner.createServer('token', {
                name: 'dev1', serverType: 'cpx21', image: 'debian-12', location: 'fsn1', sshKeys: []
            });

            assert.equal(capturedBody.ssh_keys, undefined);
        });

        it('includes labels when provided', async () => {
            let capturedBody;
            fetchMock = async (url, options) => {
                capturedBody = JSON.parse(options.body);
                return { ok: true, status: 200, json: async () => ({ server: { id: 99 } }) };
            };

            await hetzner.createServer('token', {
                name: 'dev1', serverType: 'cpx21', image: 'debian-12', location: 'fsn1',
                labels: { env: 'dev' }
            });

            assert.deepEqual(capturedBody.labels, { env: 'dev' });
        });
    });

    describe('deleteServer', () => {
        it('makes DELETE request', async () => {
            let capturedMethod;
            fetchMock = async (url, options) => {
                capturedMethod = options.method;
                return { ok: true, status: 204, json: async () => ({}) };
            };

            await hetzner.deleteServer('token', 42);
            assert.equal(capturedMethod, 'DELETE');
        });

        it('handles 204 No Content', async () => {
            fetchMock = async () => ({ ok: true, status: 204, json: async () => ({}) });
            // Should not throw
            await hetzner.deleteServer('token', 42);
        });
    });

    describe('listServerTypes', () => {
        it('returns server types', async () => {
            mockFetch(200, { server_types: [{ id: 1, name: 'cpx21' }] });
            const types = await hetzner.listServerTypes('token');
            assert.equal(types[0].name, 'cpx21');
        });
    });

    describe('listLocations', () => {
        it('returns locations', async () => {
            mockFetch(200, { locations: [{ name: 'fsn1', city: 'Falkenstein' }] });
            const locs = await hetzner.listLocations('token');
            assert.equal(locs[0].city, 'Falkenstein');
        });
    });

    describe('listImages', () => {
        it('returns system images', async () => {
            mockFetch(200, { images: [{ id: 1, name: 'debian-12' }] });
            const imgs = await hetzner.listImages('token');
            assert.equal(imgs[0].name, 'debian-12');
        });
    });

    describe('SSH key management', () => {
        it('listSSHKeys returns keys', async () => {
            mockFetch(200, { ssh_keys: [{ id: 1, name: 'dev' }] });
            const keys = await hetzner.listSSHKeys('token');
            assert.equal(keys[0].name, 'dev');
        });

        it('getSSHKeyByName finds key', async () => {
            mockFetch(200, { ssh_keys: [{ id: 1, name: 'dev' }, { id: 2, name: 'other' }] });
            const key = await hetzner.getSSHKeyByName('token', 'dev');
            assert.equal(key.id, 1);
        });

        it('getSSHKeyByName returns null when not found', async () => {
            mockFetch(200, { ssh_keys: [] });
            const key = await hetzner.getSSHKeyByName('token', 'missing');
            assert.equal(key, null);
        });

        it('createSSHKey sends correct data', async () => {
            let body;
            fetchMock = async (url, opts) => {
                body = JSON.parse(opts.body);
                return { ok: true, status: 200, json: async () => ({ ssh_key: { id: 5 } }) };
            };
            const key = await hetzner.createSSHKey('token', 'mykey', 'ssh-ed25519 AAAA');
            assert.equal(body.name, 'mykey');
            assert.equal(body.public_key, 'ssh-ed25519 AAAA');
            assert.equal(key.id, 5);
        });

        it('ensureSSHKey returns existing key', async () => {
            mockFetch(200, { ssh_keys: [{ id: 1, name: 'devbox', public_key: 'ssh-ed25519 AAAA' }] });
            const key = await hetzner.ensureSSHKey('token', 'devbox', 'ssh-ed25519 AAAA');
            assert.equal(key.id, 1);
        });

        it('ensureSSHKey creates when not found', async () => {
            let callCount = 0;
            fetchMock = async (url, opts) => {
                callCount++;
                if (callCount === 1) {
                    return { ok: true, status: 200, json: async () => ({ ssh_keys: [] }) };
                }
                return { ok: true, status: 200, json: async () => ({ ssh_key: { id: 99, name: 'new' } }) };
            };
            const key = await hetzner.ensureSSHKey('token', 'new', 'ssh-ed25519 BBB');
            assert.equal(key.id, 99);
        });
    });

    describe('waitForRunning', () => {
        it('returns server when already running', async () => {
            mockFetch(200, { server: { id: 1, status: 'running' } });
            const server = await hetzner.waitForRunning('token', 1);
            assert.equal(server.status, 'running');
        });

        it('polls until running', async () => {
            let calls = 0;
            fetchMock = async () => {
                calls++;
                const status = calls >= 3 ? 'running' : 'initializing';
                return { ok: true, status: 200, json: async () => ({ server: { id: 1, status } }) };
            };
            const server = await hetzner.waitForRunning('token', 1, 10000);
            assert.equal(server.status, 'running');
            assert.ok(calls >= 3);
        });

        it('throws on timeout', async () => {
            mockFetch(200, { server: { id: 1, status: 'initializing' } });
            await assert.rejects(
                () => hetzner.waitForRunning('token', 1, 100), // 100ms timeout
                { message: 'Timeout waiting for server to start' }
            );
        });

        it('throws immediately on error state', async () => {
            mockFetch(200, { server: { id: 1, status: 'error' } });
            await assert.rejects(
                () => hetzner.waitForRunning('token', 1, 10000),
                { message: 'Server entered error state' }
            );
        });

        it('throws on deleting state', async () => {
            mockFetch(200, { server: { id: 1, status: 'deleting' } });
            await assert.rejects(
                () => hetzner.waitForRunning('token', 1, 10000),
                { message: 'Server entered deleting state' }
            );
        });
    });

    describe('validateToken', () => {
        it('returns true for valid token', async () => {
            mockFetch(200, { servers: [] });
            assert.equal(await hetzner.validateToken('valid'), true);
        });

        it('returns false for invalid token', async () => {
            mockFetch(401, { error: { message: 'Unauthorized' } });
            assert.equal(await hetzner.validateToken('bad'), false);
        });
    });

    describe('formatIPForDNS', () => {
        it('replaces dots with dashes', () => {
            assert.equal(hetzner.formatIPForDNS('192.168.1.1'), '192-168-1-1');
        });

        it('handles already formatted', () => {
            assert.equal(hetzner.formatIPForDNS('10.0.0.1'), '10-0-0-1');
        });
    });

    describe('getServiceURLs', () => {
        const config = {
            services: {
                codeServer: true,
                shellTerminal: true,
                dnsService: 'sslip.io',
                accessToken: 'tok123'
            }
        };

        it('generates correct URLs with port-based format', () => {
            const urls = hetzner.getServiceURLs('dev1', '1.2.3.4', config, 'tok123');
            assert.equal(urls.overview, 'https://devbox:tok123@1-2-3-4.sslip.io/');
            assert.equal(urls.code, 'https://devbox:tok123@65532.1-2-3-4.sslip.io/');
            assert.equal(urls.terminal, 'https://devbox:tok123@65534.1-2-3-4.sslip.io/');
        });

        it('returns null for disabled services', () => {
            const disabledConfig = {
                services: { codeServer: false, shellTerminal: false, dnsService: 'sslip.io' }
            };
            const urls = hetzner.getServiceURLs('dev1', '1.2.3.4', disabledConfig, 'tok');
            assert.equal(urls.code, null);
            assert.equal(urls.terminal, null);
        });

        it('uses config accessToken as fallback', () => {
            const urls = hetzner.getServiceURLs('dev1', '1.2.3.4', config);
            assert.ok(urls.overview.includes('tok123'));
        });

        it('uses custom DNS service', () => {
            const nipConfig = { services: { ...config.services, dnsService: 'nip.io' } };
            const urls = hetzner.getServiceURLs('dev1', '1.2.3.4', nipConfig, 'tok');
            assert.ok(urls.overview.includes('nip.io'));
        });
    });
});
