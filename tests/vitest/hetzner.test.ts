import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import * as hetzner from '$lib/api/hetzner';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const originalFetch = globalThis.fetch;

/** Build a mock fetch that resolves with the given body and status. */
function mockFetch(body: unknown, status = 200) {
  globalThis.fetch = (() =>
    Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      statusText: 'OK',
      json: () => Promise.resolve(body),
    })) as typeof globalThis.fetch;
}

/** Build a mock fetch whose json() rejects (simulates broken JSON response). */
function mockFetchJsonFails(status = 500) {
  globalThis.fetch = (() =>
    Promise.resolve({
      ok: false,
      status,
      statusText: 'Internal Server Error',
      json: () => Promise.reject(new Error('json parse error')),
    })) as typeof globalThis.fetch;
}

// ---------------------------------------------------------------------------
// Mock data — minimal objects that satisfy the Zod schemas
// ---------------------------------------------------------------------------

const mockServer = {
  id: 1,
  name: 'test',
  status: 'running',
  created: '2024-01-01',
  labels: { managed: 'devbox' },
  datacenter: { name: 'fsn1-dc14', location: { city: 'Falkenstein', country: 'DE' } },
  public_net: { ipv4: { ip: '1.2.3.4' }, ipv6: { ip: '2001:db8::1' } },
  server_type: { name: 'cx22', description: 'CX22', cores: 2, memory: 4, disk: 40 },
};

const mockSSHKey = {
  id: 42,
  name: 'my-key',
  fingerprint: 'aa:bb:cc',
  public_key: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@dev',
};

const mockImage = {
  id: 1,
  name: 'ubuntu-24.04',
  description: 'Ubuntu 24.04',
  os_flavor: 'ubuntu',
  os_version: '24.04',
  type: 'system',
};

const mockLocation = {
  id: 1,
  name: 'fsn1',
  description: 'Falkenstein 1',
  city: 'Falkenstein',
  country: 'DE',
};

const mockServerType = {
  id: 1,
  name: 'cx22',
  description: 'CX22',
  cores: 2,
  memory: 4,
  disk: 40,
  prices: [
    {
      location: 'fsn1',
      price_hourly: { gross: '0.0080' },
      price_monthly: { gross: '5.39' },
    },
  ],
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('hetzner API client', () => {
  beforeEach(() => {
    // Ensure a clean state — restore original fetch before each test
    globalThis.fetch = originalFetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  // -----------------------------------------------------------------------
  // request() internals — tested indirectly through exported functions
  // -----------------------------------------------------------------------

  describe('request (internal)', () => {
    it('sets Authorization Bearer header', async () => {
      let capturedHeaders: Record<string, string> = {};
      globalThis.fetch = ((_url: unknown, opts: { headers: Record<string, string> }) => {
        capturedHeaders = opts.headers;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ servers: [] }),
        });
      }) as typeof globalThis.fetch;

      await hetzner.listServers('test-token-123');
      expect(capturedHeaders['Authorization']).toBe('Bearer test-token-123');
      expect(capturedHeaders['Content-Type']).toBe('application/json');
    });

    it('throws HetznerApiError with message from error response', async () => {
      mockFetch({ error: { message: 'server not found' } }, 404);

      await expect(hetzner.getServer('tok', 999)).rejects.toThrow('server not found');
      try {
        await hetzner.getServer('tok', 999);
      } catch (err) {
        expect((err as { name: string }).name).toBe('HetznerApiError');
        expect((err as { status: number }).status).toBe(404);
      }
    });

    it('throws HetznerApiError with statusText when error JSON parsing fails', async () => {
      mockFetchJsonFails(502);

      try {
        await hetzner.getServer('tok', 1);
        expect.fail('Should have thrown');
      } catch (err) {
        expect((err as { name: string }).name).toBe('HetznerApiError');
        expect((err as { status: number }).status).toBe(502);
        expect((err as Error).message).toBe('Internal Server Error');
      }
    });
  });

  // -----------------------------------------------------------------------
  // validate() internals — tested indirectly
  // -----------------------------------------------------------------------

  describe('validate (internal)', () => {
    it('throws HetznerApiError on Zod validation failure', async () => {
      // Return a server with missing required fields to trigger Zod error
      mockFetch({ server: { id: 'not-a-number' } });

      try {
        await hetzner.getServer('tok', 1);
        expect.fail('Should have thrown');
      } catch (err) {
        expect((err as { name: string }).name).toBe('HetznerApiError');
        expect((err as { status: number }).status).toBe(0);
        expect((err as Error).message).toMatch(/^Invalid API response:/);
      }
    });
  });

  // -----------------------------------------------------------------------
  // createServer
  // -----------------------------------------------------------------------

  describe('createServer', () => {
    it('sends POST with correct body and returns validated server', async () => {
      let capturedUrl = '';
      let capturedOpts: { method: string; body: string } = { method: '', body: '' };
      globalThis.fetch = ((url: string, opts: { method: string; body: string }) => {
        capturedUrl = url;
        capturedOpts = opts;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ server: mockServer }),
        });
      }) as typeof globalThis.fetch;

      const result = await hetzner.createServer('tok', {
        image: 'ubuntu-24.04',
        labels: { managed: 'devbox' },
        location: 'fsn1',
        name: 'test',
        serverType: 'cx22',
        sshKeys: [42],
        userData: '#cloud-config',
      });

      expect(capturedOpts.method).toBe('POST');
      expect(capturedUrl.endsWith('/servers')).toBe(true);

      const body = JSON.parse(capturedOpts.body);
      expect(body.name).toBe('test');
      expect(body.server_type).toBe('cx22');
      expect(body.image).toBe('ubuntu-24.04');
      expect(body.location).toBe('fsn1');
      expect(body.ssh_keys).toEqual([42]);
      expect(body.start_after_create).toBe(true);
      expect(body.user_data).toBe('#cloud-config');

      expect(result.id).toBe(1);
      expect(result.name).toBe('test');
    });

    it('throws on API error', async () => {
      mockFetch({ error: { message: 'insufficient funds' } }, 402);

      try {
        await hetzner.createServer('tok', {
          image: 'ubuntu-24.04',
          location: 'fsn1',
          name: 'test',
          serverType: 'cx22',
          sshKeys: [],
          userData: '',
        });
        expect.fail('Should have thrown');
      } catch (err) {
        expect((err as { name: string }).name).toBe('HetznerApiError');
        expect((err as { status: number }).status).toBe(402);
        expect((err as Error).message).toBe('insufficient funds');
      }
    });
  });

  // -----------------------------------------------------------------------
  // createSSHKey
  // -----------------------------------------------------------------------

  describe('createSSHKey', () => {
    it('sends POST and returns validated key', async () => {
      let capturedOpts: { method: string; body: string } = { method: '', body: '' };
      globalThis.fetch = ((_url: unknown, opts: { method: string; body: string }) => {
        capturedOpts = opts;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ ssh_key: mockSSHKey }),
        });
      }) as typeof globalThis.fetch;

      const result = await hetzner.createSSHKey('tok', 'my-key', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@dev');

      expect(capturedOpts.method).toBe('POST');
      const body = JSON.parse(capturedOpts.body);
      expect(body.name).toBe('my-key');
      expect(body.public_key).toBe('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@dev');

      expect(result.id).toBe(42);
      expect(result.name).toBe('my-key');
      expect(result.fingerprint).toBe('aa:bb:cc');
    });
  });

  // -----------------------------------------------------------------------
  // deleteServer
  // -----------------------------------------------------------------------

  describe('deleteServer', () => {
    it('sends DELETE request', async () => {
      let capturedUrl = '';
      let capturedOpts: { method: string } = { method: '' };
      globalThis.fetch = ((url: string, opts: { method: string }) => {
        capturedUrl = url;
        capturedOpts = opts;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({}),
        });
      }) as typeof globalThis.fetch;

      await hetzner.deleteServer('tok', 123);

      expect(capturedOpts.method).toBe('DELETE');
      expect(capturedUrl.endsWith('/servers/123')).toBe(true);
    });

    it('handles 204 No Content response', async () => {
      globalThis.fetch = (() =>
        Promise.resolve({
          ok: true,
          status: 204,
          json: () => Promise.reject(new Error('no body')),
        })) as typeof globalThis.fetch;

      // Should not throw — 204 is handled by returning {}
      await hetzner.deleteServer('tok', 123);
    });
  });

  // -----------------------------------------------------------------------
  // ensureSSHKey
  // -----------------------------------------------------------------------

  describe('ensureSSHKey', () => {
    it('returns existing key when found', async () => {
      mockFetch({ ssh_keys: [mockSSHKey] });

      const result = await hetzner.ensureSSHKey('tok', 'my-key', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@dev');

      expect(result.id).toBe(42);
      expect(result.name).toBe('my-key');
    });

    it('creates new key when not found', async () => {
      let callCount = 0;
      globalThis.fetch = (() => {
        callCount++;
        if (callCount === 1) {
          // listSSHKeys — no matching key
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ ssh_keys: [] }),
          });
        }
        // createSSHKey
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ ssh_key: mockSSHKey }),
        });
      }) as typeof globalThis.fetch;

      const result = await hetzner.ensureSSHKey('tok', 'my-key', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@dev');

      expect(callCount).toBe(2);
      expect(result.id).toBe(42);
    });

    it('handles uniqueness_error race condition by re-fetching', async () => {
      let callCount = 0;
      globalThis.fetch = (() => {
        callCount++;
        if (callCount === 1) {
          // listSSHKeys — empty (key doesn't exist yet)
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ ssh_keys: [] }),
          });
        }
        if (callCount === 2) {
          // createSSHKey — fails with uniqueness_error
          return Promise.resolve({
            ok: false,
            status: 409,
            statusText: 'Conflict',
            json: () => Promise.resolve({ error: { message: 'uniqueness_error' } }),
          });
        }
        // listSSHKeys — now the key exists (created by another request)
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ ssh_keys: [mockSSHKey] }),
        });
      }) as typeof globalThis.fetch;

      const result = await hetzner.ensureSSHKey('tok', 'my-key', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@dev');

      expect(callCount).toBe(3);
      expect(result.id).toBe(42);
    });

    it('throws non-uniqueness errors', async () => {
      let callCount = 0;
      globalThis.fetch = (() => {
        callCount++;
        if (callCount === 1) {
          // listSSHKeys — empty
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ ssh_keys: [] }),
          });
        }
        // createSSHKey — fails with a different error
        return Promise.resolve({
          ok: false,
          status: 403,
          statusText: 'Forbidden',
          json: () => Promise.resolve({ error: { message: 'forbidden' } }),
        });
      }) as typeof globalThis.fetch;

      try {
        await hetzner.ensureSSHKey('tok', 'my-key', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@dev');
        expect.fail('Should have thrown');
      } catch (err) {
        expect((err as { name: string }).name).toBe('HetznerApiError');
        expect((err as { status: number }).status).toBe(403);
        expect((err as Error).message).toBe('forbidden');
      }
    });
  });

  // -----------------------------------------------------------------------
  // getServer
  // -----------------------------------------------------------------------

  describe('getServer', () => {
    it('returns validated server', async () => {
      let capturedUrl = '';
      globalThis.fetch = ((url: string) => {
        capturedUrl = url;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ server: mockServer }),
        });
      }) as typeof globalThis.fetch;

      const result = await hetzner.getServer('tok', 1);

      expect(capturedUrl.endsWith('/servers/1')).toBe(true);
      expect(result.id).toBe(1);
      expect(result.name).toBe('test');
      expect(result.status).toBe('running');
      expect(result.public_net.ipv4.ip).toBe('1.2.3.4');
    });
  });

  // -----------------------------------------------------------------------
  // listImages
  // -----------------------------------------------------------------------

  describe('listImages', () => {
    it('returns validated image array', async () => {
      let capturedUrl = '';
      globalThis.fetch = ((url: string) => {
        capturedUrl = url;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ images: [mockImage] }),
        });
      }) as typeof globalThis.fetch;

      const result = await hetzner.listImages('tok');

      expect(capturedUrl).toContain('/images?type=system');
      expect(result).toHaveLength(1);
      expect(result[0]?.name).toBe('ubuntu-24.04');
      expect(result[0]?.os_flavor).toBe('ubuntu');
    });
  });

  // -----------------------------------------------------------------------
  // listLocations
  // -----------------------------------------------------------------------

  describe('listLocations', () => {
    it('returns validated location array', async () => {
      let capturedUrl = '';
      globalThis.fetch = ((url: string) => {
        capturedUrl = url;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ locations: [mockLocation] }),
        });
      }) as typeof globalThis.fetch;

      const result = await hetzner.listLocations('tok');

      expect(capturedUrl.endsWith('/locations')).toBe(true);
      expect(result).toHaveLength(1);
      expect(result[0]?.name).toBe('fsn1');
      expect(result[0]?.city).toBe('Falkenstein');
    });
  });

  // -----------------------------------------------------------------------
  // listServers
  // -----------------------------------------------------------------------

  describe('listServers', () => {
    it('returns validated server array', async () => {
      mockFetch({ servers: [mockServer] });

      const result = await hetzner.listServers('tok');

      expect(result).toHaveLength(1);
      expect(result[0]?.id).toBe(1);
      expect(result[0]?.name).toBe('test');
    });
  });

  // -----------------------------------------------------------------------
  // listServerTypes
  // -----------------------------------------------------------------------

  describe('listServerTypes', () => {
    it('returns validated server type array', async () => {
      let capturedUrl = '';
      globalThis.fetch = ((url: string) => {
        capturedUrl = url;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ server_types: [mockServerType] }),
        });
      }) as typeof globalThis.fetch;

      const result = await hetzner.listServerTypes('tok');

      expect(capturedUrl.endsWith('/server_types')).toBe(true);
      expect(result).toHaveLength(1);
      expect(result[0]?.name).toBe('cx22');
      expect(result[0]?.cores).toBe(2);
      expect(result[0]?.prices[0]?.price_hourly).toEqual({ gross: '0.0080' });
    });
  });

  // -----------------------------------------------------------------------
  // listSSHKeys
  // -----------------------------------------------------------------------

  describe('listSSHKeys', () => {
    it('returns validated SSH key array', async () => {
      let capturedUrl = '';
      globalThis.fetch = ((url: string) => {
        capturedUrl = url;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ ssh_keys: [mockSSHKey] }),
        });
      }) as typeof globalThis.fetch;

      const result = await hetzner.listSSHKeys('tok');

      expect(capturedUrl.endsWith('/ssh_keys')).toBe(true);
      expect(result).toHaveLength(1);
      expect(result[0]?.id).toBe(42);
      expect(result[0]?.fingerprint).toBe('aa:bb:cc');
    });
  });

  // -----------------------------------------------------------------------
  // rebuildServer
  // -----------------------------------------------------------------------

  describe('rebuildServer', () => {
    it('sends POST with image', async () => {
      let capturedUrl = '';
      let capturedOpts: { method: string; body: string } = { method: '', body: '' };
      globalThis.fetch = ((url: string, opts: { method: string; body: string }) => {
        capturedUrl = url;
        capturedOpts = opts;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({}),
        });
      }) as typeof globalThis.fetch;

      await hetzner.rebuildServer('tok', 5, 'ubuntu-24.04');

      expect(capturedOpts.method).toBe('POST');
      expect(capturedUrl.endsWith('/servers/5/actions/rebuild')).toBe(true);
      const body = JSON.parse(capturedOpts.body);
      expect(body.image).toBe('ubuntu-24.04');
    });
  });

  // -----------------------------------------------------------------------
  // validateToken
  // -----------------------------------------------------------------------

  describe('validateToken', () => {
    it('returns true on success', async () => {
      let capturedUrl = '';
      globalThis.fetch = ((url: string) => {
        capturedUrl = url;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ servers: [] }),
        });
      }) as typeof globalThis.fetch;

      const result = await hetzner.validateToken('good-token');

      expect(result).toBe(true);
      expect(capturedUrl).toContain('/servers?per_page=1');
    });

    it('returns false on failure', async () => {
      mockFetch({ error: { message: 'unauthorized' } }, 401);

      const result = await hetzner.validateToken('bad-token');

      expect(result).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // ensureSSHKey — normalize function edge cases
  // -----------------------------------------------------------------------

  describe('ensureSSHKey normalize', () => {
    it('matches key with extra whitespace between parts', async () => {
      // Key stored on server has single space, input has multiple spaces
      const storedKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@dev';
      const inputKey = 'ssh-ed25519   AAAAC3NzaC1lZDI1NTE5   test@dev';
      mockFetch({ ssh_keys: [{ ...mockSSHKey, public_key: storedKey }] });

      const result = await hetzner.ensureSSHKey('tok', 'my-key', inputKey);
      expect(result.id).toBe(42);
    });

    it('matches key with leading/trailing whitespace', async () => {
      const storedKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@dev';
      const inputKey = '  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@dev  ';
      mockFetch({ ssh_keys: [{ ...mockSSHKey, public_key: storedKey }] });

      const result = await hetzner.ensureSSHKey('tok', 'my-key', inputKey);
      expect(result.id).toBe(42);
    });

    it('ignores comment part when matching', async () => {
      // Same key type+data, different comments — should match
      const storedKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 stored@server';
      const inputKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 different@comment';
      mockFetch({ ssh_keys: [{ ...mockSSHKey, public_key: storedKey }] });

      const result = await hetzner.ensureSSHKey('tok', 'my-key', inputKey);
      expect(result.id).toBe(42);
    });

    it('does not match different key data', async () => {
      const storedKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@dev';
      const inputKey = 'ssh-ed25519 BBBBC3NzaC1lZDI1NTE5 test@dev';
      let callCount = 0;
      globalThis.fetch = (() => {
        callCount++;
        if (callCount === 1) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ ssh_keys: [{ ...mockSSHKey, public_key: storedKey }] }),
          });
        }
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ ssh_key: { ...mockSSHKey, public_key: inputKey } }),
        });
      }) as typeof globalThis.fetch;

      const result = await hetzner.ensureSSHKey('tok', 'my-key', inputKey);
      // Should have created a new key (call count 2)
      expect(callCount).toBe(2);
      expect(result.public_key).toBe(inputKey);
    });

    it('uniqueness_error re-fetch with no match throws', async () => {
      let callCount = 0;
      globalThis.fetch = (() => {
        callCount++;
        if (callCount === 1) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ ssh_keys: [] }),
          });
        }
        if (callCount === 2) {
          return Promise.resolve({
            ok: false,
            status: 409,
            statusText: 'Conflict',
            json: () => Promise.resolve({ error: { message: 'uniqueness_error' } }),
          });
        }
        // Re-fetch returns no matching key either
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ ssh_keys: [{ ...mockSSHKey, public_key: 'ssh-rsa OTHER other@dev' }] }),
        });
      }) as typeof globalThis.fetch;

      await expect(hetzner.ensureSSHKey('tok', 'my-key', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@dev')).rejects.toThrow(
        'uniqueness_error',
      );
    });
  });

  // -----------------------------------------------------------------------
  // createServer labels
  // -----------------------------------------------------------------------

  describe('createServer labels', () => {
    it('sends empty labels when opts.labels is undefined', async () => {
      let capturedBody = '';
      globalThis.fetch = ((_url: unknown, opts: { body: string }) => {
        capturedBody = opts.body;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ server: mockServer }),
        });
      }) as typeof globalThis.fetch;

      await hetzner.createServer('tok', {
        image: 'ubuntu-24.04',
        location: 'fsn1',
        name: 'test',
        serverType: 'cx22',
        sshKeys: [],
        userData: '',
      });

      const body = JSON.parse(capturedBody);
      expect(body.labels).toEqual({});
    });

    it('sends provided labels when opts.labels is set', async () => {
      let capturedBody = '';
      globalThis.fetch = ((_url: unknown, opts: { body: string }) => {
        capturedBody = opts.body;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ server: mockServer }),
        });
      }) as typeof globalThis.fetch;

      await hetzner.createServer('tok', {
        image: 'ubuntu-24.04',
        labels: { managed: 'devbox', progress: 'installing' },
        location: 'fsn1',
        name: 'test',
        serverType: 'cx22',
        sshKeys: [],
        userData: '',
      });

      const body = JSON.parse(capturedBody);
      expect(body.labels).toEqual({ managed: 'devbox', progress: 'installing' });
    });
  });

  // -----------------------------------------------------------------------
  // URL path verification
  // -----------------------------------------------------------------------

  describe('URL paths', () => {
    it('createSSHKey uses /ssh_keys path', async () => {
      let capturedUrl = '';
      globalThis.fetch = ((url: string) => {
        capturedUrl = url;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ ssh_key: mockSSHKey }),
        });
      }) as typeof globalThis.fetch;

      await hetzner.createSSHKey('tok', 'key', 'ssh-ed25519 AAAA test@dev');
      expect(capturedUrl).toContain('/ssh_keys');
    });

    it('listServers uses /servers path', async () => {
      let capturedUrl = '';
      globalThis.fetch = ((url: string) => {
        capturedUrl = url;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ servers: [] }),
        });
      }) as typeof globalThis.fetch;

      await hetzner.listServers('tok');
      expect(capturedUrl).toContain('/servers');
    });
  });

  // -----------------------------------------------------------------------
  // waitForRunning
  // -----------------------------------------------------------------------

  describe('waitForRunning', () => {
    it('returns server when status is running immediately', async () => {
      mockFetch({ server: { ...mockServer, status: 'running' } });

      const result = await hetzner.waitForRunning('tok', 1, 3, 1);

      expect(result.status).toBe('running');
      expect(result.id).toBe(1);
    });

    it('polls until server is running', async () => {
      let callCount = 0;
      globalThis.fetch = (() => {
        callCount++;
        const status = callCount >= 3 ? 'running' : 'initializing';
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ server: { ...mockServer, status } }),
        });
      }) as typeof globalThis.fetch;

      const result = await hetzner.waitForRunning('tok', 1, 5, 1);

      expect(result.status).toBe('running');
      expect(callCount).toBe(3);
    });

    it('throws on timeout', async () => {
      mockFetch({ server: { ...mockServer, status: 'initializing' } });

      await expect(hetzner.waitForRunning('tok', 1, 1, 1)).rejects.toThrow('Timeout');
    });
  });
});
