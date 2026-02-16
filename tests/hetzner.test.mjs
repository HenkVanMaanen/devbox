import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import * as hetzner from '../src/lib/api/hetzner.ts';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const originalFetch = globalThis.fetch;

/** Build a mock fetch that resolves with the given body and status. */
function mockFetch(body, status = 200) {
  globalThis.fetch = () =>
    Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      statusText: 'OK',
      json: () => Promise.resolve(body),
    });
}

/** Build a mock fetch whose json() rejects (simulates broken JSON response). */
function mockFetchJsonFails(status = 500) {
  globalThis.fetch = () =>
    Promise.resolve({
      ok: false,
      status,
      statusText: 'Internal Server Error',
      json: () => Promise.reject(new Error('json parse error')),
    });
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
      let capturedHeaders;
      globalThis.fetch = (_url, opts) => {
        capturedHeaders = opts.headers;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ servers: [] }),
        });
      };

      await hetzner.listServers('test-token-123');
      assert.strictEqual(capturedHeaders['Authorization'], 'Bearer test-token-123');
      assert.strictEqual(capturedHeaders['Content-Type'], 'application/json');
    });

    it('throws HetznerApiError with message from error response', async () => {
      mockFetch({ error: { message: 'server not found' } }, 404);

      await assert.rejects(
        () => hetzner.getServer('tok', 999),
        (err) => {
          assert.strictEqual(err.name, 'HetznerApiError');
          assert.strictEqual(err.status, 404);
          assert.strictEqual(err.message, 'server not found');
          return true;
        },
      );
    });

    it('throws HetznerApiError with statusText when error JSON parsing fails', async () => {
      mockFetchJsonFails(502);

      await assert.rejects(
        () => hetzner.getServer('tok', 1),
        (err) => {
          assert.strictEqual(err.name, 'HetznerApiError');
          assert.strictEqual(err.status, 502);
          assert.strictEqual(err.message, 'Internal Server Error');
          return true;
        },
      );
    });
  });

  // -----------------------------------------------------------------------
  // validate() internals — tested indirectly
  // -----------------------------------------------------------------------

  describe('validate (internal)', () => {
    it('throws HetznerApiError on Zod validation failure', async () => {
      // Return a server with missing required fields to trigger Zod error
      mockFetch({ server: { id: 'not-a-number' } });

      await assert.rejects(
        () => hetzner.getServer('tok', 1),
        (err) => {
          assert.strictEqual(err.name, 'HetznerApiError');
          assert.strictEqual(err.status, 0);
          assert.ok(err.message.startsWith('Invalid API response:'));
          return true;
        },
      );
    });
  });

  // -----------------------------------------------------------------------
  // createServer
  // -----------------------------------------------------------------------

  describe('createServer', () => {
    it('sends POST with correct body and returns validated server', async () => {
      let capturedUrl, capturedOpts;
      globalThis.fetch = (url, opts) => {
        capturedUrl = url;
        capturedOpts = opts;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ server: mockServer }),
        });
      };

      const result = await hetzner.createServer('tok', {
        image: 'ubuntu-24.04',
        labels: { managed: 'devbox' },
        location: 'fsn1',
        name: 'test',
        serverType: 'cx22',
        sshKeys: [42],
        userData: '#cloud-config',
      });

      assert.strictEqual(capturedOpts.method, 'POST');
      assert.ok(capturedUrl.endsWith('/servers'));

      const body = JSON.parse(capturedOpts.body);
      assert.strictEqual(body.name, 'test');
      assert.strictEqual(body.server_type, 'cx22');
      assert.strictEqual(body.image, 'ubuntu-24.04');
      assert.strictEqual(body.location, 'fsn1');
      assert.deepStrictEqual(body.ssh_keys, [42]);
      assert.strictEqual(body.start_after_create, true);
      assert.strictEqual(body.user_data, '#cloud-config');

      assert.strictEqual(result.id, 1);
      assert.strictEqual(result.name, 'test');
    });

    it('throws on API error', async () => {
      mockFetch({ error: { message: 'insufficient funds' } }, 402);

      await assert.rejects(
        () =>
          hetzner.createServer('tok', {
            image: 'ubuntu-24.04',
            location: 'fsn1',
            name: 'test',
            serverType: 'cx22',
            sshKeys: [],
            userData: '',
          }),
        (err) => {
          assert.strictEqual(err.name, 'HetznerApiError');
          assert.strictEqual(err.status, 402);
          assert.strictEqual(err.message, 'insufficient funds');
          return true;
        },
      );
    });
  });

  // -----------------------------------------------------------------------
  // createSSHKey
  // -----------------------------------------------------------------------

  describe('createSSHKey', () => {
    it('sends POST and returns validated key', async () => {
      let capturedOpts;
      globalThis.fetch = (_url, opts) => {
        capturedOpts = opts;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ ssh_key: mockSSHKey }),
        });
      };

      const result = await hetzner.createSSHKey('tok', 'my-key', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@dev');

      assert.strictEqual(capturedOpts.method, 'POST');
      const body = JSON.parse(capturedOpts.body);
      assert.strictEqual(body.name, 'my-key');
      assert.strictEqual(body.public_key, 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@dev');

      assert.strictEqual(result.id, 42);
      assert.strictEqual(result.name, 'my-key');
      assert.strictEqual(result.fingerprint, 'aa:bb:cc');
    });
  });

  // -----------------------------------------------------------------------
  // deleteServer
  // -----------------------------------------------------------------------

  describe('deleteServer', () => {
    it('sends DELETE request', async () => {
      let capturedUrl, capturedOpts;
      globalThis.fetch = (url, opts) => {
        capturedUrl = url;
        capturedOpts = opts;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({}),
        });
      };

      await hetzner.deleteServer('tok', 123);

      assert.strictEqual(capturedOpts.method, 'DELETE');
      assert.ok(capturedUrl.endsWith('/servers/123'));
    });

    it('handles 204 No Content response', async () => {
      globalThis.fetch = () =>
        Promise.resolve({
          ok: true,
          status: 204,
          json: () => Promise.reject(new Error('no body')),
        });

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

      assert.strictEqual(result.id, 42);
      assert.strictEqual(result.name, 'my-key');
    });

    it('creates new key when not found', async () => {
      let callCount = 0;
      globalThis.fetch = () => {
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
      };

      const result = await hetzner.ensureSSHKey('tok', 'my-key', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@dev');

      assert.strictEqual(callCount, 2);
      assert.strictEqual(result.id, 42);
    });

    it('handles uniqueness_error race condition by re-fetching', async () => {
      let callCount = 0;
      globalThis.fetch = () => {
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
      };

      const result = await hetzner.ensureSSHKey('tok', 'my-key', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@dev');

      assert.strictEqual(callCount, 3);
      assert.strictEqual(result.id, 42);
    });

    it('throws non-uniqueness errors', async () => {
      let callCount = 0;
      globalThis.fetch = () => {
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
      };

      await assert.rejects(
        () => hetzner.ensureSSHKey('tok', 'my-key', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@dev'),
        (err) => {
          assert.strictEqual(err.name, 'HetznerApiError');
          assert.strictEqual(err.status, 403);
          assert.strictEqual(err.message, 'forbidden');
          return true;
        },
      );
    });
  });

  // -----------------------------------------------------------------------
  // getServer
  // -----------------------------------------------------------------------

  describe('getServer', () => {
    it('returns validated server', async () => {
      let capturedUrl;
      globalThis.fetch = (url) => {
        capturedUrl = url;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ server: mockServer }),
        });
      };

      const result = await hetzner.getServer('tok', 1);

      assert.ok(capturedUrl.endsWith('/servers/1'));
      assert.strictEqual(result.id, 1);
      assert.strictEqual(result.name, 'test');
      assert.strictEqual(result.status, 'running');
      assert.strictEqual(result.public_net.ipv4.ip, '1.2.3.4');
    });
  });

  // -----------------------------------------------------------------------
  // listImages
  // -----------------------------------------------------------------------

  describe('listImages', () => {
    it('returns validated image array', async () => {
      let capturedUrl;
      globalThis.fetch = (url) => {
        capturedUrl = url;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ images: [mockImage] }),
        });
      };

      const result = await hetzner.listImages('tok');

      assert.ok(capturedUrl.includes('/images?type=system'));
      assert.strictEqual(result.length, 1);
      assert.strictEqual(result[0].name, 'ubuntu-24.04');
      assert.strictEqual(result[0].os_flavor, 'ubuntu');
    });
  });

  // -----------------------------------------------------------------------
  // listLocations
  // -----------------------------------------------------------------------

  describe('listLocations', () => {
    it('returns validated location array', async () => {
      let capturedUrl;
      globalThis.fetch = (url) => {
        capturedUrl = url;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ locations: [mockLocation] }),
        });
      };

      const result = await hetzner.listLocations('tok');

      assert.ok(capturedUrl.endsWith('/locations'));
      assert.strictEqual(result.length, 1);
      assert.strictEqual(result[0].name, 'fsn1');
      assert.strictEqual(result[0].city, 'Falkenstein');
    });
  });

  // -----------------------------------------------------------------------
  // listServers
  // -----------------------------------------------------------------------

  describe('listServers', () => {
    it('returns validated server array', async () => {
      mockFetch({ servers: [mockServer] });

      const result = await hetzner.listServers('tok');

      assert.strictEqual(result.length, 1);
      assert.strictEqual(result[0].id, 1);
      assert.strictEqual(result[0].name, 'test');
    });
  });

  // -----------------------------------------------------------------------
  // listServerTypes
  // -----------------------------------------------------------------------

  describe('listServerTypes', () => {
    it('returns validated server type array', async () => {
      let capturedUrl;
      globalThis.fetch = (url) => {
        capturedUrl = url;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ server_types: [mockServerType] }),
        });
      };

      const result = await hetzner.listServerTypes('tok');

      assert.ok(capturedUrl.endsWith('/server_types'));
      assert.strictEqual(result.length, 1);
      assert.strictEqual(result[0].name, 'cx22');
      assert.strictEqual(result[0].cores, 2);
      assert.deepStrictEqual(result[0].prices[0].price_hourly, { gross: '0.0080' });
    });
  });

  // -----------------------------------------------------------------------
  // listSSHKeys
  // -----------------------------------------------------------------------

  describe('listSSHKeys', () => {
    it('returns validated SSH key array', async () => {
      let capturedUrl;
      globalThis.fetch = (url) => {
        capturedUrl = url;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ ssh_keys: [mockSSHKey] }),
        });
      };

      const result = await hetzner.listSSHKeys('tok');

      assert.ok(capturedUrl.endsWith('/ssh_keys'));
      assert.strictEqual(result.length, 1);
      assert.strictEqual(result[0].id, 42);
      assert.strictEqual(result[0].fingerprint, 'aa:bb:cc');
    });
  });

  // -----------------------------------------------------------------------
  // rebuildServer
  // -----------------------------------------------------------------------

  describe('rebuildServer', () => {
    it('sends POST with image', async () => {
      let capturedUrl, capturedOpts;
      globalThis.fetch = (url, opts) => {
        capturedUrl = url;
        capturedOpts = opts;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({}),
        });
      };

      await hetzner.rebuildServer('tok', 5, 'ubuntu-24.04');

      assert.strictEqual(capturedOpts.method, 'POST');
      assert.ok(capturedUrl.endsWith('/servers/5/actions/rebuild'));
      const body = JSON.parse(capturedOpts.body);
      assert.strictEqual(body.image, 'ubuntu-24.04');
    });
  });

  // -----------------------------------------------------------------------
  // validateToken
  // -----------------------------------------------------------------------

  describe('validateToken', () => {
    it('returns true on success', async () => {
      let capturedUrl;
      globalThis.fetch = (url) => {
        capturedUrl = url;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ servers: [] }),
        });
      };

      const result = await hetzner.validateToken('good-token');

      assert.strictEqual(result, true);
      assert.ok(capturedUrl.includes('/servers?per_page=1'));
    });

    it('returns false on failure', async () => {
      mockFetch({ error: { message: 'unauthorized' } }, 401);

      const result = await hetzner.validateToken('bad-token');

      assert.strictEqual(result, false);
    });
  });

  // -----------------------------------------------------------------------
  // waitForRunning
  // -----------------------------------------------------------------------

  describe('waitForRunning', () => {
    it('returns server when status is running immediately', async () => {
      mockFetch({ server: { ...mockServer, status: 'running' } });

      const result = await hetzner.waitForRunning('tok', 1, 3, 1);

      assert.strictEqual(result.status, 'running');
      assert.strictEqual(result.id, 1);
    });

    it('polls until server is running', async () => {
      let callCount = 0;
      globalThis.fetch = () => {
        callCount++;
        const status = callCount >= 3 ? 'running' : 'initializing';
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ server: { ...mockServer, status } }),
        });
      };

      const result = await hetzner.waitForRunning('tok', 1, 5, 1);

      assert.strictEqual(result.status, 'running');
      assert.strictEqual(callCount, 3);
    });

    it('throws on timeout', async () => {
      mockFetch({ server: { ...mockServer, status: 'initializing' } });

      await assert.rejects(
        () => hetzner.waitForRunning('tok', 1, 1, 1),
        (err) => {
          assert.ok(err.message.includes('Timeout'));
          return true;
        },
      );
    });
  });
});
