/* eslint-disable */
// @ts-nocheck — This file runs on the provisioned server under Node.js, not in the browser.
// It is bundled by esbuild into a single minified script for cloud-init deployment.

const http = require('http');
const fs = require('fs');
const https = require('https');
const { execSync, execFileSync } = require('child_process');

// Read runtime config written by cloud-init
const configRaw = fs.readFileSync('/etc/devbox/config.json', 'utf8');
const config = JSON.parse(configRaw);
const TIMEOUT = config.timeout;
const WARNING = config.warning;
const TOKEN = config.token;
const DNS_SERVICE = config.dnsService;
const DEV_PREFIX = config.useDevPrefix ? 'dev.' : '';

const PORT_NAMES = { 65534: 'Terminal' };
const IGNORED_PORTS = new Set([22, 80, 443, 2019, 9091, 65531]);
const USERS_FILE = '/etc/authelia/users.yml';
let last = Date.now();
let warn = false;
let services = new Map();
let ipHex;
const guests = new Map(); // id -> { username, password, hash, expires }
const magicTokens = new Map(); // token -> { username, password, expires }

function randomId() {
  return 'guest_' + require('crypto').randomBytes(4).toString('hex');
}

function randomPassword() {
  const c = require('crypto');
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  const bytes = c.randomBytes(12);
  let pw = '';
  for (let i = 0; i < 12; i++) pw += chars[bytes[i] % chars.length];
  return pw;
}

function randomToken() {
  return require('crypto').randomBytes(32).toString('hex');
}

function hashPassword(pw) {
  try {
    const out = execFileSync('/usr/local/bin/authelia', ['crypto', 'hash', 'generate', 'bcrypt', '--password', pw], {
      encoding: 'utf8',
      timeout: 10000,
    }).trim();
    // Strip "Digest: " prefix if present
    return out.replace(/^Digest:\s*/, '');
  } catch (e) {
    console.error('Failed to hash password:', e.message);
    return null;
  }
}

function rewriteUsersFile() {
  try {
    // Read base users (non-guest) from current file
    const content = fs.readFileSync(USERS_FILE, 'utf8');
    const lines = content.split('\n');
    let yaml = '';
    let inUser = false;
    let isGuest = false;
    // Preserve non-guest users
    for (const line of lines) {
      if (/^  \S+:/.test(line) && !line.startsWith('users:')) {
        const name = line.trim().replace(':', '');
        isGuest = name.startsWith('guest_');
        inUser = true;
      }
      if (inUser && isGuest) continue;
      yaml += line + '\n';
    }
    // Remove trailing newlines, ensure one
    yaml = yaml.replace(/\n+$/, '\n');
    // Append active guests
    for (const [, g] of guests) {
      if (Date.now() >= g.expires) continue;
      yaml += `  ${g.username}:\n`;
      yaml += `    displayname: '${g.displayName || g.username}'\n`;
      yaml += `    password: "${g.hash}"\n`;
      yaml += `    email: '${g.username}@devbox.local'\n`;
    }
    fs.writeFileSync(USERS_FILE, yaml, { mode: 0o644 });
  } catch (e) {
    console.error('Failed to rewrite users file:', e.message);
  }
}

function cleanupGuests() {
  let changed = false;
  for (const [id, g] of guests) {
    if (Date.now() >= g.expires) {
      guests.delete(id);
      changed = true;
      console.log('Guest expired:', g.username);
    }
  }
  for (const [t, m] of magicTokens) {
    if (Date.now() >= m.expires) magicTokens.delete(t);
  }
  if (changed) rewriteUsersFile();
}

function createGuest(durationMinutes, name) {
  const safeName = name ? name.replace(/[^a-zA-Z0-9_.-]/g, '').slice(0, 32) : '';
  const username = safeName ? 'guest_' + safeName : randomId();
  if (guests.has(username)) return null; // duplicate name
  const password = randomPassword();
  const hash = hashPassword(password);
  if (!hash) return null;
  const id = username;
  const expires = Date.now() + durationMinutes * 60 * 1000;
  const token = randomToken();
  const displayName = safeName || username.replace('guest_', '');
  guests.set(id, { username, password, hash, expires, displayName });
  magicTokens.set(token, { username, password, expires });
  rewriteUsersFile();
  const magicUrl = `https://auth.${DEV_PREFIX}${ipHex}.${DNS_SERVICE}/magic?token=${token}`;
  console.log('Guest created:', username, '(' + displayName + ') expires in', durationMinutes, 'min');
  return { id, username, displayName, expires, magicUrl };
}

function revokeGuest(id) {
  if (!guests.has(id)) return false;
  const g = guests.get(id);
  guests.delete(id);
  rewriteUsersFile();
  console.log('Guest revoked:', g.username);
  return true;
}

function listGuests() {
  const result = [];
  for (const [id, g] of guests) {
    if (Date.now() >= g.expires) continue;
    result.push({
      id,
      username: g.username,
      displayName: g.displayName || g.username.replace('guest_', ''),
      remaining: Math.max(0, Math.floor((g.expires - Date.now()) / 1000)),
    });
  }
  return result;
}

function loadConfig() {
  // Get public IP from network interface (no external dependency)
  try {
    const ip = execSync("ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1", {
      encoding: 'utf8',
      timeout: 5000,
    }).trim();
    const parts = ip.split('.');
    if (parts.length === 4) {
      return parts.map((p) => parseInt(p).toString(16).padStart(2, '0')).join('');
    }
  } catch {}
  console.error('Failed to detect IP');
  process.exit(1);
}

function scanPorts() {
  try {
    const output = execSync('ss -tlnp', { encoding: 'utf8', timeout: 5000 });
    const discovered = new Map();
    for (const line of output.split('\n')) {
      const match = line.match(/(?:127\.0\.0\.1|0\.0\.0\.0|\*|\[::\]):(\d+)\s/);
      if (!match) continue;
      const port = parseInt(match[1]);
      if (IGNORED_PORTS.has(port)) continue;
      const procMatch = line.match(/users:\(\("([^"]+)"/);
      const proc = procMatch ? procMatch[1] : 'unknown';
      discovered.set(port, { port, process: proc, name: PORT_NAMES[port] || proc });
    }
    return discovered;
  } catch (e) {
    return new Map();
  }
}

function isPortListening(port) {
  try {
    const out = execSync(`ss -tln sport = :${port}`, { encoding: 'utf8', timeout: 5000 });
    return out.split('\n').length > 2;
  } catch {
    return false;
  }
}

function getServices() {
  return Array.from(services.values())
    .map((s) => ({
      name: s.name,
      port: s.port,
      url: `https://${s.port}.${DEV_PREFIX}${ipHex}.${DNS_SERVICE}`,
      active: true,
    }))
    .sort((a, b) => a.port - b.port);
}

function updateServices() {
  const prev = new Set(services.keys());
  services = scanPorts();
  const curr = new Set(services.keys());
  for (const p of curr) {
    if (!prev.has(p)) {
      console.log(`Service discovered: ${services.get(p).name} on port ${p}`);
      prewarmCert(p);
    }
  }
  for (const p of prev) {
    if (!curr.has(p)) console.log(`Service stopped on port ${p}`);
  }
}

function prewarmCert(port) {
  https
    .get(
      `https://${port}.${DEV_PREFIX}${ipHex}.${DNS_SERVICE}/`,
      { rejectUnauthorized: false, timeout: 30000 },
      () => {},
    )
    .on('error', () => {});
  console.log(`Pre-warming certificate for port ${port}`);
}

function prewarmOverview() {
  https
    .get(`https://${DEV_PREFIX}${ipHex}.${DNS_SERVICE}/`, { rejectUnauthorized: false, timeout: 30000 }, () => {})
    .on('error', () => {});
  console.log('Pre-warming certificate for overview page');
  // Also prewarm the auth subdomain
  https
    .get(`https://auth.${DEV_PREFIX}${ipHex}.${DNS_SERVICE}/`, { rejectUnauthorized: false, timeout: 30000 }, () => {})
    .on('error', () => {});
}

function prewarmAll() {
  services = scanPorts();
  prewarmOverview();
  for (const [p] of services) prewarmCert(p);
}

function waitForCaddy(cb) {
  const poll = () => {
    http
      .get('http://127.0.0.1:2019/config/', (r) => {
        if (r.statusCode === 200) {
          console.log('Caddy ready');
          cb();
        } else {
          setTimeout(poll, 2000);
        }
      })
      .on('error', () => setTimeout(poll, 2000));
  };
  poll();
}

// Domain-agnostic verification: accepts any domain matching our IP hex
// Supports optional 'dev.' prefix for wildcard DNS (PSL cookie workaround)
function verifyDomain(domain) {
  if (!domain) return false;
  // Pattern 1: auth.{devPrefix}{ipHex}.{suffix} - Authelia portal
  const authPattern = new RegExp(`^auth\\.${DEV_PREFIX}${ipHex}\\.[a-z0-9.-]+$`, 'i');
  if (authPattern.test(domain)) return true;
  // Pattern 2: {devPrefix}{ipHex}.{suffix} - base domain for overview page
  const basePattern = new RegExp(`^${DEV_PREFIX}${ipHex}\\.[a-z0-9.-]+$`, 'i');
  if (basePattern.test(domain)) return true;
  // Pattern 3: {port}.{devPrefix}{ipHex}.{suffix} - service subdomain
  const svcPattern = new RegExp(`^(\\d+)\\.${DEV_PREFIX}${ipHex}\\.[a-z0-9.-]+$`, 'i');
  const match = domain.match(svcPattern);
  if (!match) return false;
  const port = parseInt(match[1]);
  return isPortListening(port);
}

function check() {
  let a = false;
  try {
    for (const f of fs.readdirSync('/dev/pts')) {
      if (/^\d+$/.test(f) && Date.now() - fs.statSync('/dev/pts/' + f).mtimeMs < 60000) a = true;
    }
  } catch {}
  if (a) {
    last = Date.now();
    warn = false;
  }
}

let sid;
try {
  sid = execSync('curl -s -H "Metadata-Flavor:hetzner" http://169.254.169.254/hetzner/v1/metadata/instance-id', {
    encoding: 'utf8',
    timeout: 5000,
  }).trim();
} catch {}

// Generic Hetzner API call helper
function apiCall(method, path, body, callback) {
  const req = https.request(
    {
      hostname: 'api.hetzner.cloud',
      path: '/v1' + path,
      method,
      headers: { Authorization: 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
    },
    (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          callback(null, res.statusCode, JSON.parse(data));
        } catch {
          callback(null, res.statusCode, {});
        }
      });
    },
  );
  req.on('error', (e) => callback(e));
  if (body) req.write(JSON.stringify(body));
  req.end();
}

function createSnapshot(cb) {
  console.log('Syncing filesystem...');
  try {
    execSync('sync', { timeout: 30000 });
  } catch {}
  console.log('Creating snapshot...');
  apiCall(
    'POST',
    '/servers/' + sid + '/actions/create_image',
    { description: 'devbox-snapshot', type: 'snapshot', labels: { managed: 'devbox' } },
    (err, status, data) => {
      if (err || status >= 300) {
        console.error('Snapshot failed, aborting deletion:', err || status);
        return cb(null);
      }
      const actionId = data.action && data.action.id;
      const imageId = data.image && data.image.id;
      console.log('Snapshot started, action:', actionId, 'image:', imageId);
      cb({ actionId, imageId });
    },
  );
}

function waitForAction(actionId, cb) {
  if (!actionId) return cb(false);
  const poll = () => {
    apiCall('GET', '/actions/' + actionId, null, (err, _status, data) => {
      if (err || !data.action) {
        console.error('Action poll failed, aborting');
        return cb(false);
      }
      if (data.action.status === 'success') {
        console.log('Snapshot complete');
        return cb(true);
      }
      if (data.action.status === 'error') {
        console.error('Snapshot action failed, aborting');
        return cb(false);
      }
      setTimeout(poll, 5000);
    });
  };
  poll();
}

function cleanupSnapshots(keepImageId, cb) {
  // cspell:disable-next-line
  apiCall('GET', '/images?type=snapshot&label_selector=managed%3Ddevbox', null, (err, _status, data) => {
    if (err || !data.images) return cb();
    const toDelete = data.images.filter((i) => i.id !== keepImageId);
    if (toDelete.length === 0) return cb();
    let remaining = toDelete.length;
    for (const img of toDelete) {
      console.log('Deleting old snapshot:', img.id);
      apiCall('DELETE', '/images/' + img.id, null, () => {
        remaining--;
        if (remaining <= 0) cb();
      });
    }
  });
}

function deleteServer() {
  console.log('Deleting server...');
  apiCall('DELETE', '/servers/' + sid, null, () => process.exit(0));
}

function del() {
  if (!sid) return;
  createSnapshot((result) => {
    if (!result) {
      console.error('Snapshot failed, server NOT deleted');
      return;
    }
    waitForAction(result.actionId, (success) => {
      if (!success) {
        console.error('Snapshot did not complete, server NOT deleted');
        return;
      }
      cleanupSnapshots(result.imageId, deleteServer);
    });
  });
}

function checkActivityAndMaybeDelete() {
  check();
  const i = (Date.now() - last) / 1000;
  if (TIMEOUT * 60 - i <= WARNING * 60 && !warn) warn = true;
  if (i >= TIMEOUT * 60) {
    del();
  }
}

function main() {
  ipHex = loadConfig();
  console.log(`Devbox daemon starting with IP hex: ${ipHex}, DNS: ${DNS_SERVICE}`);
  services = scanPorts();
  console.log(`Found ${services.size} services on startup`);
  waitForCaddy(prewarmAll);
  setInterval(updateServices, 10000);
  http
    .createServer((req, res) => {
      const url = new URL(req.url, 'http://localhost');
      const json = (code, data) => {
        res.writeHead(code, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data));
      };
      if (url.pathname === '/services') return json(200, getServices());
      if (url.pathname === '/status') {
        const idle = (Date.now() - last) / 1000;
        return json(200, {
          idle: Math.floor(idle),
          timeout: TIMEOUT,
          warning: WARNING,
          remaining: Math.max(0, Math.floor(TIMEOUT * 60 - idle)),
          warn,
          last: new Date(last).toISOString(),
        });
      }
      if (url.pathname === '/keepalive' && req.method === 'POST') {
        last = Date.now();
        warn = false;
        return json(200, { ok: true });
      }
      if (url.pathname === '/whoami') {
        const user = req.headers['remote-user'] || 'unknown';
        const guest = guests.get(user);
        return json(200, { user, displayName: guest ? guest.displayName : user, isGuest: user.startsWith('guest_') });
      }
      if (url.pathname === '/magic') {
        const token = url.searchParams.get('token');
        const creds = token ? magicTokens.get(token) : null;
        if (!creds || Date.now() >= creds.expires) {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(
            '<html><body style="font-family:sans-serif;padding:2rem;color:#f5f5f5;background:#0d0d0d"><h2>Link expired or invalid</h2></body></html>',
          );
          return;
        }
        // Consume token (one-time use)
        magicTokens.delete(token);
        const targetUrl = `https://${DEV_PREFIX}${ipHex}.${DNS_SERVICE}/`;
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`<html><body style="font-family:sans-serif;padding:2rem;color:#f5f5f5;background:#0d0d0d"><p>Logging in...</p><script>
fetch('/api/firstfactor',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'${creds.username}',password:'${creds.password}',keepMeLoggedIn:false,targetURL:'${targetUrl}'})}).then(function(r){return r.json()}).then(function(d){if(d.status==='OK')window.location='${targetUrl}';else document.body.innerHTML='<h2>Login failed: '+(d.message||'unknown error')+'</h2>'}).catch(function(){document.body.innerHTML='<h2>Login failed</h2>'})
</script></body></html>`);
        return;
      }
      if (url.pathname === '/guests' && req.method === 'GET') {
        return json(200, listGuests());
      }
      if (url.pathname === '/guests' && req.method === 'POST') {
        const remoteUser = req.headers['remote-user'] || '';
        if (remoteUser.startsWith('guest_')) return json(403, { error: 'Guests cannot create guests' });
        let body = '';
        req.on('data', (chunk) => (body += chunk));
        req.on('end', () => {
          try {
            const parsed = JSON.parse(body);
            const dur = Math.min(Math.max(parseInt(parsed.minutes) || 60, 5), 960);
            const guest = createGuest(dur, parsed.name || '');
            if (!guest) return json(500, { error: 'Failed to create guest' });
            json(201, guest);
          } catch {
            json(400, { error: 'Invalid request' });
          }
        });
        return;
      }
      if (url.pathname === '/guests' && req.method === 'DELETE') {
        const remoteUser = req.headers['remote-user'] || '';
        if (remoteUser.startsWith('guest_')) return json(403, { error: 'Guests cannot revoke guests' });
        const id = url.searchParams.get('id');
        if (id && revokeGuest(id)) return json(200, { ok: true });
        return json(404, { error: 'Guest not found' });
      }
      if (url.pathname === '/verify-domain') {
        const domain = url.searchParams.get('domain');
        if (verifyDomain(domain)) {
          res.writeHead(200);
          res.end();
        } else {
          res.writeHead(403);
          res.end();
        }
        return;
      }
      json(404, { error: 'not found' });
    })
    .listen(65531, '127.0.0.1');
  console.log('HTTP server listening on 127.0.0.1:65531');
  setInterval(checkActivityAndMaybeDelete, 30000);
  setInterval(cleanupGuests, 60000);
}

main();
