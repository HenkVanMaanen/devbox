/* eslint-disable */
// @ts-nocheck — This file runs on the provisioned server under Node.js, not in the browser.
// It is bundled by esbuild into a single minified script for cloud-init deployment.

const http = require('http');
const fs = require('fs');
const https = require('https');
const { execSync } = require('child_process');

// Read runtime config written by cloud-init
const configRaw = fs.readFileSync('/etc/devbox/config.json', 'utf8');
const config = JSON.parse(configRaw);
const TIMEOUT = config.timeout;
const WARNING = config.warning;
const TOKEN = config.token;
const DNS_SERVICE = config.dnsService;

const PORT_NAMES = { 65534: 'Terminal' };
const IGNORED_PORTS = new Set([22, 80, 443, 2019, 65531]);
let last = Date.now();
let warn = false;
let services = new Map();
let ipHex;

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
      url: `https://${s.port}.${ipHex}.${DNS_SERVICE}`,
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
    .get(`https://${port}.${ipHex}.${DNS_SERVICE}/`, { rejectUnauthorized: false, timeout: 30000 }, () => {})
    .on('error', () => {});
  console.log(`Pre-warming certificate for port ${port}`);
}

function prewarmOverview() {
  https
    .get(`https://${ipHex}.${DNS_SERVICE}/`, { rejectUnauthorized: false, timeout: 30000 }, () => {})
    .on('error', () => {});
  console.log('Pre-warming certificate for overview page');
}

function prewarmAll() {
  services = scanPorts();
  prewarmOverview();
  for (const [p] of services) prewarmCert(p);
}

function waitForCaddy(cb) {
  const poll = () => {
    http
      .get('http://localhost:2019/config/', (r) => {
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
// This allows the same server to work with sslip.io, nip.io, custom domains, etc.
function verifyDomain(domain) {
  if (!domain) return false;
  // Pattern 1: {ipHex}.{any-suffix} - base domain for overview page
  const basePattern = new RegExp(`^${ipHex}\\.[a-z0-9.-]+$`, 'i');
  if (basePattern.test(domain)) return true;
  // Pattern 2: {port}.{ipHex}.{any-suffix} - service subdomain
  const svcPattern = new RegExp(`^(\\d+)\\.${ipHex}\\.[a-z0-9.-]+$`, 'i');
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

function wip() {
  try {
    let USER = '';
    try {
      USER = execSync('git config user.name', { encoding: 'utf8', timeout: 5000 }).trim();
    } catch {}
    for (const d of fs.readdirSync('/home/dev')) {
      if (/[^a-zA-Z0-9._-]/.test(d)) continue;
      const p = '/home/dev/' + d;
      if (!fs.statSync(p).isDirectory() || !fs.existsSync(p + '/.git')) continue;
      try {
        if (!execSync('git -C ' + JSON.stringify(p) + ' status --porcelain', { encoding: 'utf8' }).trim()) continue;
        const b =
          (USER ? 'wip/' + USER.replace(/[^a-zA-Z0-9._-]/g, '_') + '/' : 'wip/') +
          new Date().toISOString().replace(/[T:]/g, '-').slice(0, 19);
        execSync(
          'git -C ' +
            JSON.stringify(p) +
            ' checkout -b ' +
            JSON.stringify(b) +
            ' && git -C ' +
            JSON.stringify(p) +
            ' add -A && git -C ' +
            JSON.stringify(p) +
            ' commit -m WIP && git -C ' +
            JSON.stringify(p) +
            ' push -u origin ' +
            JSON.stringify(b),
          { timeout: 60000 },
        );
      } catch {}
    }
  } catch {}
}

let sid;
try {
  sid = execSync('curl -s -H "Metadata-Flavor:hetzner" http://169.254.169.254/hetzner/v1/metadata/instance-id', {
    encoding: 'utf8',
    timeout: 5000,
  }).trim();
} catch {}

function del() {
  if (!sid) return;
  https
    .request(
      {
        hostname: 'api.hetzner.cloud',
        path: '/v1/servers/' + sid,
        method: 'DELETE',
        headers: { Authorization: 'Bearer ' + TOKEN },
      },
      () => process.exit(0),
    )
    .end();
}

function checkActivityAndMaybeDelete() {
  check();
  const i = (Date.now() - last) / 1000;
  if (TIMEOUT * 60 - i <= WARNING * 60 && !warn) warn = true;
  if (i >= TIMEOUT * 60) {
    wip();
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
}

main();
