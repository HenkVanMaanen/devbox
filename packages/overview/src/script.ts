/* eslint-disable */
// @ts-nocheck — This file runs in the browser on the provisioned server's overview page.
// It is bundled by esbuild into a minified script inlined into the HTML.

const d = document.getElementById('d');
const s = document.getElementById('s');
const cd = document.getElementById('cd');
const svcsEl = document.getElementById('svcs');
let r = -1;
let w = 0;

function f(x: number): string {
  if (x < 0) return '--:--';
  return String(Math.floor(x / 60)).padStart(2, '0') + ':' + String(x % 60).padStart(2, '0');
}

function up() {
  cd.textContent = f(r);
  d.className = w ? 'dot w' : r <= 0 ? 'dot e' : 'dot';
  s.textContent = w ? 'Warning' : r <= 0 ? 'Shutting down' : 'Active';
}

async function getStatus() {
  try {
    const x = await (await fetch(location.origin + '/api/status')).json();
    r = x.remaining || x.remaining_seconds || 0;
    w = x.warn || x.warning_active;
    up();
  } catch {
    d.className = 'dot e';
    s.textContent = 'Error';
  }
}

async function getServices() {
  try {
    const svcs = await (await fetch(location.origin + '/api/services')).json();
    renderServices(svcs);
  } catch {}
}

function renderServices(svcs: { name: string; port: number; url: string; active: boolean }[]) {
  svcsEl.innerHTML = '';
  for (const svc of svcs) {
    const url = 'https://' + new URL(svc.url).host + '/';
    const a = document.createElement('a');
    a.href = url;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.className = 'svc' + (svc.active ? '' : ' inactive');
    a.innerHTML =
      '<div class="ico" aria-hidden="true">' +
      getIcon(svc.name) +
      '</div><div class="inf"><div class="nm">' +
      esc(svc.name) +
      '</div><div class="ds">' +
      (svc.active ? 'Active' : 'Inactive') +
      (svc.port ? ' &middot; port ' + svc.port : '') +
      '</div></div><div class="sdot ' +
      (svc.active ? 'active' : 'inactive') +
      '"></div>';
    svcsEl.appendChild(a);
  }
}

function getIcon(name: string): string {
  const m: Record<string, string> = { Terminal: '$_' };
  return m[name] || '\u{1F310}';
}

function esc(s: string): string {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function t() {
  if (r > 0) {
    r--;
    up();
  }
}

async function getWhoami() {
  try {
    const data = await (await fetch(location.origin + '/api/whoami')).json();
    const el = document.getElementById('user');
    if (el && data.user) el.textContent = 'Logged in as ' + esc(data.user);
  } catch {}
}

getStatus();
getServices();
getWhoami();
setInterval(getStatus, 10000);
setInterval(getServices, 10000);
setInterval(t, 1000);
