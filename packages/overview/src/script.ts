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
    if (el && data.displayName) el.textContent = 'Logged in as ' + esc(data.displayName);
    if (data.isGuest) {
      isGuest = true;
      const guestCard = document.getElementById('guestcard');
      if (guestCard) guestCard.style.display = 'none';
    }
  } catch {}
}

// Guest access management
const guestsEl = document.getElementById('guests');
const gbtn = document.getElementById('gbtn');
const gdur = document.getElementById('gdur') as HTMLSelectElement;
const gname = document.getElementById('gname') as HTMLInputElement;
let guestList: { id: string; username: string; displayName?: string; magicUrl?: string; remaining: number }[] = [];
let isGuest = false;

async function loadGuests() {
  try {
    const data = await (await fetch(location.origin + '/api/guests')).json();
    // Merge: keep passwords for guests we created this session
    for (const g of data) {
      const existing = guestList.find((e) => e.id === g.id);
      if (existing) {
        existing.remaining = g.remaining;
        existing.displayName = g.displayName || existing.displayName;
      } else {
        guestList.push(g);
      }
    }
    // Remove expired
    guestList = guestList.filter((g) => g.remaining > 0 || data.some((d: { id: string }) => d.id === g.id));
    renderGuests();
  } catch {}
}

async function createGuest() {
  gbtn.textContent = '...';
  try {
    const nameVal = gname.value.trim();
    const res = await fetch(location.origin + '/api/guests', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ minutes: parseInt(gdur.value), name: nameVal }),
    });
    const g = await res.json();
    if (g.username) {
      guestList.push({
        id: g.id,
        username: g.username,
        displayName: g.displayName,
        magicUrl: g.magicUrl,
        remaining: Math.floor((g.expires - Date.now()) / 1000),
      });
      gname.value = '';
      renderGuests();
    }
  } catch {}
  gbtn.textContent = 'Generate';
}

function showToast(msg: string) {
  const el = document.createElement('div');
  el.textContent = msg;
  el.style.cssText =
    'position:fixed;bottom:1.5rem;left:50%;transform:translateX(-50%);background:var(--card,#171717);color:var(--fg,#f5f5f5);border:1px solid var(--border,#333);border-radius:0.375rem;padding:0.5rem 1rem;font-size:0.875rem;z-index:9999;opacity:0;transition:opacity 0.2s';
  document.body.appendChild(el);
  requestAnimationFrame(() => (el.style.opacity = '1'));
  setTimeout(() => {
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 200);
  }, 2000);
}

function copyLink(url: string) {
  navigator.clipboard.writeText(url);
  showToast('Link copied');
}

async function revokeGuest(id: string) {
  try {
    await fetch(location.origin + '/api/guests?id=' + id, { method: 'DELETE' });
    guestList = guestList.filter((g) => g.id !== id);
    renderGuests();
    showToast('Guest revoked');
  } catch {}
}

function renderGuests() {
  if (!guestsEl) return;
  if (guestList.length === 0) {
    guestsEl.innerHTML = '<div style="color:var(--muted-fg,#a3a3a3);font-size:0.875rem">No active guests</div>';
    return;
  }
  guestsEl.innerHTML = '';
  for (const g of guestList) {
    const el = document.createElement('div');
    el.style.cssText =
      'background:var(--muted,#262626);border-radius:0.375rem;padding:0.75rem;margin-bottom:0.5rem;font-size:0.875rem';
    const mins = Math.floor(g.remaining / 60);
    let html =
      '<div style="display:flex;justify-content:space-between;align-items:center">' +
      '<strong>' +
      esc(g.displayName || g.username) +
      '</strong>' +
      '<span style="color:var(--muted-fg,#a3a3a3)">' +
      mins +
      'm left</span></div>';
    html += '<div style="display:flex;gap:0.5rem;margin-top:0.5rem">';
    if (g.magicUrl) {
      html +=
        '<button onclick="window.__copy(\'' +
        g.magicUrl.replace(/'/g, "\\'") +
        '\')" style="background:var(--card,#171717);color:var(--fg,#f5f5f5);border:1px solid var(--border,#333);border-radius:0.25rem;padding:0.25rem 0.5rem;font-size:0.75rem;cursor:pointer">Copy link</button>';
    }
    html +=
      '<button onclick="window.__revoke(\'' +
      g.id +
      '\')" style="background:var(--card,#171717);color:var(--destructive,#ef4444);border:1px solid var(--border,#333);border-radius:0.25rem;padding:0.25rem 0.5rem;font-size:0.75rem;cursor:pointer">Revoke</button></div>';
    el.innerHTML = html;
    guestsEl.appendChild(el);
  }
}

window.__revoke = revokeGuest;
window.__copy = copyLink;
gbtn.addEventListener('click', createGuest);

getStatus();
getServices();
getWhoami();
loadGuests();
setInterval(getStatus, 10000);
setInterval(getServices, 10000);
setInterval(loadGuests, 10000);
setInterval(t, 1000);
