// Cloud-init builder helpers - Caddyfile, index page, autodelete daemon

import type { GlobalConfig, GitCredential } from '$lib/types';

// Escape a string for safe embedding in a single-quoted JS string literal
function escapeSingleQuotedJS(s: string): string {
  if (!s) return '';
  return s.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n').replace(/<\//g, '<\\/');
}

// Escape shell metacharacters in double-quoted strings
export function shellEscape(s: string): string {
  if (!s) return '';
  return s.replace(/[\\"$`!]/g, '\\$&').replace(/\n/g, '');
}

// Convert standard base64 to base64url (for Actalis EAB keys)
export function toBase64URL(s: string): string {
  if (!s) return '';
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Build git credentials file content
export function buildGitCredentials(credential: GitCredential): string {
  if (!credential || !credential.host || !credential.username || !credential.token) return '';
  const username = encodeURIComponent(credential.username);
  const token = encodeURIComponent(credential.token);
  // Validate host to prevent injection (only allow valid hostname chars)
  const host = credential.host.replace(/[^a-zA-Z0-9._-]/g, '');
  return `https://${username}:${token}@${host}\n`;
}

export interface ThemeColors {
  background: string;
  foreground: string;
  card: string;
  border: string;
  primary: string;
  muted: string;
  mutedForeground: string;
  success: string;
  warning: string;
  destructive: string;
  focus: string;
  [key: string]: string; // Allow extra properties from theme store
}

export interface TerminalColors {
  black?: string;
  red?: string;
  green?: string;
  yellow?: string;
  blue?: string;
  magenta?: string;
  cyan?: string;
  white?: string;
  brightBlack?: string;
  brightRed?: string;
  brightGreen?: string;
  brightYellow?: string;
  brightBlue?: string;
  brightMagenta?: string;
  brightCyan?: string;
  brightWhite?: string;
}

// Build devbox daemon script with port scanning and autodelete
export function buildDaemonScript(config: GlobalConfig, hetznerToken: string): string {
  const timeout = config.autoDelete.timeoutMinutes;
  const warning = config.autoDelete.warningMinutes;
  // Get DNS service for URL generation (custom domain or standard service)
  const dnsService = config.services.dnsService === 'custom'
    ? (config.services.customDnsDomain || 'sslip.io')
    : (config.services.dnsService || 'sslip.io');

  return `#!/usr/bin/env node
const http=require('http'),fs=require('fs'),https=require('https'),{execSync}=require('child_process');
const TIMEOUT=${timeout},WARNING=${warning},TOKEN='${escapeSingleQuotedJS(hetznerToken)}';
const DNS_SERVICE='${escapeSingleQuotedJS(dnsService)}';
const PORT_NAMES={65534:'Terminal'};
const IGNORED_PORTS=new Set([22,80,443,2019,65531]);
let last=Date.now(),warn=false,services=new Map(),ipHex;

function loadConfig(){
  // Get public IP from network interface (no external dependency)
  try{
    const ip=execSync("ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1",{encoding:'utf8',timeout:5000}).trim();
    const parts=ip.split('.');
    if(parts.length===4){
      return parts.map(p=>parseInt(p).toString(16).padStart(2,'0')).join('');
    }
  }catch{}
  console.error('Failed to detect IP');process.exit(1);
}

function scanPorts(){
  try{
    const output=execSync('ss -tlnp',{encoding:'utf8',timeout:5000});
    const discovered=new Map();
    for(const line of output.split('\\n')){
      const match=line.match(/(?:127\\.0\\.0\\.1|0\\.0\\.0\\.0|\\*|\\[::\\]):(\\d+)\\s/);
      if(!match)continue;
      const port=parseInt(match[1]);
      if(IGNORED_PORTS.has(port))continue;
      const procMatch=line.match(/users:\\(\\("([^"]+)"/);
      const proc=procMatch?procMatch[1]:'unknown';
      discovered.set(port,{port,process:proc,name:PORT_NAMES[port]||proc});
    }
    return discovered;
  }catch(e){return new Map()}
}

function isPortListening(port){
  try{const out=execSync(\`ss -tln sport = :\${port}\`,{encoding:'utf8',timeout:5000});return out.split('\\n').length>2}catch{return false}
}

function getServices(){
  return Array.from(services.values()).map(s=>({name:s.name,port:s.port,url:\`https://\${s.port}.\${ipHex}.\${DNS_SERVICE}\`,active:true})).sort((a,b)=>a.port-b.port);
}

function updateServices(){
  const prev=new Set(services.keys());
  services=scanPorts();
  const curr=new Set(services.keys());
  for(const p of curr)if(!prev.has(p)){console.log(\`Service discovered: \${services.get(p).name} on port \${p}\`);prewarmCert(p)}
  for(const p of prev)if(!curr.has(p))console.log(\`Service stopped on port \${p}\`);
}

function prewarmCert(port){
  https.get(\`https://\${port}.\${ipHex}.\${DNS_SERVICE}/\`,{rejectUnauthorized:false,timeout:30000},()=>{}).on('error',()=>{});
  console.log(\`Pre-warming certificate for port \${port}\`);
}

// Domain-agnostic verification: accepts any domain matching our IP hex
// This allows the same server to work with sslip.io, nip.io, custom domains, etc.
function verifyDomain(domain){
  if(!domain)return false;
  // Pattern 1: {ipHex}.{any-suffix} - base domain for overview page
  const basePattern=new RegExp(\`^\${ipHex}\\\\.[a-z0-9.-]+\$\`,'i');
  if(basePattern.test(domain))return true;
  // Pattern 2: {port}.{ipHex}.{any-suffix} - service subdomain
  const svcPattern=new RegExp(\`^(\\\\d+)\\\\.\${ipHex}\\\\.[a-z0-9.-]+\$\`,'i');
  const match=domain.match(svcPattern);
  if(!match)return false;
  const port=parseInt(match[1]);
  return isPortListening(port);
}

function check(){let a=false;try{if(execSync('who',{encoding:'utf8',timeout:5000}).trim())a=true}catch{}try{for(const f of fs.readdirSync('/dev/pts'))if(/^\\d+$/.test(f)&&Date.now()-fs.statSync('/dev/pts/'+f).atimeMs<60000)a=true}catch{}if(a){last=Date.now();warn=false}}

function wip(){try{let USER='';try{USER=execSync('git config user.name',{encoding:'utf8',timeout:5000}).trim()}catch{}for(const d of fs.readdirSync('/home/dev')){if(/[^a-zA-Z0-9._-]/.test(d))continue;const p='/home/dev/'+d;if(!fs.statSync(p).isDirectory()||!fs.existsSync(p+'/.git'))continue;try{if(!execSync('git -C '+JSON.stringify(p)+' status --porcelain',{encoding:'utf8'}).trim())continue;const b=(USER?'wip/'+USER.replace(/[^a-zA-Z0-9._-]/g,'_')+'/':'wip/')+new Date().toISOString().replace(/[T:]/g,'-').slice(0,19);execSync('git -C '+JSON.stringify(p)+' checkout -b '+JSON.stringify(b)+' && git -C '+JSON.stringify(p)+' add -A && git -C '+JSON.stringify(p)+' commit -m WIP && git -C '+JSON.stringify(p)+' push -u origin '+JSON.stringify(b),{timeout:60000})}catch{}}}catch{}}

let sid;try{sid=execSync('curl -s -H "Metadata-Flavor:hetzner" http://169.254.169.254/hetzner/v1/metadata/instance-id',{encoding:'utf8',timeout:5000}).trim()}catch{}

function del(){if(!sid)return;https.request({hostname:'api.hetzner.cloud',path:'/v1/servers/'+sid,method:'DELETE',headers:{Authorization:'Bearer '+TOKEN}},()=>process.exit(0)).end()}

function checkActivityAndMaybeDelete(){check();const i=(Date.now()-last)/1000;if(TIMEOUT*60-i<=WARNING*60&&!warn)warn=true;if(i>=TIMEOUT*60){wip();del()}}

function main(){
  ipHex=loadConfig();console.log(\`Devbox daemon starting with IP hex: \${ipHex}, DNS: \${DNS_SERVICE}\`);
  services=scanPorts();
  console.log(\`Found \${services.size} services on startup\`);
  for(const[p,s]of services)prewarmCert(p);
  setInterval(updateServices,10000);
  http.createServer((req,res)=>{
    const url=new URL(req.url,'http://localhost');
    const json=(code,data)=>{res.writeHead(code,{'Content-Type':'application/json'});res.end(JSON.stringify(data))};
    if(url.pathname==='/services')return json(200,getServices());
    if(url.pathname==='/status'){const idle=(Date.now()-last)/1000;return json(200,{idle:Math.floor(idle),timeout:TIMEOUT,warning:WARNING,remaining:Math.max(0,Math.floor(TIMEOUT*60-idle)),warn,last:new Date(last).toISOString()})}
    if(url.pathname==='/keepalive'&&req.method==='POST'){last=Date.now();warn=false;return json(200,{ok:true})}
    if(url.pathname==='/verify-domain'){const domain=url.searchParams.get('domain');if(verifyDomain(domain)){res.writeHead(200);res.end()}else{res.writeHead(403);res.end()}return}
    json(404,{error:'not found'});
  }).listen(65531,'127.0.0.1');
  console.log('HTTP server listening on 127.0.0.1:65531');
  setInterval(checkActivityAndMaybeDelete,30000);
}

main();
`;
}

// ACME provider configurations
const ACME_PROVIDERS: Record<string, { ca: string; requiresEab?: boolean }> = {
  letsencrypt: { ca: 'https://acme-v02.api.letsencrypt.org/directory' },
  zerossl: { ca: 'https://acme.zerossl.com/v2/DV90', requiresEab: true },
  buypass: { ca: 'https://api.buypass.com/acme/directory' },
  actalis: { ca: 'https://acme-api.actalis.com/acme/directory', requiresEab: true },
};

// Build Caddyfile for services (domain-agnostic)
// Accepts any domain matching {port}.{ipHex}.{anything} or {ipHex}.{anything}
export function buildCaddyConfig(config: GlobalConfig): string {
  let caddyfile = '{\n';
  caddyfile += '  on_demand_tls {\n    ask http://localhost:65531/verify-domain\n  }\n';

  if (config.services.acmeEmail && /^[^\s{}]+$/.test(config.services.acmeEmail)) {
    caddyfile += `  email ${config.services.acmeEmail}\n`;
  }

  // ACME provider configuration
  const acmeProvider = config.services.acmeProvider || 'zerossl';
  if (acmeProvider === 'custom' && config.services.customAcmeUrl) {
    caddyfile += '  acme_ca ' + config.services.customAcmeUrl + '\n';
    if (config.services.customEabKeyId && config.services.customEabKey) {
      caddyfile += `  acme_eab {\n    key_id ${config.services.customEabKeyId}\n    mac_key ${config.services.customEabKey}\n  }\n`;
    }
  } else if (acmeProvider !== 'letsencrypt') {
    const providerConfig = ACME_PROVIDERS[acmeProvider];
    if (providerConfig) {
      caddyfile += '  acme_ca ' + providerConfig.ca + '\n';
    }
    // EAB for zerossl
    if (acmeProvider === 'zerossl' && config.services.zerosslEabKeyId && config.services.zerosslEabKey) {
      caddyfile += `  acme_eab {\n    key_id ${config.services.zerosslEabKeyId}\n    mac_key ${config.services.zerosslEabKey}\n  }\n`;
    }
    // EAB for actalis
    if (acmeProvider === 'actalis' && config.services.actalisEabKeyId && config.services.actalisEabKey) {
      caddyfile += `  acme_eab {\n    key_id ${config.services.actalisEabKeyId}\n    mac_key ${toBase64URL(config.services.actalisEabKey)}\n  }\n`;
    }
  }

  caddyfile += '}\n\n';

  const authBlock = '  basic_auth {\n    devbox __HASH__\n  }\n';

  // HTTP to HTTPS redirect (also needed for ACME HTTP-01 challenge)
  caddyfile += `:80 {
  redir https://{host}{uri} permanent
}

`;

  // Single HTTPS listener - domain-agnostic routing via header matching
  caddyfile += `:443 {
  tls {
    on_demand
  }
${authBlock}
  # Base domain: {ipHex}.{any-suffix} - serves overview page
  @base header_regexp basehost Host (?i)^__IP__\\.[a-z0-9.-]+$
  handle @base {
    route /api/* {
      uri strip_prefix /api
      reverse_proxy localhost:65531
    }
    root * /var/www/devbox-overview
    file_server
  }

  # Service subdomain: {port}.{ipHex}.{any-suffix} - proxies to port
  @service header_regexp svchost Host (?i)^(\\d+)\\.__IP__\\.[a-z0-9.-]+$
  handle @service {
    reverse_proxy localhost:{re.svchost.1}
  }

  # Fallback: reject unmatched requests
  handle {
    respond "Not Found" 404
  }
}
`;

  return caddyfile;
}

// Build overview page HTML (minified, themed)
export function buildOverviewPage(config: GlobalConfig, serverName: string, themeColors: ThemeColors): string {
  const colors = themeColors;

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="${colors.background}"><title>${serverName}</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:${colors.background};min-height:100vh;color:${colors.foreground};padding:1.5rem;font-size:16px;line-height:1.6}.c{max-width:600px;margin:0 auto}h1{font-size:1.5rem;color:${colors.foreground};margin-bottom:.25rem}.sub{color:${colors.mutedForeground};font-size:1rem;margin-bottom:1.5rem}.card{background:${colors.card};border-radius:.5rem;padding:1.5rem;margin-bottom:1rem;border:2px solid ${colors.border}}.hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem}.ttl{font-size:1rem;color:${colors.mutedForeground}}.ind{display:flex;align-items:center;gap:.5rem}.dot{width:10px;height:10px;border-radius:50%;background:${colors.success};animation:p 2s infinite}.dot.w{background:${colors.warning}}.dot.e{background:${colors.destructive};animation:none}@keyframes p{0%,100%{opacity:1}50%{opacity:.5}}#cd{font-size:2rem;font-weight:600;color:${colors.foreground}}.lbl{font-size:1rem;color:${colors.mutedForeground};margin-top:.25rem}.svcs{display:grid;gap:.75rem}.svc{display:flex;align-items:center;gap:1rem;background:${colors.card};border:2px solid ${colors.border};border-radius:.5rem;padding:1rem;min-height:60px;text-decoration:none;color:inherit;transition:background .15s}.svc:hover{background:${colors.muted}}.svc:focus{outline:3px solid ${colors.focus};outline-offset:2px}.svc.inactive{opacity:.5}.ico{width:44px;height:44px;border-radius:.375rem;display:flex;align-items:center;justify-content:center;font-size:1.25rem;background:${colors.muted}}.inf{flex:1}.nm{font-weight:600;font-size:1rem;color:${colors.foreground}}.ds{font-size:1rem;color:${colors.mutedForeground}}.sdot{width:8px;height:8px;border-radius:50%;flex-shrink:0}.sdot.active{background:${colors.success}}.sdot.inactive{background:${colors.destructive}}</style></head><body><div class="c"><h1>${serverName}</h1><p class="sub">Devbox</p><div class="card"><div class="hdr"><span class="ttl">Auto-shutdown</span><div class="ind"><div id="d" class="dot" role="status" aria-label="Server status indicator"></div><span id="s">Active</span></div></div><div id="cd" aria-live="polite">--:--</div><div class="lbl">until idle shutdown</div></div><nav class="svcs" id="svcs" aria-label="Services"></nav></div><script>const token='${escapeSingleQuotedJS(config.services.accessToken)}';const d=document.getElementById('d'),s=document.getElementById('s'),cd=document.getElementById('cd'),svcsEl=document.getElementById('svcs');let r=-1,w=0;function f(x){if(x<0)return'--:--';return String(Math.floor(x/60)).padStart(2,'0')+':'+String(x%60).padStart(2,'0')}function up(){cd.textContent=f(r);d.className=w?'dot w':r<=0?'dot e':'dot';s.textContent=w?'Warning':r<=0?'Shutting down':'Active'}async function getStatus(){try{const x=await(await fetch(location.origin+'/api/status')).json();r=x.remaining||x.remaining_seconds||0;w=x.warn||x.warning_active;up()}catch{d.className='dot e';s.textContent='Error'}}async function getServices(){try{const svcs=await(await fetch(location.origin+'/api/services')).json();renderServices(svcs)}catch{}}function renderServices(svcs){svcsEl.innerHTML='';for(const svc of svcs){const url='https://devbox:'+encodeURIComponent(token)+'@'+new URL(svc.url).host+'/';const a=document.createElement('a');a.href=url;a.className='svc'+(svc.active?'':' inactive');a.innerHTML='<div class="ico" aria-hidden="true">'+getIcon(svc.name)+'</div><div class="inf"><div class="nm">'+esc(svc.name)+'</div><div class="ds">'+(svc.active?'Active':'Inactive')+(svc.port?' &middot; port '+svc.port:'')+'</div></div><div class="sdot '+(svc.active?'active':'inactive')+'"></div>';svcsEl.appendChild(a)}}function getIcon(name){const m={'Terminal':'$_'};return m[name]||'\\ud83c\\udf10'}function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}function t(){if(r>0){r--;up()}}getStatus();getServices();setInterval(getStatus,10000);setInterval(getServices,10000);setInterval(t,1000)</script></body></html>`;
}

// Default theme colors (dark theme)
export const defaultThemeColors: ThemeColors = {
  background: '#0d0d0d',
  foreground: '#f5f5f5',
  card: '#171717',
  border: '#333333',
  primary: '#6366f1',
  muted: '#262626',
  mutedForeground: '#a3a3a3',
  success: '#22c55e',
  warning: '#f59e0b',
  destructive: '#ef4444',
  focus: 'rgba(99,102,241,0.5)',
};

export const defaultTerminalColors: TerminalColors = {
  black: '#0d0d0d',
  red: '#ef4444',
  green: '#22c55e',
  yellow: '#f59e0b',
  blue: '#3b82f6',
  magenta: '#a855f7',
  cyan: '#06b6d4',
  white: '#f5f5f5',
  brightBlack: '#404040',
  brightRed: '#f87171',
  brightGreen: '#4ade80',
  brightYellow: '#fbbf24',
  brightBlue: '#60a5fa',
  brightMagenta: '#c084fc',
  brightCyan: '#22d3ee',
  brightWhite: '#ffffff',
};
