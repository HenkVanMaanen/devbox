// Cloud-init builder helpers - Caddyfile, index page, autodelete daemon

// Escape a string for safe embedding in a single-quoted JS string literal
function escapeSingleQuotedJS(s) {
    if (!s) return '';
    return s.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n').replace(/<\//g, '<\\/');
}

// Escape shell metacharacters in double-quoted strings
export function shellEscape(s) {
    if (!s) return '';
    return s.replace(/[\\"$`!]/g, '\\$&').replace(/\n/g, '');
}

// Escape a value for gitconfig (backslashes and double quotes)
export function escapeGitConfig(val) {
    if (!val) return '';
    return val.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

// Convert standard base64 to base64url (for Actalis EAB keys)
export function toBase64URL(s) {
    if (!s) return '';
    return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Build git credentials file content
export function buildGitCredentials(credentials) {
    if (!credentials || credentials.length === 0) return '';
    return credentials.map(cred => {
        const username = encodeURIComponent(cred.username);
        const token = encodeURIComponent(cred.token);
        // Validate host to prevent injection (only allow valid hostname chars)
        const host = cred.host.replace(/[^a-zA-Z0-9._-]/g, '');
        return `https://${username}:${token}@${host}`;
    }).join('\n') + '\n';
}

// Build main .gitconfig content
export function buildGitConfig(config, gitCreds) {
    let content = '[init]\n    defaultBranch = main\n';

    if (config.git?.userName || config.git?.userEmail) {
        content += '[user]\n';
        if (config.git.userName) content += `    name = "${escapeGitConfig(config.git.userName)}"\n`;
        if (config.git.userEmail) content += `    email = "${escapeGitConfig(config.git.userEmail)}"\n`;
    }

    if (gitCreds.length > 0) {
        content += '[credential]\n    helper = store\n';
    }

    // Add includeIf for each credential with custom identity
    gitCreds.forEach(cred => {
        if (cred.name || cred.email) {
            const safeHost = cred.host.replace(/[^a-zA-Z0-9._-]/g, '');
            content += `[includeIf "hasconfig:remote.*.url:https://${safeHost}/**"]\n    path = ~/.gitconfig-${safeHost}\n`;
            content += `[includeIf "hasconfig:remote.*.url:git@${safeHost}:*/**"]\n    path = ~/.gitconfig-${safeHost}\n`;
        }
    });

    return content;
}

// Build per-host gitconfig for credentials with custom identity
export function buildHostGitConfig(cred) {
    if (!cred.name && !cred.email) return null;
    let content = '[user]\n';
    if (cred.name) content += `    name = "${escapeGitConfig(cred.name)}"\n`;
    if (cred.email) content += `    email = "${escapeGitConfig(cred.email)}"\n`;
    return content;
}

// Build devbox daemon script with port scanning and autodelete
// Uses wildcard Caddy route - no dynamic route management needed (eliminates connection drops)
export function buildDaemonScript(config, hetznerToken) {
    const timeout = config.autoDelete.timeoutMinutes;
    const warning = config.autoDelete.warningMinutes;
    const gitUser = config.git.userName || '';

    return `#!/usr/bin/env node
const http=require('http'),fs=require('fs'),https=require('https'),{execSync}=require('child_process');
const TIMEOUT=${timeout},WARNING=${warning},TOKEN='${escapeSingleQuotedJS(hetznerToken)}',USER='${escapeSingleQuotedJS(gitUser)}';
const STATIC_SERVICES=new Map([[65532,{name:'VS Code',subdomain:'code'}],[65533,{name:'Claude',subdomain:'claude'}],[65534,{name:'Terminal',subdomain:'term'}]]);
const IGNORED_PORTS=new Set([22,80,443,2019,65531]);
let last=Date.now(),warn=false,discoveredServices=new Map(),baseDomain;

function loadConfig(){
  const caddyfile=fs.readFileSync('/etc/caddy/Caddyfile','utf8');
  const domainMatch=caddyfile.match(/^([a-z0-9-]+\\.\\d+-\\d+-\\d+-\\d+\\.[a-z.]+)\\s*\\{/m);
  if(!domainMatch){console.error('Failed to detect domain');process.exit(1)}
  return domainMatch[1];
}

function scanPorts(){
  try{
    const output=execSync('ss -tlnp',{encoding:'utf8',timeout:5000});
    const discovered=new Map();
    for(const line of output.split('\\n')){
      const match=line.match(/(?:127\\.0\\.0\\.1|0\\.0\\.0\\.0|\\*|\\[::\\]):(\\d+)\\s/);
      if(!match)continue;
      const port=parseInt(match[1]);
      if(IGNORED_PORTS.has(port)||STATIC_SERVICES.has(port))continue;
      const procMatch=line.match(/users:\\(\\("([^"]+)"/);
      discovered.set(port,{port,process:procMatch?procMatch[1]:'unknown'});
    }
    return discovered;
  }catch(e){return new Map()}
}

function isPortListening(port){
  try{const out=execSync(\`ss -tln sport = :\${port}\`,{encoding:'utf8',timeout:5000});return out.split('\\n').length>2}catch{return false}
}

function getServices(){
  const services=[];
  for(const[port,info]of STATIC_SERVICES)services.push({name:info.name,port,url:\`https://\${info.subdomain}.\${baseDomain}\`,active:isPortListening(port)});
  for(const[port,info]of discoveredServices)services.push({name:info.process,port,url:\`https://\${port}.\${baseDomain}\`,active:true});
  services.sort((a,b)=>{const aS=STATIC_SERVICES.has(a.port),bS=STATIC_SERVICES.has(b.port);if(aS!==bS)return aS?-1:1;return a.port-b.port});
  return services;
}

function updateDiscoveredServices(){
  const prev=new Set(discoveredServices.keys());
  discoveredServices=scanPorts();
  const curr=new Set(discoveredServices.keys());
  for(const p of curr)if(!prev.has(p))console.log(\`Service discovered on port \${p} (\${discoveredServices.get(p).process})\`);
  for(const p of prev)if(!curr.has(p))console.log(\`Service stopped on port \${p}\`);
}

// Verify domain for Caddy on-demand TLS - ensures only valid ports get certificates
function verifyDomain(domain){
  if(!domain)return false;
  // Must match pattern: {port}.{baseDomain} where port is numeric
  const expected=new RegExp(\`^(\\\\d+)\\\\.\${baseDomain.replace(/\\./g,'\\\\.')}\$\`);
  const match=domain.match(expected);
  if(!match)return false;
  const port=parseInt(match[1]);
  // Only allow if port is actively listening (security: don't issue certs for random ports)
  return isPortListening(port);
}

function check(){let a=false;try{if(execSync('who',{encoding:'utf8',timeout:5000}).trim())a=true}catch{}try{for(const f of fs.readdirSync('/dev/pts'))if(/^\\d+$/.test(f)&&Date.now()-fs.statSync('/dev/pts/'+f).atimeMs<60000)a=true}catch{}if(a){last=Date.now();warn=false}}

function wip(){try{for(const d of fs.readdirSync('/home/dev')){if(/[^a-zA-Z0-9._-]/.test(d))continue;const p='/home/dev/'+d;if(!fs.statSync(p).isDirectory()||!fs.existsSync(p+'/.git'))continue;try{if(!execSync('git -C '+JSON.stringify(p)+' status --porcelain',{encoding:'utf8'}).trim())continue;const b=(USER?'wip/'+USER.replace(/[^a-zA-Z0-9._-]/g,'_')+'/':'wip/')+new Date().toISOString().replace(/[T:]/g,'-').slice(0,19);execSync('git -C '+JSON.stringify(p)+' checkout -b '+JSON.stringify(b)+' && git -C '+JSON.stringify(p)+' add -A && git -C '+JSON.stringify(p)+' commit -m WIP && git -C '+JSON.stringify(p)+' push -u origin '+JSON.stringify(b),{timeout:60000})}catch{}}}catch{}}

let sid;try{sid=execSync('curl -s -H "Metadata-Flavor:hetzner" http://169.254.169.254/hetzner/v1/metadata/instance-id',{encoding:'utf8',timeout:5000}).trim()}catch{}

function del(){if(!sid)return;https.request({hostname:'api.hetzner.cloud',path:'/v1/servers/'+sid,method:'DELETE',headers:{Authorization:'Bearer '+TOKEN}},()=>process.exit(0)).end()}

function checkActivityAndMaybeDelete(){check();const i=(Date.now()-last)/1000;if(TIMEOUT*60-i<=WARNING*60&&!warn)warn=true;if(i>=TIMEOUT*60){wip();del()}}

function main(){
  baseDomain=loadConfig();console.log(\`Devbox daemon starting with domain: \${baseDomain}\`);
  discoveredServices=scanPorts();
  console.log(\`Found \${discoveredServices.size} services on startup\`);
  setInterval(updateDiscoveredServices,10000);
  http.createServer((req,res)=>{
    const url=new URL(req.url,'http://localhost');
    const json=(code,data)=>{res.writeHead(code,{'Content-Type':'application/json'});res.end(JSON.stringify(data))};
    if(url.pathname==='/services')return json(200,getServices());
    if(url.pathname==='/status'){const idle=(Date.now()-last)/1000;return json(200,{idle:Math.floor(idle),timeout:TIMEOUT,warning:WARNING,remaining:Math.max(0,Math.floor(TIMEOUT*60-idle)),warn,last:new Date(last).toISOString()})}
    if(url.pathname==='/keepalive'&&req.method==='POST'){last=Date.now();warn=false;return json(200,{ok:true})}
    // Caddy on-demand TLS verification endpoint
    if(url.pathname==='/verify-domain'){const domain=url.searchParams.get('domain');if(verifyDomain(domain)){res.writeHead(200);res.end()}else{res.writeHead(403);res.end()}return}
    json(404,{error:'not found'});
  }).listen(65531,'127.0.0.1');
  console.log('HTTP server listening on 127.0.0.1:65531');
  setInterval(checkActivityAndMaybeDelete,30000);
}

main();
`;
}

// Sanitize a value for safe use in Caddyfile (strip whitespace, braces, newlines)
function sanitizeCaddyValue(s) {
    if (!s) return '';
    return s.replace(/[\s{}]/g, '');
}

// Build Caddyfile for services
export function buildCaddyConfig(config, serverName) {
    const dns = config.services.dnsService || 'sslip.io';
    const token = config.services.accessToken;

    // Count labels in dns service (e.g., sslip.io = 2, nip.io = 2)
    const dnsLabels = dns.split('.').length;
    // Port is at: total labels - 1 - dnsLabels - 1 (for IP) - 1 (for serverName) = labels from the end
    // For 1234.devbox.1-2-3-4.sslip.io: labels are [io, sslip, 1-2-3-4, devbox, 1234]
    // Index 0=io, 1=sslip, 2=IP, 3=serverName, 4=port
    // So port index = dnsLabels + 2 = 4 for sslip.io
    const portLabelIndex = dnsLabels + 2;

    let caddyfile = '{\n';

    // On-demand TLS for wildcard dynamic services (daemon verifies domain)
    caddyfile += '  on_demand_tls {\n    ask http://localhost:65531/verify-domain\n  }\n';

    switch (config.services.acmeProvider) {
        case 'zerossl':
            caddyfile += '  acme_ca https://acme.zerossl.com/v2/DV90\n';
            if (config.services.zerosslEabKeyId && config.services.zerosslEabKey) {
                caddyfile += `  acme_eab {\n    key_id ${sanitizeCaddyValue(config.services.zerosslEabKeyId)}\n    mac_key ${sanitizeCaddyValue(config.services.zerosslEabKey)}\n  }\n`;
            }
            break;
        case 'buypass':
            caddyfile += '  acme_ca https://api.buypass.com/acme/directory\n';
            break;
        case 'actalis':
            caddyfile += '  acme_ca https://acme-api.actalis.com/acme/directory\n';
            if (config.services.actalisEabKeyId && config.services.actalisEabKey) {
                caddyfile += `  acme_eab {\n    key_id ${sanitizeCaddyValue(config.services.actalisEabKeyId)}\n    mac_key ${toBase64URL(sanitizeCaddyValue(config.services.actalisEabKey))}\n  }\n`;
            }
            break;
        case 'custom':
            if (config.services.customAcmeUrl) caddyfile += `  acme_ca ${sanitizeCaddyValue(config.services.customAcmeUrl)}\n`;
            if (config.services.customEabKeyId && config.services.customEabKey) {
                caddyfile += `  acme_eab {\n    key_id ${sanitizeCaddyValue(config.services.customEabKeyId)}\n    mac_key ${sanitizeCaddyValue(config.services.customEabKey)}\n  }\n`;
            }
            break;
    }
    if (config.services.acmeEmail && /^[^\s{}]+$/.test(config.services.acmeEmail)) {
        caddyfile += `  email ${config.services.acmeEmail}\n`;
    }
    caddyfile += '}\n';

    const authBlock = '  basic_auth {\n    devbox __HASH__\n  }\n';

    // Index page
    caddyfile += `${serverName}.__IP__.${dns} {\n${authBlock}  route /api/* {\n    uri strip_prefix /api\n    reverse_proxy localhost:65531\n  }\n  root * /var/www/devbox-index\n  file_server\n}\n`;

    if (config.services.codeServer) {
        caddyfile += `code.${serverName}.__IP__.${dns} {\n${authBlock}  reverse_proxy localhost:65532\n}\n`;
    }
    if (config.services.claudeTerminal) {
        caddyfile += `claude.${serverName}.__IP__.${dns} {\n${authBlock}  reverse_proxy localhost:65533\n}\n`;
    }
    if (config.services.shellTerminal) {
        caddyfile += `term.${serverName}.__IP__.${dns} {\n${authBlock}  reverse_proxy localhost:65534\n}\n`;
    }

    // Wildcard route for dynamic services - extracts port from subdomain
    // No config changes needed when services come/go - eliminates connection drops
    caddyfile += `*.${serverName}.__IP__.${dns} {\n  tls {\n    on_demand\n  }\n${authBlock}  reverse_proxy localhost:{http.request.host.labels.${portLabelIndex}}\n}\n`;

    return caddyfile;
}

// Build index page HTML (minified, themed)
export function buildIndexPage(config, serverName, themeColors) {
    const colors = themeColors;

    return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="${colors.background}"><title>${serverName}</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:${colors.background};min-height:100vh;color:${colors.foreground};padding:1.5rem;font-size:16px;line-height:1.6}.c{max-width:600px;margin:0 auto}h1{font-size:1.5rem;color:${colors.foreground};margin-bottom:.25rem}.sub{color:${colors.mutedForeground};font-size:1rem;margin-bottom:1.5rem}.card{background:${colors.card};border-radius:.5rem;padding:1.5rem;margin-bottom:1rem;border:2px solid ${colors.border}}.hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem}.ttl{font-size:1rem;color:${colors.mutedForeground}}.ind{display:flex;align-items:center;gap:.5rem}.dot{width:10px;height:10px;border-radius:50%;background:${colors.success};animation:p 2s infinite}.dot.w{background:${colors.warning}}.dot.e{background:${colors.destructive};animation:none}@keyframes p{0%,100%{opacity:1}50%{opacity:.5}}#cd{font-size:2rem;font-weight:600;color:${colors.foreground}}.lbl{font-size:1rem;color:${colors.mutedForeground};margin-top:.25rem}.svcs{display:grid;gap:.75rem}.svc{display:flex;align-items:center;gap:1rem;background:${colors.card};border:2px solid ${colors.border};border-radius:.5rem;padding:1rem;min-height:60px;text-decoration:none;color:inherit;transition:background .15s}.svc:hover{background:${colors.muted}}.svc:focus{outline:3px solid ${colors.focus};outline-offset:2px}.svc.inactive{opacity:.5}.ico{width:44px;height:44px;border-radius:.375rem;display:flex;align-items:center;justify-content:center;font-size:1.25rem;background:${colors.muted}}.inf{flex:1}.nm{font-weight:600;font-size:1rem;color:${colors.foreground}}.ds{font-size:1rem;color:${colors.mutedForeground}}.sdot{width:8px;height:8px;border-radius:50%;flex-shrink:0}.sdot.active{background:${colors.success}}.sdot.inactive{background:${colors.destructive}}</style></head><body><div class="c"><h1>${serverName}</h1><p class="sub">Devbox</p><div class="card"><div class="hdr"><span class="ttl">Auto-shutdown</span><div class="ind"><div id="d" class="dot" role="status" aria-label="Server status indicator"></div><span id="s">Active</span></div></div><div id="cd" aria-live="polite">--:--</div><div class="lbl">until idle shutdown</div></div><nav class="svcs" id="svcs" aria-label="Services"></nav></div><script>const token='${escapeSingleQuotedJS(config.services.accessToken)}';const d=document.getElementById('d'),s=document.getElementById('s'),cd=document.getElementById('cd'),svcsEl=document.getElementById('svcs');let r=-1,w=0;function f(x){if(x<0)return'--:--';return String(Math.floor(x/60)).padStart(2,'0')+':'+String(x%60).padStart(2,'0')}function up(){cd.textContent=f(r);d.className=w?'dot w':r<=0?'dot e':'dot';s.textContent=w?'Warning':r<=0?'Shutting down':'Active'}async function getStatus(){try{const x=await(await fetch(location.origin+'/api/status')).json();r=x.remaining||x.remaining_seconds||0;w=x.warn||x.warning_active;up()}catch{d.className='dot e';s.textContent='Error'}}async function getServices(){try{const svcs=await(await fetch(location.origin+'/api/services')).json();renderServices(svcs)}catch{}}function renderServices(svcs){svcsEl.innerHTML='';for(const svc of svcs){const url='https://devbox:'+encodeURIComponent(token)+'@'+new URL(svc.url).host+'/';const a=document.createElement('a');a.href=url;a.className='svc'+(svc.active?'':' inactive');a.innerHTML='<div class="ico" aria-hidden="true">'+getIcon(svc.name)+'</div><div class="inf"><div class="nm">'+esc(svc.name)+'</div><div class="ds">'+(svc.active?'Active':'Inactive')+(svc.port?' &middot; port '+svc.port:'')+'</div></div><div class="sdot '+(svc.active?'active':'inactive')+'"></div>';svcsEl.appendChild(a)}}function getIcon(name){const m={'VS Code':'\\u2328','Claude':'\\ud83e\\udd16','Terminal':'$_'};return m[name]||'\\ud83c\\udf10'}function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}function t(){if(r>0){r--;up()}}getStatus();getServices();setInterval(getStatus,10000);setInterval(getServices,10000);setInterval(t,1000)</script></body></html>`;
}
