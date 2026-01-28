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

// Build autodelete daemon script with config values baked in
export function buildAutodeleteScript(config, hetznerToken) {
    const timeout = config.autoDelete.timeoutMinutes;
    const warning = config.autoDelete.warningMinutes;
    const gitUser = config.git.userName || '';

    return `#!/usr/bin/env node
const http=require('http'),fs=require('fs'),{execSync}=require('child_process'),https=require('https');
const TIMEOUT=${timeout},WARNING=${warning},TOKEN='${escapeSingleQuotedJS(hetznerToken)}',USER='${escapeSingleQuotedJS(gitUser)}';
let last=Date.now(),warn=false;

function check(){
  let a=false;
  try{if(execSync('who',{encoding:'utf8',timeout:5000}).trim())a=true}catch{}
  try{for(const f of fs.readdirSync('/dev/pts'))if(/^\\d+$/.test(f)&&Date.now()-fs.statSync('/dev/pts/'+f).atimeMs<60000)a=true}catch{}
  if(a){last=Date.now();warn=false}
}

function getServices(){
  const nameMap={code:'VS Code',claude:'Claude',term:'Terminal',app:'Web App'};
  try{
    const cfg=fs.readFileSync('/etc/caddy/Caddyfile','utf8');
    const lines=cfg.split('\\n');
    const blocks=[];
    let cur=null,depth=0;
    for(const line of lines){
      const trimmed=line.trim();
      if(!cur&&/^[a-zA-Z0-9]\\S*\\s*\\{/.test(trimmed)){
        cur={domain:trimmed.split('{')[0].trim(),auth:false,port:null,hasFileServer:false};
        depth=1;continue;
      }
      if(cur){
        if(trimmed.includes('{'))depth++;
        if(trimmed.includes('}'))depth--;
        if(trimmed.includes('file_server'))cur.hasFileServer=true;
        if(/@auth\\s+query\\s+token=/.test(trimmed))cur.auth=true;
        const pm=trimmed.match(/reverse_proxy\\s+localhost:(\\d+)/);
        if(pm&&!cur.port)cur.port=parseInt(pm[1]);
        if(depth===0){blocks.push(cur);cur=null;}
      }
    }
    const services=[];
    for(const b of blocks){
      const sub=b.domain.split('.')[0];
      if(!nameMap[sub])continue;
      const name=nameMap[sub];
      services.push({name,url:'https://'+b.domain,auth:b.auth,active:false,port:b.port});
    }
    let listening=[];
    try{const ss=execSync('ss -tlnp',{encoding:'utf8',timeout:5000});listening=ss.split('\\n')}catch{}
    for(const svc of services){
      if(!svc.port){svc.active=true;continue}
      const pat=':'+svc.port;
      svc.active=listening.some(l=>l.includes(pat+' ')||l.includes(pat+'\\t')||l.endsWith(pat));
    }
    return services;
  }catch(e){return[]}
}

http.createServer((q,r)=>{
  const p=new URL(q.url,'http://x').pathname,j=(c,d)=>{r.writeHead(c,{'Content-Type':'application/json'});r.end(JSON.stringify(d))};
  if(p==='/status'){const i=(Date.now()-last)/1000;return j(200,{idle:Math.floor(i),timeout:TIMEOUT,warning:WARNING,remaining:Math.max(0,Math.floor(TIMEOUT*60-i)),warn,last:new Date(last).toISOString()})}
  if(p==='/keepalive'&&q.method==='POST'){last=Date.now();warn=false;return j(200,{ok:true})}
  if(p==='/services'){return j(200,getServices())}
  j(404,{error:'not found'})
}).listen(8081,'127.0.0.1');

let sid;try{sid=execSync('curl -s -H "Metadata-Flavor:hetzner" http://169.254.169.254/hetzner/v1/metadata/instance-id',{encoding:'utf8',timeout:5000}).trim()}catch{}
if(!sid)process.exit(0);

function del(){https.request({hostname:'api.hetzner.cloud',path:'/v1/servers/'+sid,method:'DELETE',headers:{Authorization:'Bearer '+TOKEN}},()=>process.exit(0)).end()}

function wip(){
  try{for(const d of fs.readdirSync('/home/dev')){
    if(/[^a-zA-Z0-9._-]/.test(d))continue;
    const p='/home/dev/'+d;if(!fs.statSync(p).isDirectory()||!fs.existsSync(p+'/.git'))continue;
    try{if(!execSync('git -C '+JSON.stringify(p)+' status --porcelain',{encoding:'utf8'}).trim())continue;
      const b=(USER?'wip/'+USER.replace(/[^a-zA-Z0-9._-]/g,'_')+'/':'wip/')+new Date().toISOString().replace(/[T:]/g,'-').slice(0,19);
      execSync('git -C '+JSON.stringify(p)+' checkout -b '+JSON.stringify(b)+' && git -C '+JSON.stringify(p)+' add -A && git -C '+JSON.stringify(p)+' commit -m WIP && git -C '+JSON.stringify(p)+' push -u origin '+JSON.stringify(b),{timeout:60000})
    }catch{}}
  }catch{}
}

setInterval(()=>{check();const i=(Date.now()-last)/1000;if(TIMEOUT*60-i<=WARNING*60&&!warn)warn=true;if(i>=TIMEOUT*60){wip();del()}},30000);
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
    let caddyfile = '{\n';

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
    caddyfile += `${serverName}.__IP__.${dns} {\n${authBlock}  route /api/* {\n    uri strip_prefix /api\n    reverse_proxy localhost:8081\n  }\n  root * /var/www/devbox-index\n  file_server\n}\n`;

    if (config.services.codeServer) {
        caddyfile += `code.${serverName}.__IP__.${dns} {\n${authBlock}  reverse_proxy localhost:8090\n}\n`;
    }
    if (config.services.claudeTerminal) {
        caddyfile += `claude.${serverName}.__IP__.${dns} {\n${authBlock}  reverse_proxy localhost:7681\n}\n`;
    }
    if (config.services.shellTerminal) {
        caddyfile += `term.${serverName}.__IP__.${dns} {\n${authBlock}  reverse_proxy localhost:7682\n}\n`;
    }
    return caddyfile;
}

// Build index page HTML (minified, themed)
export function buildIndexPage(config, serverName, themeColors) {
    const colors = themeColors;

    return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="${colors.background}"><title>${serverName}</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:${colors.background};min-height:100vh;color:${colors.foreground};padding:1.5rem;font-size:16px;line-height:1.6}.c{max-width:600px;margin:0 auto}h1{font-size:1.5rem;color:${colors.foreground};margin-bottom:.25rem}.sub{color:${colors.mutedForeground};font-size:1rem;margin-bottom:1.5rem}.card{background:${colors.card};border-radius:.5rem;padding:1.5rem;margin-bottom:1rem;border:2px solid ${colors.border}}.hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem}.ttl{font-size:1rem;color:${colors.mutedForeground}}.ind{display:flex;align-items:center;gap:.5rem}.dot{width:10px;height:10px;border-radius:50%;background:${colors.success};animation:p 2s infinite}.dot.w{background:${colors.warning}}.dot.e{background:${colors.destructive};animation:none}@keyframes p{0%,100%{opacity:1}50%{opacity:.5}}#cd{font-size:2rem;font-weight:600;color:${colors.foreground}}.lbl{font-size:1rem;color:${colors.mutedForeground};margin-top:.25rem}.svcs{display:grid;gap:.75rem}.svc{display:flex;align-items:center;gap:1rem;background:${colors.card};border:2px solid ${colors.border};border-radius:.5rem;padding:1rem;min-height:60px;text-decoration:none;color:inherit;transition:background .15s}.svc:hover{background:${colors.muted}}.svc:focus{outline:3px solid ${colors.focus};outline-offset:2px}.svc.inactive{opacity:.5}.ico{width:44px;height:44px;border-radius:.375rem;display:flex;align-items:center;justify-content:center;font-size:1.25rem;background:${colors.muted}}.inf{flex:1}.nm{font-weight:600;font-size:1rem;color:${colors.foreground}}.ds{font-size:1rem;color:${colors.mutedForeground}}.sdot{width:8px;height:8px;border-radius:50%;flex-shrink:0}.sdot.active{background:${colors.success}}.sdot.inactive{background:${colors.destructive}}</style></head><body><div class="c"><h1>${serverName}</h1><p class="sub">Devbox</p><div class="card"><div class="hdr"><span class="ttl">Auto-shutdown</span><div class="ind"><div id="d" class="dot" role="status" aria-label="Server status indicator"></div><span id="s">Active</span></div></div><div id="cd" aria-live="polite">--:--</div><div class="lbl">until idle shutdown</div></div><nav class="svcs" id="svcs" aria-label="Services"></nav></div><script>const token='${escapeSingleQuotedJS(config.services.accessToken)}';const d=document.getElementById('d'),s=document.getElementById('s'),cd=document.getElementById('cd'),svcsEl=document.getElementById('svcs');let r=-1,w=0;function f(x){if(x<0)return'--:--';return String(Math.floor(x/60)).padStart(2,'0')+':'+String(x%60).padStart(2,'0')}function up(){cd.textContent=f(r);d.className=w?'dot w':r<=0?'dot e':'dot';s.textContent=w?'Warning':r<=0?'Shutting down':'Active'}async function getStatus(){try{const x=await(await fetch(location.origin+'/api/status')).json();r=x.remaining||x.remaining_seconds||0;w=x.warn||x.warning_active;up()}catch{d.className='dot e';s.textContent='Error'}}async function getServices(){try{const svcs=await(await fetch(location.origin+'/api/services')).json();renderServices(svcs)}catch{}}function renderServices(svcs){svcsEl.innerHTML='';for(const svc of svcs){const url='https://devbox:'+encodeURIComponent(token)+'@'+new URL(svc.url).host+'/';const a=document.createElement('a');a.href=url;a.className='svc'+(svc.active?'':' inactive');a.innerHTML='<div class="ico" aria-hidden="true">'+getIcon(svc.name)+'</div><div class="inf"><div class="nm">'+esc(svc.name)+'</div><div class="ds">'+(svc.active?'Active':'Inactive')+(svc.port?' &middot; port '+svc.port:'')+'</div></div><div class="sdot '+(svc.active?'active':'inactive')+'"></div>';svcsEl.appendChild(a)}}function getIcon(name){const m={'VS Code':'\\u2328','Claude':'\\ud83e\\udd16','Terminal':'$_','Web App':'\\ud83c\\udf10'};return m[name]||'\\ud83d\\udd17'}function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}function t(){if(r>0){r--;up()}}getStatus();getServices();setInterval(getStatus,10000);setInterval(getServices,30000);setInterval(t,1000)</script></body></html>`;
}
