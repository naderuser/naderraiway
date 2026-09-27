// VLESS over WebSocket - Node.js server for Railway (or any plain Node host).
//
// Unlike the Cloudflare Workers version, this process can open a normal outbound TCP
// connection to anywhere (including Cloudflare's own IPs), so there is no ProxyIP relay,
// no "clean IP" fetching, and no country filter here - none of that is needed. What this
// keeps from the Workers version: multi-user VLESS-over-WS, per-user expiry + data quota
// (tracked exactly here, since this is one long-running process, not many distributed
// isolates), a subscription link, UDP DNS over DoH, and a web admin panel.
//
// Env vars:
//   ADMIN_PASSWORD   (required) - password for /admin
//   PORT             (optional) - Railway sets this automatically
//   DATA_FILE        (optional) - where config is persisted, default ./data.json
//                                  On Railway, point this at a mounted Volume so data
//                                  survives redeploys, e.g. /data/data.json
//   ADDRS            (optional) - comma/newline separated host[:port] list to use in
//                                  generated links instead of the request's Host header
//                                  (e.g. if you put a custom domain in front of this app)

const http = require('http');
const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');

const PORT = parseInt(process.env.PORT, 10) || 8080;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const ENV_ADDRS = process.env.ADDRS || '';

const BYTES_PER_GB = 1024 * 1024 * 1024;
const MAX_QUOTA_GB = 100000;
const MAX_USERS = 50;
const DOH_URL = 'https://cloudflare-dns.com/dns-query';

/* --------------------------------- Config store -------------------------------- */
// A single JSON file is enough for personal-scale use and avoids native dependencies
// (no SQLite build step on Railway). Since this is one process, updates here are exact -
// no cross-isolate races like the Workers version had to work around.

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function loadConfig() {
  let cfg = null;
  try {
    cfg = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch (_) {}

  let dirty = false;
  if (!cfg || typeof cfg !== 'object') { cfg = {}; dirty = true; }
  if (!Array.isArray(cfg.users)) { cfg.users = []; dirty = true; }
  if (!cfg.users.length) {
    cfg.users.push({ uuid: crypto.randomUUID(), name: 'default', expiresAt: null, quotaBytes: null, usedBytes: 0 });
    dirty = true;
  }
  for (const u of cfg.users) {
    if (!UUID_RE.test(u.uuid || '')) { u.uuid = crypto.randomUUID(); dirty = true; }
    u.uuid = u.uuid.toLowerCase();
    if (typeof u.name !== 'string' || !u.name) { u.name = 'user'; dirty = true; }
    if (u.expiresAt !== null && !Number.isFinite(u.expiresAt)) { u.expiresAt = null; dirty = true; }
    if (u.quotaBytes !== null && !Number.isFinite(u.quotaBytes)) { u.quotaBytes = null; dirty = true; }
    if (!Number.isFinite(u.usedBytes)) { u.usedBytes = 0; dirty = true; }
  }
  if (!cfg.subToken) { cfg.subToken = randomToken(); dirty = true; }
  if (typeof cfg.addrs !== 'string') { cfg.addrs = ''; dirty = true; }

  if (dirty) saveConfig(cfg);
  return cfg;
}

function saveConfig(cfg) {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(cfg, null, 2));
}

function randomToken() {
  return crypto.randomBytes(24).toString('hex');
}

// Config lives in memory for the life of the process, saved to disk on every change.
let CFG = loadConfig();

/* ------------------------------ Shared small helpers ----------------------------- */

function splitList(text) {
  return String(text || '').split(/[\r\n,;]+/).map((s) => s.trim()).filter(Boolean);
}

function splitHostPort(s) {
  s = String(s).trim();
  let m = s.match(/^(\[[^\]]+\])(?::(\d+))?$/);
  if (m) return [m[1], m[2] ? parseInt(m[2], 10) : null];
  m = s.match(/^([^:]+)(?::(\d+))?$/);
  if (m) return [m[1], m[2] ? parseInt(m[2], 10) : null];
  return [s, null];
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function sha256(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function parseCookies(str) {
  const out = {};
  String(str || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return out;
}

function connectAddrs(host) {
  const fromEnv = splitList(ENV_ADDRS);
  const fromCfg = splitList(CFG.addrs);
  const items = fromCfg.length ? fromCfg : fromEnv;
  if (!items.length) return [[host, 443]];
  return items.map((s) => {
    const [a, p] = splitHostPort(s);
    return [a, p || 443];
  });
}

function vlessLink(u, host, addr, port) {
  const label = encodeURIComponent(addr === host ? u.name : `${u.name}-${addr}`);
  return (
    `vless://${u.uuid}@${addr}:${port}?encryption=none&security=tls&sni=${host}` +
    `&fp=chrome&type=ws&host=${host}&path=%2F%3Fed%3D2048#${label}`
  );
}

// null = OK to use; otherwise a short reason.
function checkUserStatus(user) {
  if (user.expiresAt && Date.now() > user.expiresAt) return 'expired';
  if (user.quotaBytes && (user.usedBytes || 0) >= user.quotaBytes) return 'quota';
  return null;
}

function addUsage(uuid, bytes) {
  if (!bytes) return;
  const u = CFG.users.find((x) => x.uuid === uuid);
  if (u) {
    u.usedBytes = (u.usedBytes || 0) + bytes;
    saveConfig(CFG);
  }
}

/* --------------------------------- VLESS parsing -------------------------------- */

function parseVless(buf, usersById) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  if (b.length < 24) return { error: 'header too short' };

  const version = b[0];
  const id = Array.from(b.slice(1, 17)).map((x) => x.toString(16).padStart(2, '0')).join('');
  if (!usersById.has(id)) return { error: 'invalid uuid' };

  const addonLen = b[17];
  let i = 18 + addonLen;

  const cmd = b[i++];
  if (cmd !== 1 && cmd !== 2) return { error: 'unsupported command ' + cmd };

  const port = (b[i] << 8) | b[i + 1];
  i += 2;

  const atype = b[i++];
  let address = '';

  if (atype === 1) {
    address = Array.from(b.slice(i, i + 4)).join('.');
    i += 4;
  } else if (atype === 2) {
    const len = b[i++];
    address = new TextDecoder().decode(b.slice(i, i + len));
    i += len;
  } else if (atype === 3) {
    const parts = [];
    for (let k = 0; k < 8; k++) parts.push(((b[i + k * 2] << 8) | b[i + k * 2 + 1]).toString(16));
    address = parts.join(':');
    i += 16;
  } else {
    return { error: 'unknown address type' };
  }

  if (!address) return { error: 'empty address' };
  return { version, id, address, port, payload: b.slice(i), isUdp: cmd === 2 };
}

// UDP DNS over VLESS: payload is [2-byte length][DNS query] repeated.
// Each query is forwarded to a DoH server and answered in the same framing.
function createDnsHandler(ws, version) {
  let headerSent = false;
  let buf = Buffer.alloc(0);

  return async (chunk) => {
    buf = Buffer.concat([buf, Buffer.from(chunk)]);

    while (buf.length >= 2) {
      const len = (buf[0] << 8) | buf[1];
      if (buf.length < 2 + len) break;
      const query = buf.subarray(2, 2 + len);
      buf = buf.subarray(2 + len);

      let answer;
      try {
        const resp = await fetch(DOH_URL, {
          method: 'POST',
          headers: { 'content-type': 'application/dns-message', accept: 'application/dns-message' },
          body: query,
        });
        answer = Buffer.from(await resp.arrayBuffer());
      } catch (_) {
        answer = Buffer.alloc(0);
      }

      const prefix = headerSent ? 0 : 2;
      const out = Buffer.alloc(prefix + 2 + answer.length);
      if (!headerSent) {
        out[0] = version;
        out[1] = 0;
        headerSent = true;
      }
      out.writeUInt16BE(answer.length, prefix);
      answer.copy(out, prefix + 2);

      if (ws.readyState === ws.OPEN) ws.send(out);
    }
  };
}

/* ------------------------------- WebSocket handling ------------------------------ */

function handleConnection(ws) {
  const usersById = new Map(CFG.users.map((u) => [u.uuid.replace(/-/g, ''), u]));

  let remoteSocket = null;
  let udpHandler = null;
  let closed = false;
  let activeUser = null;
  let bytesThisConn = 0;

  function trackBytes(n) {
    bytesThisConn += n;
    if (activeUser && activeUser.quotaBytes && (activeUser.usedBytes || 0) + bytesThisConn >= activeUser.quotaBytes) {
      closeAll();
    }
  }

  function closeAll() {
    if (closed) return;
    closed = true;
    try { remoteSocket && remoteSocket.destroy(); } catch (_) {}
    try { ws.close(); } catch (_) {}
    if (activeUser && bytesThisConn > 0) addUsage(activeUser.uuid, bytesThisConn);
  }

  function connectTcp(address, port, payload) {
    return new Promise((resolve, reject) => {
      const sock = net.connect({ host: address, port }, () => {
        if (payload && payload.length) {
          sock.write(payload);
          trackBytes(payload.length);
        }
        resolve(sock);
      });
      sock.once('error', reject);
      sock.setTimeout(10000, () => sock.destroy(new Error('connect timeout')));
    });
  }

  function pipeRemoteToWs(sock, version) {
    let header = Buffer.from([version, 0]);
    remoteSocket = sock;

    sock.on('data', (chunk) => {
      trackBytes(chunk.length);
      if (ws.readyState !== ws.OPEN) return;
      if (header) {
        ws.send(Buffer.concat([header, chunk]));
        header = null;
      } else {
        ws.send(chunk);
      }
    });
    sock.on('close', closeAll);
    sock.on('error', closeAll);
  }

  async function onChunk(data) {
    if (closed) return;

    if (udpHandler) {
      await udpHandler(data);
      return;
    }
    if (remoteSocket) {
      trackBytes(data.length);
      remoteSocket.write(data);
      return;
    }

    const h = parseVless(data, usersById);
    if (h.error) throw new Error(h.error);

    const user = usersById.get(h.id);
    const status = user ? checkUserStatus(user) : 'invalid';
    if (status) throw new Error('user ' + status);
    activeUser = user;

    if (h.isUdp) {
      if (h.port !== 53) throw new Error('UDP is only supported for DNS (port 53)');
      udpHandler = createDnsHandler(ws, h.version);
      if (h.payload.length) await udpHandler(h.payload);
      return;
    }

    const sock = await connectTcp(h.address, h.port, h.payload);
    pipeRemoteToWs(sock, h.version);
  }

  // Process messages sequentially - correct for a single VLESS TCP stream, and simple.
  let queue = Promise.resolve();
  ws.on('message', (data, isBinary) => {
    if (!isBinary) return;
    queue = queue.then(() => onChunk(data)).catch((e) => {
      console.log('vless error:', e && e.message ? e.message : e);
      closeAll();
    });
  });

  ws.on('close', closeAll);
  ws.on('error', closeAll);
}

/* ---------------------------------- Admin panel ---------------------------------- */

const SEC_HEADERS = {
  'Cache-Control': 'no-store',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'Content-Security-Policy':
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
};

function sendHtml(res, body, status = 200) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', ...SEC_HEADERS });
  res.end(body);
}

function sendJson(res, obj, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 1024 * 1024) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function readJsonBody(req) {
  const raw = await readBody(req);
  if (!raw.length) return {};
  try { return JSON.parse(raw.toString('utf8')); } catch (_) { return {}; }
}

function publicState(host) {
  const addrs = connectAddrs(host);
  return {
    host,
    maxUsers: MAX_USERS,
    subUrl: `https://${host}/sub/${CFG.subToken}`,
    addrs: CFG.addrs,
    users: CFG.users.map((u) => ({
      uuid: u.uuid,
      name: u.name,
      expiresAt: u.expiresAt || null,
      quotaBytes: u.quotaBytes || null,
      usedBytes: u.usedBytes || 0,
      status: checkUserStatus(u),
      links: addrs.map(([a, p]) => ({ label: a === host ? 'پیش‌فرض' : a, url: vlessLink(u, host, a, p) })),
    })),
  };
}

async function handleAdminApi(req, res, url, authed) {
  if (!authed) return sendJson(res, { error: 'unauthorized' }, 401);
  const action = url.pathname.slice('/admin/api/'.length);
  const host = req.headers.host || 'localhost';

  if (req.method === 'GET' && action === 'state') return sendJson(res, publicState(host));
  if (req.method !== 'POST') return sendJson(res, { error: 'method not allowed' }, 405);

  const body = await readJsonBody(req);

  if (action === 'logout') {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': 'auth=; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0',
    });
    return res.end(JSON.stringify({ ok: true }));
  }

  try {
    switch (action) {
      case 'user/add': {
        if (CFG.users.length >= MAX_USERS) throw new Error(`حداکثر ${MAX_USERS} کاربر`);
        const name = String(body.name || '').trim().slice(0, 32) || 'user';
        CFG.users.push({ uuid: crypto.randomUUID(), name, expiresAt: null, quotaBytes: null, usedBytes: 0 });
        break;
      }
      case 'user/delete': {
        if (CFG.users.length <= 1) throw new Error('حداقل یک کاربر لازم است');
        const uuid = String(body.uuid || '').toLowerCase();
        CFG.users = CFG.users.filter((u) => u.uuid !== uuid);
        break;
      }
      case 'user/rename': {
        const name = String(body.name || '').trim().slice(0, 32);
        if (!name) throw new Error('نام خالی است');
        const u = CFG.users.find((x) => x.uuid === String(body.uuid || '').toLowerCase());
        if (!u) throw new Error('کاربر پیدا نشد');
        u.name = name;
        break;
      }
      case 'user/set-limits': {
        const u = CFG.users.find((x) => x.uuid === String(body.uuid || '').toLowerCase());
        if (!u) throw new Error('کاربر پیدا نشد');

        const dateStr = String(body.expiresAt || '').trim();
        if (!dateStr) u.expiresAt = null;
        else {
          const t = Date.parse(dateStr + 'T23:59:59Z');
          if (!Number.isFinite(t)) throw new Error('تاریخ نامعتبر است');
          u.expiresAt = t;
        }

        const gbStr = String(body.quotaGB || '').trim();
        if (!gbStr) u.quotaBytes = null;
        else {
          const gb = Number(gbStr);
          if (!Number.isFinite(gb) || gb <= 0 || gb > MAX_QUOTA_GB) throw new Error('حجم نامعتبر است');
          u.quotaBytes = Math.round(gb * BYTES_PER_GB);
        }
        break;
      }
      case 'user/reset-usage': {
        const u = CFG.users.find((x) => x.uuid === String(body.uuid || '').toLowerCase());
        if (!u) throw new Error('کاربر پیدا نشد');
        u.usedBytes = 0;
        break;
      }
      case 'addr/save': {
        const items = splitList(body.addrs);
        if (items.length > 20) throw new Error('حداکثر ۲۰ آدرس مجاز است');
        CFG.addrs = items.join('\n');
        break;
      }
      case 'sub/regen': {
        CFG.subToken = randomToken();
        break;
      }
      default:
        return sendJson(res, { error: 'not found' }, 404);
    }
  } catch (e) {
    return sendJson(res, { error: e && e.message ? e.message : String(e) }, 400);
  }

  saveConfig(CFG);
  return sendJson(res, { ok: true, state: publicState(host) });
}

const STYLE = `
:root{
  --canvas:#eef1f4;--surface:#fff;--ink:#14202b;--muted:#5b6b78;--line:#d6dce3;
  --accent:#0f5c63;--accent-ink:#fff;--soft:#e3eff0;--ok:#1f7a4c;--bad:#b4322a;--warn:#a86f0c;
  --mono:ui-monospace,SFMono-Regular,Consolas,Menlo,monospace;
  --sans:Vazirmatn,IRANSans,"Segoe UI",Tahoma,Arial,sans-serif;
}
@media (prefers-color-scheme:dark){:root{
  --canvas:#0e1a20;--surface:#15252d;--ink:#e6eef2;--muted:#95a8b4;--line:#2a3d47;
  --accent:#4fb7b0;--accent-ink:#06211f;--soft:#1b3237;--ok:#5fcf97;--bad:#ef7d74;--warn:#e0a94a;
}}
*{box-sizing:border-box}
body{margin:0;background:var(--canvas);color:var(--ink);font-family:var(--sans);font-size:15px;line-height:1.7}
.wrap{max-width:860px;margin:0 auto;padding:16px}
header.top{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:8px 0 14px}
header.top h1{font-size:18px;margin:0}
.tabs{display:flex;gap:4px;overflow-x:auto;border-bottom:1px solid var(--line);margin-bottom:16px}
.tab{background:none;border:0;color:var(--muted);padding:10px 14px;cursor:pointer;font:inherit;border-bottom:2px solid transparent;white-space:nowrap}
.tab.on{color:var(--ink);border-bottom-color:var(--accent);font-weight:700}
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:14px;box-shadow:0 1px 2px rgba(0,0,0,.04),0 1px 12px rgba(0,0,0,.03)}
.card h3{margin:0 0 10px;font-size:16px}
.card h4{margin:14px 0 6px;font-size:14px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:14px}
.stat{background:var(--surface);border:1px solid var(--line);border-inline-start:3px solid var(--accent);border-radius:10px;padding:10px 14px}
.stat span{display:block;color:var(--muted);font-size:13px}
.stat b{font-size:16px;word-break:break-all}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600}
.badge.ok{background:color-mix(in srgb,var(--ok) 18%,transparent);color:var(--ok)}
.badge.bad{background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)}
.bar{background:var(--canvas);border:1px solid var(--line);border-radius:6px;overflow:hidden;height:8px;margin:6px 0}
.bar > div{height:100%;background:var(--accent)}
.bar.bad > div{background:var(--bad)}
input[type=text],input:not([type]),textarea,input[type=date]{width:100%;background:var(--canvas);color:var(--ink);border:1px solid var(--line);border-radius:6px;padding:9px 10px;font:inherit;margin:4px 0 10px}
textarea{font-family:var(--mono);font-size:13px;direction:ltr;resize:vertical}
.ltr{direction:ltr;text-align:left;font-family:var(--mono);font-size:13px}
input.ltr{font-family:var(--mono)}
.field{display:inline-block;min-width:150px;margin-inline-end:8px;vertical-align:top}
.field label{display:block;font-size:12px;color:var(--muted);margin-bottom:2px}
.field input{margin:0}
code.blk{display:block;background:var(--canvas);border:1px solid var(--line);border-radius:6px;padding:8px 10px;margin:6px 0;word-break:break-all;direction:ltr;text-align:left;font-family:var(--mono);font-size:12.5px}
.btn{background:var(--accent);color:var(--accent-ink);border:0;border-radius:6px;padding:8px 14px;cursor:pointer;font:inherit;transition:filter .12s,transform .05s}
.btn:hover{filter:brightness(1.08)}
.btn:active{transform:translateY(1px)}
.btn.sm{padding:4px 10px;font-size:13px}
.btn.ghost{background:transparent;color:var(--ink);border:1px solid var(--line)}
.btn.ghost:hover{background:var(--soft)}
.btn.danger{background:transparent;color:var(--bad);border:1px solid var(--bad)}
.btn.danger:hover{background:color-mix(in srgb,var(--bad) 12%,transparent)}
.row{display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap}
.user{border-top:1px solid var(--line);padding:12px 0}
.user:first-of-type{border-top:0}
.note{color:var(--muted);font-size:13px;margin:8px 0 0}
#toast{position:fixed;inset-inline:0;bottom:18px;display:flex;justify-content:center;pointer-events:none}
#toast div{background:var(--ink);color:var(--canvas);padding:8px 16px;border-radius:8px;font-size:14px}
#toast div.bad{background:var(--bad);color:#fff}
.login{max-width:360px;margin:12vh auto}
`;

function loginPage(msg) {
  return `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>ورود</title><style>${STYLE}</style></head>
<body><div class="wrap"><div class="card login"><h3>ورود به پنل</h3>
${msg ? `<p class="badge bad">${esc(msg)}</p>` : ''}
<form method="POST" action="/admin/login">
<input type="password" name="password" placeholder="رمز عبور" autocomplete="current-password" autofocus required>
<button class="btn" type="submit">ورود</button></form></div></div></body></html>`;
}

function clientMain() {
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  let S = null, tab = 'overview';

  async function api(path, body) {
    const opt = body === undefined ? {} : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) };
    const r = await fetch('/admin/api/' + path, opt);
    if (r.status === 401) { location.reload(); throw new Error('نشست منقضی شد'); }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || 'خطا ' + r.status);
    return j;
  }

  let toastTimer = null;
  function toast(msg, bad) {
    const el = $('#toast');
    el.innerHTML = '<div class="' + (bad ? 'bad' : '') + '">' + esc(msg) + '</div>';
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.innerHTML = ''; }, 2600);
  }

  async function doAct(path, body, okMsg) {
    try {
      const j = await api(path, body);
      if (j.state) S = j.state;
      toast(okMsg || 'انجام شد');
      render();
    } catch (e) { toast(e.message, true); }
  }

  function copy(t) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(t).then(() => toast('کپی شد'), () => window.prompt('کپی کنید:', t));
    } else { window.prompt('کپی کنید:', t); }
  }

  const views = {
    overview() {
      return '<div class="stats">' +
        '<div class="stat"><span>کاربران</span><b>' + S.users.length + ' از ' + S.maxUsers + '</b></div>' +
        '<div class="stat"><span>دامنه</span><b class="ltr">' + esc(S.host) + '</b></div></div>' +
        '<section class="card"><h3>لینک اشتراک</h3><code class="blk">' + esc(S.subUrl) + '</code>' +
        '<button class="btn sm" data-copy="' + esc(S.subUrl) + '">کپی لینک اشتراک</button>' +
        '<p class="note">این لینک را در کلاینت به‌عنوان Subscription اضافه کنید و به‌روزرسانی خودکار اشتراک را در کلاینت روشن کنید.</p></section>';
    },
    users() {
      const list = S.users.map((u) => {
        const badge = u.status === 'expired' ? '<span class="badge bad">منقضی‌شده</span>'
          : u.status === 'quota' ? '<span class="badge bad">اتمام حجم</span>'
          : '<span class="badge ok">فعال</span>';
        const expiryVal = u.expiresAt ? new Date(u.expiresAt).toISOString().slice(0, 10) : '';
        const quotaVal = u.quotaBytes ? (u.quotaBytes / 1073741824).toFixed(2) : '';
        const usedGB = (u.usedBytes / 1073741824).toFixed(2);
        const quotaGB = u.quotaBytes ? (u.quotaBytes / 1073741824).toFixed(2) : null;
        const pct = quotaGB ? Math.min(100, (u.usedBytes / u.quotaBytes) * 100) : 0;
        return '<div class="user"><div class="row"><span><b>' + esc(u.name) + '</b> ' + badge + '</span><span>' +
          '<button class="btn sm ghost" data-act="user-rename" data-uuid="' + esc(u.uuid) + '">تغییر نام</button> ' +
          '<button class="btn sm danger" data-act="user-delete" data-uuid="' + esc(u.uuid) + '">حذف</button></span></div>' +
          '<code class="blk">' + esc(u.uuid) + '</code>' +
          '<button class="btn sm ghost" data-copy="' + esc(u.uuid) + '">کپی UUID</button>' +
          '<h4>محدودیت‌ها</h4>' +
          '<div class="field"><label>تاریخ انقضا</label><input type="date" class="limit-expiry" value="' + esc(expiryVal) + '"></div>' +
          '<div class="field"><label>سقف حجم (گیگابایت)</label><input type="text" inputmode="decimal" class="limit-quota ltr" placeholder="نامحدود" value="' + esc(quotaVal) + '"></div>' +
          '<button class="btn sm" data-act="user-limits" data-uuid="' + esc(u.uuid) + '">ذخیره محدودیت‌ها</button>' +
          '<div class="row" style="margin-top:8px"><span>مصرف: <b>' + usedGB + ' GB</b>' + (quotaGB ? ' از ' + quotaGB + ' GB' : ' (نامحدود)') + '</span>' +
          '<button class="btn sm ghost" data-act="user-reset-usage" data-uuid="' + esc(u.uuid) + '">ریست مصرف</button></div>' +
          (quotaGB ? '<div class="bar' + (pct >= 100 ? ' bad' : '') + '"><div style="width:' + pct.toFixed(1) + '%"></div></div>' : '') +
          u.links.map((l) =>
            '<div class="row" style="margin-top:8px"><small class="note">' + esc(l.label) + '</small>' +
            '<button class="btn sm" data-copy="' + esc(l.url) + '">کپی لینک VLESS</button></div>' +
            '<code class="blk">' + esc(l.url) + '</code>').join('') +
          '</div>';
      }).join('');
      return '<section class="card"><h3>کاربران (' + S.users.length + ' از ' + S.maxUsers + ')</h3>' + list + '</section>' +
        '<section class="card"><h3>افزودن کاربر</h3><input id="newname" placeholder="نام کاربر" maxlength="32">' +
        '<button class="btn" data-act="user-add">افزودن</button></section>';
    },
    sub() {
      return '<section class="card"><h3>لینک اشتراک</h3><code class="blk">' + esc(S.subUrl) + '</code>' +
        '<button class="btn sm" data-copy="' + esc(S.subUrl) + '">کپی</button> ' +
        '<button class="btn sm danger" data-act="sub-regen">ساخت لینک جدید</button>' +
        '<p class="note">هر کس این لینک را داشته باشد به همه‌ی کاربران دسترسی دارد.</p></section>' +
        '<section class="card"><h3>آدرس‌های اتصال</h3>' +
        '<p class="note">اگر پشت این سرور یک دامنه‌ی سفارشی گذاشته‌اید، اینجا وارد کنید تا در لینک‌ها استفاده شود. خالی = همان دامنه‌ای که با آن به پنل وصل شده‌اید.</p>' +
        '<textarea id="addrs" rows="4" placeholder="example.com:443">' + esc(S.addrs) + '</textarea>' +
        '<button class="btn" data-act="addr-save">ذخیره</button></section>';
    },
  };

  function render() {
    if (!S) return;
    const tabs = [['overview', 'نمای کلی'], ['users', 'کاربران'], ['sub', 'اشتراک و آدرس‌ها']];
    $('#app').innerHTML =
      '<header class="top"><h1>پنل مدیریت</h1><button class="btn sm ghost" data-act="logout">خروج</button></header>' +
      '<nav class="tabs">' + tabs.map((t) => '<button class="tab ' + (t[0] === tab ? 'on' : '') + '" data-act="tab" data-tab="' + t[0] + '">' + t[1] + '</button>').join('') + '</nav>' +
      views[tab]();
  }

  document.addEventListener('click', async (e) => {
    const c = e.target.closest('[data-copy]');
    if (c) { copy(c.dataset.copy); return; }
    const a = e.target.closest('[data-act]');
    if (!a) return;
    const act = a.dataset.act;
    if (act === 'tab') { tab = a.dataset.tab; render(); }
    else if (act === 'user-add') await doAct('user/add', { name: $('#newname').value }, 'کاربر اضافه شد');
    else if (act === 'user-delete') { if (window.confirm('این کاربر حذف شود؟')) await doAct('user/delete', { uuid: a.dataset.uuid }, 'کاربر حذف شد'); }
    else if (act === 'user-rename') { const n = window.prompt('نام جدید:'); if (n) await doAct('user/rename', { uuid: a.dataset.uuid, name: n }, 'نام ذخیره شد'); }
    else if (act === 'user-limits') {
      const box = a.closest('.user');
      const expiresAt = box.querySelector('.limit-expiry').value;
      const quotaGB = box.querySelector('.limit-quota').value;
      await doAct('user/set-limits', { uuid: a.dataset.uuid, expiresAt, quotaGB }, 'محدودیت‌ها ذخیره شد');
    }
    else if (act === 'user-reset-usage') { if (window.confirm('مصرف این کاربر صفر شود؟')) await doAct('user/reset-usage', { uuid: a.dataset.uuid }, 'مصرف صفر شد'); }
    else if (act === 'addr-save') await doAct('addr/save', { addrs: $('#addrs').value }, 'آدرس‌ها ذخیره شد');
    else if (act === 'sub-regen') { if (window.confirm('لینک قبلی باطل می‌شود. ادامه؟')) await doAct('sub/regen', {}, 'لینک اشتراک جدید ساخته شد'); }
    else if (act === 'logout') { try { await api('logout', {}); } catch (_) {} location.reload(); }
  });

  api('state').then((j) => { S = j; render(); }).catch((e) => { $('#app').innerHTML = '<p class="badge bad">' + esc(e.message) + '</p>'; });
}

function panelPage() {
  return `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>پنل مدیریت</title><style>${STYLE}</style></head>
<body><div class="wrap" id="app"><p class="note">در حال بارگذاری…</p></div><div id="toast"></div>
<script>(${clientMain.toString()})();</script></body></html>`;
}

async function handleAdmin(req, res, url) {
  if (!ADMIN_PASSWORD) {
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    return res.end('ADMIN_PASSWORD environment variable is not set');
  }

  const token = sha256(ADMIN_PASSWORD);
  const cookies = parseCookies(req.headers.cookie);
  const authed = cookies.auth ? safeEqual(cookies.auth, token) : false;

  if (req.method === 'POST' && url.pathname === '/admin/login') {
    const raw = await readBody(req);
    const params = new URLSearchParams(raw.toString('utf8'));
    const pass = params.get('password') || '';
    if (safeEqual(sha256(pass), token)) {
      res.writeHead(302, {
        Location: '/admin',
        'Set-Cookie': `auth=${token}; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`,
      });
      return res.end();
    }
    await new Promise((r) => setTimeout(r, 600));
    return sendHtml(res, loginPage('رمز اشتباه است'), 401);
  }

  if (url.pathname.startsWith('/admin/api/')) return handleAdminApi(req, res, url, authed);
  if (!authed) return sendHtml(res, loginPage(''));
  return sendHtml(res, panelPage());
}

/* ------------------------------------- HTTP -------------------------------------- */

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (url.pathname.startsWith('/sub/')) {
      const token = url.pathname.slice('/sub/'.length);
      if (!safeEqual(token, CFG.subToken)) { res.writeHead(404); return res.end('Not found'); }
      const host = req.headers.host || 'localhost';
      const addrs = connectAddrs(host);
      const lines = [];
      for (const u of CFG.users) for (const [a, p] of addrs) lines.push(vlessLink(u, host, a, p));
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(Buffer.from(lines.join('\n')).toString('base64'));
    }

    if (url.pathname === '/admin' || url.pathname.startsWith('/admin/')) {
      return await handleAdmin(req, res, url);
    }

    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('OK');
  } catch (err) {
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Error: ' + (err && err.message ? err.message : err));
  }
});

const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  wss.handleUpgrade(req, socket, head, (ws) => {
    handleConnection(ws);
  });
});

server.listen(PORT, () => {
  console.log(`Listening on :${PORT}`);
  if (!ADMIN_PASSWORD) console.log('WARNING: ADMIN_PASSWORD is not set - /admin will be disabled.');
});
