/* ================================================================
 * WebCatX 后端 · Vercel Serverless 版
 * 接口与之前完全一致，客户端 APK / setup.html 无需改动
 * 存储：Upstash Redis（REST API，无需安装依赖）
 * 环境变量（Vercel 项目 Settings → Environment Variables 配置）：
 *   UPSTASH_REDIS_REST_URL     Upstash 控制台复制
 *   UPSTASH_REDIS_REST_TOKEN   Upstash 控制台复制
 *   ADMIN_KEY                  管理员密钥（可选，默认见下）
 * ================================================================ */

const ADMIN_DEFAULT = 'adm_m51bV9rzD3PoS_Ft2vyo76b0';
const TOKEN_TTL_MS = 120 * 1000;
const LOG_KEEP = 200;
const HEX64 = /^[0-9a-f]{64}$/;
const KEY_RE = /^WCX(-[A-Z2-9]{4}){4}$/;
const KEY_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,X-Admin-Key',
};

/* ---------- Upstash REST 读写 ---------- */
async function redis(cmd) {
  const r = await fetch(process.env.UPSTASH_REDIS_REST_URL, {
    method: 'POST',
    headers: {
      Authorization: 'Bearer ' + process.env.UPSTASH_REDIS_REST_TOKEN,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(cmd),
  });
  const d = await r.json();
  return d.result;
}

async function loadState() {
  const s = await redis(['GET', 'webcatx']);
  try { return s ? JSON.parse(s) : {}; } catch (e) { return {}; }
}

async function saveState(st) {
  await redis(['SET', 'webcatx', JSON.stringify(st)]);
}

/* ---------- 工具 ---------- */
const now = () => Date.now();
const ts = () => new Date(now() + 8 * 3600 * 1000).toISOString().replace('T', ' ').slice(0, 19);

function ctEq(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function addLog(st, event, ip, detail = '') {
  st.logs = (st.logs || []).concat([{ ts: ts(), ip, event, detail }]).slice(-LOG_KEEP);
}

function genKey() {
  const g = [...crypto.getRandomValues(new Uint8Array(16))].map(b => KEY_CHARS[b % 32]);
  return 'WCX-' + [0, 4, 8, 12].map(i => g.slice(i, i + 4).join('')).join('-');
}

function issueToken(st) {
  const t = [...crypto.getRandomValues(new Uint8Array(16))].map(b => b.toString(16).padStart(2, '0')).join('');
  st.tokens = st.tokens || {};
  for (const k of Object.keys(st.tokens)) if (st.tokens[k] < now()) delete st.tokens[k];
  st.tokens[t] = now() + TOKEN_TTL_MS;
  return t;
}

function takeToken(st, t) {
  const exp = (st.tokens || {})[t];
  if (st.tokens) delete st.tokens[t];
  return exp && exp > now();
}

function adminOk(req, st) {
  const key = st.admin_key || process.env.ADMIN_KEY || ADMIN_DEFAULT;
  return ctEq(req.headers['x-admin-key'] || '', key);
}

function json(res, obj, code = 200) {
  res.status(code).setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify(obj));
}

/* ---------- 主入口 ---------- */
export default async function handler(req, res) {
  for (const [k, v] of Object.entries(CORS)) res.setHeader(k, v);
  if (req.method === 'OPTIONS') return res.status(204).end();

  const ip = (req.headers['x-forwarded-for'] || '-').split(',')[0].trim();
  let path = (req.url || '/').split('?')[0];
  for (const p of ['/keys/del', '/activate', '/status', '/setup', '/logs', '/keys', '/app', '/v', '/set', '/key']) {
    if (path.endsWith(p)) { path = p; break; }
  }
  const body = typeof req.body === 'object' && req.body ? req.body : {};
  const query = req.query || {};
  const st = await loadState();

  try {
    if (path === '/v' && req.method === 'POST') {
      if (!HEX64.test(body.h || '')) return json(res, { ok: false, error: 'bad' }, 400);
      if (!st.verifier) return json(res, { ok: false, error: 'unset' }, 503);
      const ok = ctEq(body.h, st.verifier);
      addLog(st, ok ? 'verify_ok' : 'verify_fail', ip);
      if (!ok) { await saveState(st); return json(res, { ok: false }); }
      const t = issueToken(st);
      await saveState(st);
      return json(res, { ok: true, t });
    }

    if (path === '/app' && req.method === 'GET') {
      if (!takeToken(st, query.t || '')) { await saveState(st); return json(res, { error: 'forbidden' }, 403); }
      const html = st.app_html;
      await saveState(st);
      if (!html) return json(res, { error: 'app not setup' }, 503);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store');
      return res.send(html);
    }

    if (path === '/setup' && req.method === 'POST') {
      if (!adminOk(req, st)) return json(res, { ok: false, error: 'deny' }, 403);
      if (typeof body.html !== 'string' || body.html.length < 1000) return json(res, { ok: false, error: 'bad' }, 400);
      st.app_html = body.html;
      await saveState(st);
      return json(res, { ok: true, size: body.html.length });
    }

    if (path === '/status') return json(res, { set: !!st.verifier });

    if (path === '/set' && req.method === 'POST') {
      if (!adminOk(req, st)) return json(res, { ok: false, error: 'deny' }, 403);
      if (!HEX64.test(body.h || '')) return json(res, { ok: false, error: 'bad' }, 400);
      st.verifier = body.h;
      addLog(st, 'password_change', ip);
      await saveState(st);
      return json(res, { ok: true });
    }

    if (path === '/key' && req.method === 'POST') {
      if (!adminOk(req, st)) return json(res, { ok: false, error: 'deny' }, 403);
      const nw = (body.new || '').trim();
      if (nw.length < 8 || nw.length > 64) return json(res, { ok: false, error: '长度需 8-64 位' }, 400);
      st.admin_key = nw;
      addLog(st, 'key_change', ip);
      await saveState(st);
      return json(res, { ok: true });
    }

    if (path === '/logs' && req.method === 'GET') {
      if (!adminOk(req, st)) return json(res, { ok: false, error: 'deny' }, 403);
      return json(res, { ok: true, logs: (st.logs || []).slice(-100) });
    }

    if (path === '/keys') {
      if (!adminOk(req, st)) return json(res, { ok: false, error: 'deny' }, 403);
      st.keys = st.keys || {};
      if (req.method === 'POST') {
        const ttl = Number(body.ttl_min) || null;
        const uses = Number(body.max_uses) || null;
        const k = genKey();
        st.keys[k] = {
          created_at: now(),
          expires_at: ttl > 0 ? now() + ttl * 60000 : null,
          max_uses: uses > 0 ? uses : null,
          uses: 0, bound: null,
        };
        addLog(st, 'keygen', ip, k);
        await saveState(st);
        return json(res, { ok: true, key: k });
      }
      if (req.method === 'GET') {
        const list = Object.entries(st.keys).map(([k, v]) => ({
          k, uses: v.uses, max_uses: v.max_uses, expires_at: v.expires_at,
          bound: !!v.bound,
          left: v.expires_at ? Math.max(0, Math.round((v.expires_at - now()) / 60000)) : null,
        }));
        return json(res, { ok: true, keys: list });
      }
    }

    if (path === '/keys/del' && req.method === 'POST') {
      if (!adminOk(req, st)) return json(res, { ok: false, error: 'deny' }, 403);
      st.keys = st.keys || {};
      if (!(body.k in st.keys)) return json(res, { ok: false, error: 'not_found' }, 404);
      delete st.keys[body.k];
      addLog(st, 'keydel', ip, body.k);
      await saveState(st);
      return json(res, { ok: true });
    }

    if (path === '/activate' && req.method === 'POST') {
      const k = body.k || '', dev = body.dev || '';
      if (!KEY_RE.test(k) || !/^[0-9a-f]{8,32}$/.test(dev)) return json(res, { ok: false, error: 'bad' }, 400);
      st.keys = st.keys || {};
      const rec = st.keys[k];
      if (!rec) return json(res, { ok: false, error: 'not_found' });
      if ((rec.expires_at && now() > rec.expires_at) || (rec.max_uses && rec.uses >= rec.max_uses)) {
        delete st.keys[k];
        addLog(st, rec.expires_at && now() > rec.expires_at ? 'expire' : 'exhausted', ip, k);
        await saveState(st);
        return json(res, { ok: false, error: 'not_found' });
      }
      if (rec.bound && rec.bound !== dev) {
        addLog(st, 'bind_conflict', ip, k);
        await saveState(st);
        return json(res, { ok: false, error: 'bound' });
      }
      if (!rec.bound) rec.bound = dev;
      rec.uses += 1;
      if (rec.max_uses && rec.uses >= rec.max_uses) delete st.keys[k];
      const t = issueToken(st);
      addLog(st, 'activate_ok', ip, k);
      await saveState(st);
      return json(res, { ok: true, t, left: rec.max_uses ? Math.max(0, rec.max_uses - rec.uses) : null });
    }

    return json(res, { error: '404' }, 404);
  } catch (e) {
    return json(res, { error: '500', detail: String(e && e.message || e) }, 500);
  }
}
