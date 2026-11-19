// Content store for bradborowski.com: public read, password-protected write. Password lives in the ADMIN_PASSWORD secret.
const CORS = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'content-type,authorization', 'access-control-allow-methods': 'GET,PUT,POST,OPTIONS' };
const json = (o, s = 200, h = {}) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...CORS, ...h } });
const enc = new TextEncoder();
async function token(pw) { const k = await crypto.subtle.importKey('raw', enc.encode(pw), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); const s = await crypto.subtle.sign('HMAC', k, enc.encode('bradborowski-admin-v1')); return [...new Uint8Array(s)].map((b) => b.toString(16).padStart(2, '0')).join(''); }
function same(a, b) { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }
export default {
  async fetch(req, env) {
    const u = new URL(req.url);
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });
    if (u.pathname === '/content' && req.method === 'GET') return json(JSON.parse((await env.SITE.get('content')) || '{}'));
    if (u.pathname === '/login' && req.method === 'POST') {
      const { password } = await req.json().catch(() => ({}));
      const t = await token(env.ADMIN_PASSWORD);
      if (typeof password === 'string' && same(await token(password), t)) return json({ token: t });
      await new Promise((r) => setTimeout(r, 800)); return json({ error: 'wrong password' }, 401);
    }
    if (u.pathname === '/content' && req.method === 'PUT') {
      const t = (req.headers.get('authorization') || '').replace(/^Bearer /, '');
      if (!same(t, await token(env.ADMIN_PASSWORD))) return json({ error: 'not signed in' }, 401);
      const body = await req.json().catch(() => null);
      if (!body || typeof body !== 'object' || Array.isArray(body)) return json({ error: 'bad content' }, 400);
      const clean = {}; for (const [k, v] of Object.entries(body)) if (/^[a-z0-9]{1,20}$/i.test(k) && typeof v === 'string' && v.length < 5000) clean[k] = v;
      await env.SITE.put('content', JSON.stringify(clean)); return json({ ok: true, saved: Object.keys(clean).length });
    }
    return json({ error: 'not found' }, 404);
  },
};
