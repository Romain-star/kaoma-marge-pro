// KAOMA Marge PRO — Worker unique (Cloudflare Pages, mode avancé _worker.js)
// Sert le statique (index.html) via env.ASSETS et gère l'API /api/dossiers.
// Multi-société : login Google (Bearer ID token) + espaces cloisonnés "dossier:<espace>:<id>".
//
// CONFIG SENSIBLE HORS CODE (le dépôt peut être public) — variables d'environnement Cloudflare :
//   GOOGLE_CLIENT_ID = ...apps.googleusercontent.com   (public, mais paramétrable)
//   SUPER_ADMIN      = user1@exemple.fr
//   ACL_JSON         = {"user1@exemple.fr":["blomkal","woox"], "user2@exemple.fr":["blomkal"], ...}
// Sans ACL_JSON -> personne n'a accès (fail-closed).

const DEFAULT_CLIENT_ID = '897490379532-ta39a6sla6c03ur1ben03jpv6aqjrb7a.apps.googleusercontent.com';
const ESPACES = { blomkal: { name: 'Blomkål' }, woox: { name: 'WOOX' } };
const HIST_MAX = 40;
const HIST_TTL = 60 * 60 * 24 * 120;

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });

function config(env) {
  let acl = {};
  try { if (env && env.ACL_JSON) acl = JSON.parse(env.ACL_JSON); } catch (e) { acl = {}; }
  const lc = {}; for (const k in acl) lc[String(k).toLowerCase()] = acl[k];
  return {
    clientId: (env && env.GOOGLE_CLIENT_ID) || DEFAULT_CLIENT_ID,
    superAdmin: String((env && env.SUPER_ADMIN) || '').toLowerCase(),
    acl: lc,
  };
}
const espaceOk = (user, espace) => !!espace && user && user.espaces.indexOf(espace) >= 0;
const dkey = (espace, id) => 'dossier:' + espace + ':' + id;
const hpref = (espace, id) => 'hist:' + espace + ':' + id + ':';

async function getUser(request, env) {
  const h = request.headers.get('Authorization') || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const cfg = config(env);
  try {
    const r = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(m[1].trim()));
    if (!r.ok) return null;
    const d = await r.json();
    if (!d || !d.email) return null;
    if (d.aud !== cfg.clientId) return null;
    if (!(d.email_verified === true || d.email_verified === 'true')) return null;
    if (d.exp && Number(d.exp) * 1000 < Date.now()) return null;
    const email = String(d.email).toLowerCase();
    return { email, espaces: cfg.acl[email] || [], isAdmin: email === cfg.superAdmin, cfg };
  } catch (e) { return null; }
}

async function handleGet(request, env, url) {
  const user = await getUser(request, env);
  if (!user) return json({ error: 'non authentifié' }, 401);
  if (url.searchParams.get('me')) return json({ email: user.email, espaces: user.espaces.map((e) => ({ id: e, name: (ESPACES[e] && ESPACES[e].name) || e })), isAdmin: user.isAdmin });
  if (url.searchParams.get('admin')) {
    if (!user.isAdmin) return json({ error: 'réservé admin' }, 403);
    if (!env.DOSSIERS) return json([], 200);
    const out = [];
    for (const e of Object.keys(ESPACES)) {
      const list = await env.DOSSIERS.list({ prefix: 'dossier:' + e + ':' });
      out.push({ espace: e, name: ESPACES[e].name, dossiers: list.keys.length, users: Object.keys(user.cfg.acl).filter((m) => user.cfg.acl[m].indexOf(e) >= 0) });
    }
    return json(out);
  }
  const espace = url.searchParams.get('espace');
  if (!espaceOk(user, espace)) return json({ error: 'accès refusé à cet espace' }, 403);
  if (!env.DOSSIERS) return json([], 200);
  const histId = url.searchParams.get('history');
  if (histId) {
    const list = await env.DOSSIERS.list({ prefix: hpref(espace, histId) });
    const items = await Promise.all(list.keys.map(async (k) => { const v = await env.DOSSIERS.get(k.name); try { return { _key: k.name, ...JSON.parse(v) }; } catch { return null; } }));
    items.sort((a, b) => String((b && b.updated) || '').localeCompare(String((a && a.updated) || '')));
    return json(items.filter(Boolean));
  }
  const list = await env.DOSSIERS.list({ prefix: 'dossier:' + espace + ':' });
  const items = await Promise.all(list.keys.map(async (k) => { const v = await env.DOSSIERS.get(k.name); try { return JSON.parse(v); } catch { return null; } }));
  return json(items.filter(Boolean));
}

async function handlePost(request, env, url) {
  const user = await getUser(request, env);
  if (!user) return json({ error: 'non authentifié' }, 401);
  if (!env.DOSSIERS) return json({ error: 'KV non configuré' }, 503);
  const importEsp = url.searchParams.get('import');
  if (importEsp) {
    if (!user.isAdmin) return json({ error: 'réservé admin' }, 403);
    if (!ESPACES[importEsp]) return json({ error: 'espace inconnu' }, 400);
    let arr; try { arr = await request.json(); } catch { return json({ error: 'JSON invalide' }, 400); }
    if (!Array.isArray(arr)) return json({ error: 'tableau attendu' }, 400);
    let n = 0;
    for (const d of arr) { if (d && d.id) { d.updated = d.updated || new Date().toISOString(); delete d.espace; await env.DOSSIERS.put(dkey(importEsp, d.id), JSON.stringify(d)); n++; } }
    return json({ ok: true, imported: n, espace: importEsp });
  }
  const espace = url.searchParams.get('espace');
  if (!espaceOk(user, espace)) return json({ error: 'accès refusé à cet espace' }, 403);
  let d; try { d = await request.json(); } catch { return json({ error: 'JSON invalide' }, 400); }
  if (!d || !d.id) return json({ error: 'id manquant' }, 400);
  const baseUpdated = d.baseUpdated; const force = d.force === true;
  delete d.baseUpdated; delete d.force; delete d.espace;
  const k = dkey(espace, d.id);
  let prevRaw = null; try { prevRaw = await env.DOSSIERS.get(k); } catch {}
  if (prevRaw) {
    let prev = null; try { prev = JSON.parse(prevRaw); } catch {}
    if (prev && !force && baseUpdated && prev.updated && String(prev.updated) > String(baseUpdated)) return json({ conflict: true, current: prev }, 409);
    try {
      const ts = (prev && prev.updated) || new Date().toISOString();
      await env.DOSSIERS.put(hpref(espace, d.id) + ts, prevRaw, { expirationTtl: HIST_TTL });
      const hl = await env.DOSSIERS.list({ prefix: hpref(espace, d.id) });
      if (hl.keys.length > HIST_MAX) { const olders = hl.keys.map((x) => x.name).sort().slice(0, hl.keys.length - HIST_MAX); for (const name of olders) { try { await env.DOSSIERS.delete(name); } catch {} } }
    } catch {}
  }
  d.updated = new Date().toISOString();
  await env.DOSSIERS.put(k, JSON.stringify(d));
  return json({ ok: true, id: d.id, updated: d.updated });
}

async function handleDelete(request, env, url) {
  const user = await getUser(request, env);
  if (!user) return json({ error: 'non authentifié' }, 401);
  if (!env.DOSSIERS) return json({ error: 'KV non configuré' }, 503);
  const espace = url.searchParams.get('espace');
  if (!espaceOk(user, espace)) return json({ error: 'accès refusé à cet espace' }, 403);
  const id = url.searchParams.get('id');
  if (!id) return json({ error: 'id manquant' }, 400);
  const k = dkey(espace, id);
  try { const prevRaw = await env.DOSSIERS.get(k); if (prevRaw) await env.DOSSIERS.put(hpref(espace, id) + 'deleted:' + new Date().toISOString(), prevRaw, { expirationTtl: HIST_TTL }); } catch {}
  await env.DOSSIERS.delete(k);
  return json({ ok: true });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/dossiers') {
      if (request.method === 'GET') return handleGet(request, env, url);
      if (request.method === 'POST') return handlePost(request, env, url);
      if (request.method === 'DELETE') return handleDelete(request, env, url);
      return json({ error: 'méthode non supportée' }, 405);
    }
    return env.ASSETS.fetch(request);
  },
};
