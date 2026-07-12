// KAOMA Marge PRO — Worker (Cloudflare Pages, _worker.js)
// Sert le statique + API /api/dossiers. Multi-société (login Google + espaces cloisonnés).
// Socle plateforme : journal d'événements + suivi utilisateurs + cockpit KAOMA + mode support tracé.
//
// CONFIG (variables d'env Cloudflare, hors code) :
//   GOOGLE_CLIENT_ID, SUPER_ADMIN, ACL_JSON (email -> [espaces]),
//   TENANT_ADMINS (optionnel) = {"patron@societe.fr":["espaceX"]}  (responsables d'UNE société)
//
// RÈGLE ANTI-RÉÉCRITURE : TOUT l'accès données passe par `store` (get/put/list/del).
// Pour migrer KV -> vraie base (D1/Postgres/par-pays) : ne réécrire QUE `store`.

const DEFAULT_CLIENT_ID = '897490379532-ta39a6sla6c03ur1ben03jpv6aqjrb7a.apps.googleusercontent.com';
const ESPACES = { blomkal: { name: 'Blomkål' }, woox: { name: 'WOOX' }, bf: { name: 'BF Agencement' } };
const HIST_MAX = 40;
const HIST_TTL = 60 * 60 * 24 * 120;   // 120 j (historique dossiers)
const EVT_TTL  = 60 * 60 * 24 * 180;   // 180 j (événements)
const LOGIN_THROTTLE = 30 * 60 * 1000; // 30 min entre 2 connexions comptées
const SUPPORT_THROTTLE = 30 * 60 * 1000; // 30 min entre 2 traces d'accès support

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });

// ---- Couche données découplée (seul endroit à changer pour migrer KV -> vraie base) ----
function makeStore(env) {
  const kv = env && env.DOSSIERS;
  return {
    ok: !!kv,
    get: (k) => kv.get(k),
    put: (k, v, opt) => kv.put(k, v, opt),
    del: (k) => kv.delete(k),
    list: (prefix, limit) => kv.list({ prefix, limit: limit || 1000 }),
  };
}

function config(env) {
  let acl = {}; try { if (env && env.ACL_JSON) acl = JSON.parse(env.ACL_JSON); } catch (e) { acl = {}; }
  const lc = {}; for (const k in acl) lc[String(k).toLowerCase()] = acl[k];
  let ta = {}; try { if (env && env.TENANT_ADMINS) ta = JSON.parse(env.TENANT_ADMINS); } catch (e) { ta = {}; }
  const lta = {}; for (const k in ta) lta[String(k).toLowerCase()] = ta[k];
  return {
    clientId: (env && env.GOOGLE_CLIENT_ID) || DEFAULT_CLIENT_ID,
    superAdmin: String((env && env.SUPER_ADMIN) || '').toLowerCase(),
    acl: lc,
    tenantAdmins: lta,
  };
}
const espaceOk = (user, espace) => !!espace && user && user.espaces.indexOf(espace) >= 0;
const dkey = (espace, id) => 'dossier:' + espace + ':' + id;
const hpref = (espace, id) => 'hist:' + espace + ':' + id + ':';
const espName = (e) => (ESPACES[e] && ESPACES[e].name) || e;
const clientMeta = (request) => ({ ip: request.headers.get('CF-Connecting-IP') || '', ua: (request.headers.get('User-Agent') || '').slice(0, 140), pays: (request.cf && request.cf.country) || '' });

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
    return { email, espaces: cfg.acl[email] || [], isAdmin: email === cfg.superAdmin, tenantAdmin: cfg.tenantAdmins[email] || [], cfg };
  } catch (e) { return null; }
}

// ---- Socle événements (append-only, portable) ----
async function logEvent(store, type, email, meta) {
  if (!store.ok) return;
  const ts = new Date().toISOString();
  try { await store.put('event:' + ts + ':' + Math.random().toString(36).slice(2, 8), JSON.stringify({ ts, type, email: email || '', meta: meta || {} }), { expirationTtl: EVT_TTL }); } catch (e) {}
}
async function touchUser(store, email, espaces, meta) {
  if (!store.ok || !email) return;
  let u = null; try { const raw = await store.get('user:' + email); if (raw) u = JSON.parse(raw); } catch (e) {}
  const now = Date.now();
  const isNew = !u || !u.lastLogin || (now - new Date(u.lastLogin).getTime() > LOGIN_THROTTLE);
  u = u || { email: email, firstSeen: new Date().toISOString(), logins: 0 };
  if (isNew) u.logins = (u.logins || 0) + 1;
  u.lastLogin = new Date().toISOString();
  u.espaces = espaces || u.espaces || [];
  if (meta && meta.pays) u.pays = meta.pays;
  try { await store.put('user:' + email, JSON.stringify(u)); } catch (e) {}
  if (isNew) await logEvent(store, 'login', email, meta);
}
// Trace un accès support (super-admin qui entre dans un espace dont il n'est PAS membre), throttlé
async function maybeLogSupport(store, email, espace) {
  const k = 'support:' + email + ':' + espace;
  let last = 0; try { const raw = await store.get(k); if (raw) last = Number(raw) || 0; } catch (e) {}
  if (Date.now() - last > SUPPORT_THROTTLE) {
    try { await store.put(k, String(Date.now()), { expirationTtl: 60 * 60 * 24 * 7 }); } catch (e) {}
    await logEvent(store, 'support_access', email, { espace: espace });
  }
}
// Accès autorisé à un espace ? (membre, OU super-admin en mode support)
function accessInfo(user, espace) {
  const member = espaceOk(user, espace);
  return { allowed: member || (user.isAdmin && !!ESPACES[espace]), member: member, support: !member && user.isAdmin && !!ESPACES[espace] };
}

async function handleGet(request, env, url) {
  const store = makeStore(env);
  const user = await getUser(request, env);
  if (!user) return json({ error: 'non authentifié' }, 401);

  if (url.searchParams.get('me')) {
    await touchUser(store, user.email, user.espaces, clientMeta(request));
    return json({
      email: user.email,
      espaces: user.espaces.map((e) => ({ id: e, name: espName(e) })),
      isAdmin: user.isAdmin,
      tenantAdmin: user.tenantAdmin.map((e) => ({ id: e, name: espName(e) })),
      allEspaces: user.isAdmin ? Object.keys(ESPACES).map((e) => ({ id: e, name: espName(e) })) : [],
    });
  }

  // Cockpit responsable de société (niveau 2) : agrégats de SES sociétés uniquement
  if (url.searchParams.get('tenant') === 'data') {
    const mine = user.tenantAdmin || [];
    if (!mine.length) return json({ error: 'réservé responsable de société' }, 403);
    if (!store.ok) return json({}, 200);
    const out = {};
    for (const e of mine) {
      const list = await store.list('dossier:' + e + ':');
      const items = await Promise.all(list.keys.map(async (k) => { const v = await store.get(k.name); try { return JSON.parse(v); } catch { return null; } }));
      out[e] = { name: espName(e), dossiers: items.filter(Boolean) };
    }
    return json(out);
  }

  const adminParam = url.searchParams.get('admin');
  if (adminParam) {
    if (!user.isAdmin) return json({ error: 'réservé admin' }, 403);
    if (!store.ok) return json(adminParam === 'data' ? {} : [], 200);
    if (adminParam === 'users') {
      const l = await store.list('user:');
      const users = await Promise.all(l.keys.map(async (k) => { const v = await store.get(k.name); try { return JSON.parse(v); } catch { return null; } }));
      return json(users.filter(Boolean).sort((a, b) => String(b.lastLogin || '').localeCompare(String(a.lastLogin || ''))));
    }
    if (adminParam === 'events') {
      const l = await store.list('event:', 1000);
      const names = l.keys.map((k) => k.name).sort().reverse().slice(0, 120);
      const evs = await Promise.all(names.map(async (n) => { const v = await store.get(n); try { return JSON.parse(v); } catch { return null; } }));
      return json(evs.filter(Boolean));
    }
    if (adminParam === 'data') {
      const out = {};
      for (const e of Object.keys(ESPACES)) {
        const list = await store.list('dossier:' + e + ':');
        const items = await Promise.all(list.keys.map(async (k) => { const v = await store.get(k.name); try { return JSON.parse(v); } catch { return null; } }));
        out[e] = { name: espName(e), users: Object.keys(user.cfg.acl).filter((mm) => user.cfg.acl[mm].indexOf(e) >= 0), dossiers: items.filter(Boolean) };
      }
      return json(out);
    }
    const out = [];
    for (const e of Object.keys(ESPACES)) {
      const list = await store.list('dossier:' + e + ':');
      out.push({ espace: e, name: espName(e), dossiers: list.keys.length, users: Object.keys(user.cfg.acl).filter((mm) => user.cfg.acl[mm].indexOf(e) >= 0) });
    }
    return json(out);
  }

  const espace = url.searchParams.get('espace');
  const acc = accessInfo(user, espace);
  if (!acc.allowed) return json({ error: 'accès refusé à cet espace' }, 403);
  if (!store.ok) return json([], 200);
  if (acc.support) await maybeLogSupport(store, user.email, espace);
  const histId = url.searchParams.get('history');
  if (histId) {
    const list = await store.list(hpref(espace, histId));
    const items = await Promise.all(list.keys.map(async (k) => { const v = await store.get(k.name); try { return { _key: k.name, ...JSON.parse(v) }; } catch { return null; } }));
    items.sort((a, b) => String((b && b.updated) || '').localeCompare(String((a && a.updated) || '')));
    return json(items.filter(Boolean));
  }
  const list = await store.list('dossier:' + espace + ':');
  const items = await Promise.all(list.keys.map(async (k) => { const v = await store.get(k.name); try { return JSON.parse(v); } catch { return null; } }));
  return json(items.filter(Boolean));
}

async function handlePost(request, env, url) {
  const store = makeStore(env);
  const user = await getUser(request, env);
  if (!user) return json({ error: 'non authentifié' }, 401);
  if (!store.ok) return json({ error: 'KV non configuré' }, 503);
  const importEsp = url.searchParams.get('import');
  if (importEsp) {
    if (!user.isAdmin) return json({ error: 'réservé admin' }, 403);
    if (!ESPACES[importEsp]) return json({ error: 'espace inconnu' }, 400);
    let arr; try { arr = await request.json(); } catch { return json({ error: 'JSON invalide' }, 400); }
    if (!Array.isArray(arr)) return json({ error: 'tableau attendu' }, 400);
    let n = 0;
    for (const d of arr) { if (d && d.id) { d.updated = d.updated || new Date().toISOString(); delete d.espace; await store.put(dkey(importEsp, d.id), JSON.stringify(d)); n++; } }
    await logEvent(store, 'import', user.email, { espace: importEsp, n: n });
    return json({ ok: true, imported: n, espace: importEsp });
  }
  const espace = url.searchParams.get('espace');
  const acc = accessInfo(user, espace);
  if (!acc.allowed) return json({ error: 'accès refusé à cet espace' }, 403);
  let d; try { d = await request.json(); } catch { return json({ error: 'JSON invalide' }, 400); }
  if (!d || !d.id) return json({ error: 'id manquant' }, 400);
  const baseUpdated = d.baseUpdated; const force = d.force === true;
  delete d.baseUpdated; delete d.force; delete d.espace;
  const k = dkey(espace, d.id);
  let prevRaw = null; try { prevRaw = await store.get(k); } catch {}
  if (prevRaw) {
    let prev = null; try { prev = JSON.parse(prevRaw); } catch {}
    if (prev && !force && baseUpdated && prev.updated && String(prev.updated) > String(baseUpdated)) return json({ conflict: true, current: prev }, 409);
    try {
      const ts = (prev && prev.updated) || new Date().toISOString();
      await store.put(hpref(espace, d.id) + ts, prevRaw, { expirationTtl: HIST_TTL });
      const hl = await store.list(hpref(espace, d.id));
      if (hl.keys.length > HIST_MAX) { const olders = hl.keys.map((x) => x.name).sort().slice(0, hl.keys.length - HIST_MAX); for (const name of olders) { try { await store.del(name); } catch {} } }
    } catch {}
  }
  d.updated = new Date().toISOString();
  await store.put(k, JSON.stringify(d));
  if (acc.support) await logEvent(store, 'support_access', user.email, { espace: espace, action: 'modif', id: d.id });
  else await logEvent(store, 'dossier_save', user.email, { espace: espace, id: d.id, name: (d.name || '').slice(0, 60) });
  return json({ ok: true, id: d.id, updated: d.updated });
}

async function handleDelete(request, env, url) {
  const store = makeStore(env);
  const user = await getUser(request, env);
  if (!user) return json({ error: 'non authentifié' }, 401);
  if (!store.ok) return json({ error: 'KV non configuré' }, 503);
  const espace = url.searchParams.get('espace');
  const acc = accessInfo(user, espace);
  if (!acc.allowed) return json({ error: 'accès refusé à cet espace' }, 403);
  const id = url.searchParams.get('id');
  if (!id) return json({ error: 'id manquant' }, 400);
  const k = dkey(espace, id);
  try { const prevRaw = await store.get(k); if (prevRaw) await store.put(hpref(espace, id) + 'deleted:' + new Date().toISOString(), prevRaw, { expirationTtl: HIST_TTL }); } catch {}
  await store.del(k);
  await logEvent(store, acc.support ? 'support_access' : 'dossier_delete', user.email, { espace: espace, id: id, action: acc.support ? 'suppression' : undefined });
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
