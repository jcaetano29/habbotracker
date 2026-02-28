'use strict';
/**
 * HabboTracker API — by Fungi 🍄  (v5)
 * Deploy en Render.com (free tier)
 * Zero dependencias externas — Node.js v18+
 */

const http   = require('http');
const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const url    = require('url');
const crypto = require('crypto');

// ─── Config ───────────────────────────────────────────────────────────────────
const PORT             = parseInt(process.env.PORT || '3001', 10);
const FRONTEND_ORIGIN  = process.env.FRONTEND_ORIGIN || '*';
const HABBO_HOST       = 'www.habbo.es';
const HABBO_TIMEOUT    = 10_000;
const DATA_DIR         = path.join(__dirname, 'data');
const UPLOADS_DIR      = path.join(DATA_DIR, 'uploads');
const DB_FILE          = path.join(DATA_DIR, 'db.json');
const MAX_IMG_BYTES    = 5 * 1024 * 1024;
const MAX_BODY_BYTES   = 6 * 1024 * 1024;
const POST_TYPES       = ['funa', 'post', 'recommend'];
const REACTIONS        = ['confirm', 'false', 'fire'];
const SESSION_TTL_MS   = 30 * 24 * 3_600_000;
const POSTS_PER_PAGE   = 20;
const ALLOWED_IMG      = new Set(['image/jpeg','image/jpg','image/png','image/gif','image/webp']);

// ─── Dirs ─────────────────────────────────────────────────────────────────────
for (const d of [DATA_DIR, UPLOADS_DIR])
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });

// ─── DB ───────────────────────────────────────────────────────────────────────
const empty = () => ({ users: {}, sessions: {}, posts: [] });

function loadDB() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return empty(); }
}

function saveDB(db) {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db), 'utf8');
  fs.renameSync(tmp, DB_FILE);
}

if (!fs.existsSync(DB_FILE)) saveDB(empty());

// ─── Rate limit ───────────────────────────────────────────────────────────────
const rlMap = new Map();
function isRateLimited(ip, max = 60) {
  const now = Date.now();
  let e = rlMap.get(ip);
  if (!e || now > e.reset) e = { n: 0, reset: now + 60_000 };
  e.n++;
  rlMap.set(ip, e);
  return e.n > max;
}
setInterval(() => { const now = Date.now(); for (const [k,v] of rlMap) if (now > v.reset) rlMap.delete(k); }, 60_000).unref();

// ─── Crypto ───────────────────────────────────────────────────────────────────
const newSalt  = () => crypto.randomBytes(32).toString('hex');
const newToken = () => crypto.randomBytes(48).toString('hex');

function hashPw(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100_000, 64, 'sha512').toString('hex');
}
function safeEq(a, b) {
  // Protección contra timing attacks
  try {
    const ba = Buffer.from(a, 'hex');
    const bb = Buffer.from(b, 'hex');
    if (ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
  } catch { return false; }
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────
function setCORS(res) {
  res.setHeader('Access-Control-Allow-Origin',  FRONTEND_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  res.setHeader('Access-Control-Max-Age',       '86400');
  res.setHeader('X-Content-Type-Options',       'nosniff');
}

function ok(res, status, data) {
  setCORS(res);
  const body = JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

function readRaw(req) {
  return new Promise((resolve, reject) => {
    const parts = []; let total = 0;
    req.on('data', c => { total += c.length; if (total > MAX_BODY_BYTES) return reject(new Error('Payload demasiado grande')); parts.push(c); });
    req.on('end',   () => resolve(Buffer.concat(parts)));
    req.on('error', reject);
  });
}

async function readJSON(req) {
  const buf = await readRaw(req);
  try { return JSON.parse(buf.toString('utf8')); }
  catch { throw new Error('JSON inválido'); }
}

function bearerToken(req) {
  const auth = req.headers['authorization'] || '';
  return auth.startsWith('Bearer ') ? auth.slice(7).trim() : null;
}

const san = (s, max) => String(s ?? '').trim().slice(0, max).replace(/[<>]/g, '');

// ─── Multipart ────────────────────────────────────────────────────────────────
function parseMultipart(buf, boundary) {
  const fields = {}; let file = null;
  const sep = '\r\n--' + boundary;
  let pos = buf.indexOf('--' + boundary);

  while (pos !== -1) {
    const after = pos + boundary.length + 2;
    if (buf[after] === 45 && buf[after+1] === 45) break;  // --boundary--

    const he = buf.indexOf('\r\n\r\n', after);
    if (he === -1) break;

    const headers   = buf.slice(after + 2, he).toString('utf8');
    const bodyStart = he + 4;
    const nextBound = buf.indexOf('\r\n--' + boundary, bodyStart);
    const body      = buf.slice(bodyStart, nextBound !== -1 ? nextBound : buf.length);

    const nameM = headers.match(/name="([^"]+)"/i);
    const fileM = headers.match(/filename="([^"]*)"/i);
    const typeM = headers.match(/Content-Type:\s*([^\r\n]+)/i);

    if (nameM) {
      if (fileM) {
        file = {
          filename: path.basename(fileM[1] || 'upload'),
          mimetype: (typeM ? typeM[1].trim() : 'application/octet-stream').toLowerCase(),
          data: body,
        };
      } else {
        fields[nameM[1]] = body.toString('utf8').trim();
      }
    }
    pos = nextBound !== -1 ? nextBound + 2 : -1;
  }
  return { fields, file };
}

// ─── Habbo proxy ──────────────────────────────────────────────────────────────
function habboFetch(p) {
  return new Promise((resolve, reject) => {
    const r = https.request({ hostname: HABBO_HOST, path: p, method: 'GET',
      headers: { 'User-Agent': 'HabboTracker/2.0', Accept: 'application/json,image/*' },
      timeout: HABBO_TIMEOUT,
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    r.on('timeout', () => { r.destroy(); reject(new Error('Timeout')); });
    r.on('error', reject);
    r.end();
  });
}

async function proxyJSON(res, p) {
  try {
    const { status, body } = await habboFetch(p);
    if (status < 200 || status >= 300) return ok(res, status, { error: `habbo.es: ${status}` });
    ok(res, 200, JSON.parse(body.toString('utf8')));
  } catch (e) { ok(res, e.message === 'Timeout' ? 504 : 502, { error: e.message }); }
}

async function proxyImg(res, p, cache) {
  try {
    const { status, headers, body } = await habboFetch(p);
    if (status < 200 || status >= 300) { res.writeHead(status); res.end(); return; }
    setCORS(res);
    res.writeHead(200, { 'Content-Type': headers['content-type'] || 'image/gif', 'Cache-Control': `public, max-age=${cache}`, 'Content-Length': body.length });
    res.end(body);
  } catch { res.writeHead(502); res.end(); }
}

// ─── Sessions ─────────────────────────────────────────────────────────────────
function getSession(req) {
  const token = bearerToken(req);
  if (!token) return null;
  const db = loadDB();
  const s  = db.sessions?.[token];
  if (!s) return null;
  if (Date.now() - s.createdAt > SESSION_TTL_MS) {
    delete db.sessions[token]; saveDB(db); return null;
  }
  return s;
}

// ─── Auth handlers ────────────────────────────────────────────────────────────
async function handleRegister(req, res) {
  let body; try { body = await readJSON(req); } catch (e) { return ok(res, 400, { error: e.message }); }

  const username  = san(body.username,  30).toLowerCase();
  const password  = san(body.password, 200);
  const habboName = san(body.habboName, 50);

  if (username.length < 3)              return ok(res, 400, { error: 'El usuario debe tener al menos 3 caracteres' });
  if (!/^[a-z0-9_-]+$/.test(username)) return ok(res, 400, { error: 'Solo letras, números, _ y - permitidos en el usuario' });
  if (password.length < 6)              return ok(res, 400, { error: 'La contraseña debe tener al menos 6 caracteres' });
  if (habboName.length < 2)             return ok(res, 400, { error: 'Escribe tu nombre de Habbo (al menos 2 caracteres)' });

  const db = loadDB();
  if (!db.users)    db.users    = {};
  if (!db.sessions) db.sessions = {};

  if (db.users[username]) return ok(res, 409, { error: 'Ese nombre de usuario ya está en uso' });

  const salt     = newSalt();
  const passHash = hashPw(password, salt);
  db.users[username] = { passHash, salt, habboName, createdAt: Date.now() };

  // Crear sesión inmediatamente (auto-login tras registro)
  const token = newToken();
  db.sessions[token] = { username, habboName, createdAt: Date.now() };
  saveDB(db);

  ok(res, 201, { token, username, habboName });
}

async function handleLogin(req, res) {
  let body; try { body = await readJSON(req); } catch (e) { return ok(res, 400, { error: e.message }); }

  const username = san(body.username, 30).toLowerCase();
  const password = san(body.password, 200);

  if (!username || !password) return ok(res, 400, { error: 'Faltan usuario o contraseña' });

  const db   = loadDB();
  const user = db.users?.[username];

  if (!user) return ok(res, 401, { error: 'Usuario o contraseña incorrectos' });

  const hash = hashPw(password, user.salt);
  if (!safeEq(hash, user.passHash)) return ok(res, 401, { error: 'Usuario o contraseña incorrectos' });

  // Limpiar sesiones anteriores
  if (!db.sessions) db.sessions = {};
  for (const [t, s] of Object.entries(db.sessions))
    if (s.username === username) delete db.sessions[t];

  const token = newToken();
  db.sessions[token] = { username, habboName: user.habboName, createdAt: Date.now() };
  saveDB(db);

  ok(res, 200, { token, username, habboName: user.habboName });
}

// ─── Social helpers ───────────────────────────────────────────────────────────
const totR = p => REACTIONS.reduce((s, r) => s + (p.reactions?.[r]?.length || 0), 0);

function publicPost(p) {
  const { _author, ...pub } = p;
  if (pub.anonymous) pub.authorName = 'Anónimo';
  return pub;
}

// ─── Social: GET /social/posts ────────────────────────────────────────────────
function handleGetPosts(res, q) {
  const db  = loadDB();
  let posts = [...(db.posts || [])];

  if (q.type   && POST_TYPES.includes(q.type)) posts = posts.filter(p => p.type === q.type);
  if (q.target) posts = posts.filter(p => p.targetName?.toLowerCase() === q.target.toLowerCase());

  posts.sort(q.sort === 'top'
    ? (a, b) => totR(b) - totR(a)
    : (a, b) => b.createdAt - a.createdAt
  );

  const page  = Math.max(1, parseInt(q.page) || 1);
  const start = (page - 1) * POSTS_PER_PAGE;
  const items = posts.slice(start, start + POSTS_PER_PAGE).map(publicPost);

  ok(res, 200, { total: posts.length, page, pages: Math.ceil(posts.length / POSTS_PER_PAGE) || 1, items });
}

// ─── Social: POST /social/posts ───────────────────────────────────────────────
async function handleCreatePost(req, res) {
  const session = getSession(req);
  if (!session) return ok(res, 401, { error: 'Sesión inválida. Inicia sesión de nuevo.' });

  const ct = req.headers['content-type'] || '';
  let fields = {}, imageFile = null;

  if (ct.includes('multipart/form-data')) {
    const bm = ct.match(/boundary=([^\s;]+)/);
    if (!bm) return ok(res, 400, { error: 'Boundary multipart no encontrado' });
    let raw; try { raw = await readRaw(req); } catch (e) { return ok(res, 413, { error: e.message }); }
    ({ fields, file: imageFile } = parseMultipart(raw, bm[1]));
  } else {
    try { fields = await readJSON(req); } catch (e) { return ok(res, 400, { error: e.message }); }
  }

  const type       = san(fields.type       || '', 20);
  const title      = san(fields.title      || '', 100);
  const content    = san(fields.content    || '', 500);
  const targetName = san(fields.targetName || '',  60);
  const anonymous  = fields.anonymous === 'true' || fields.anonymous === true;

  if (!POST_TYPES.includes(type)) return ok(res, 400, { error: 'Tipo de post inválido' });
  if (title.length   < 3)         return ok(res, 400, { error: 'El título debe tener al menos 3 caracteres' });
  if (content.length < 10)        return ok(res, 400, { error: 'El contenido debe tener al menos 10 caracteres' });

  const db = loadDB();
  if (!db.posts) db.posts = [];

  // Anti-spam: 5 posts por hora
  const oneHourAgo = Date.now() - 3_600_000;
  if (db.posts.filter(p => p._author === session.username && p.createdAt > oneHourAgo).length >= 5)
    return ok(res, 429, { error: 'Máximo 5 posts por hora. Vuelve más tarde.' });

  // Imagen
  let imageUrl = null;
  if (imageFile && imageFile.data.length > 0) {
    if (!ALLOWED_IMG.has(imageFile.mimetype))
      return ok(res, 400, { error: 'Formato no permitido. Usa JPG, PNG, GIF o WEBP' });
    if (imageFile.data.length > MAX_IMG_BYTES)
      return ok(res, 413, { error: 'Imagen demasiado grande (máx 5 MB)' });

    const extMap = { 'image/gif': '.gif', 'image/png': '.png', 'image/webp': '.webp' };
    const ext    = extMap[imageFile.mimetype] || '.jpg';
    const fname  = crypto.randomBytes(16).toString('hex') + ext;
    fs.writeFileSync(path.join(UPLOADS_DIR, fname), imageFile.data);
    imageUrl = `/uploads/${fname}`;
  }

  const post = {
    id:         crypto.randomBytes(8).toString('hex'),
    type,
    anonymous,
    _author:    session.username,
    authorName: anonymous ? 'Anónimo' : session.habboName,
    targetName: targetName || null,
    title,
    content,
    imageUrl,
    createdAt:  Date.now(),
    reactions:  { confirm: [], false: [], fire: [] },
  };

  db.posts.unshift(post);
  saveDB(db);
  ok(res, 201, publicPost(post));
}

// ─── Social: POST /social/posts/:id/react ────────────────────────────────────
async function handleReact(req, res, postId) {
  const session = getSession(req);
  if (!session) return ok(res, 401, { error: 'No autenticado' });

  let body; try { body = await readJSON(req); } catch (e) { return ok(res, 400, { error: e.message }); }
  const reaction = body.reaction;
  if (!REACTIONS.includes(reaction)) return ok(res, 400, { error: 'Reacción inválida' });

  const db   = loadDB();
  const post = db.posts?.find(p => p.id === postId);
  if (!post) return ok(res, 404, { error: 'Post no encontrado' });

  if (post._author === session.username) return ok(res, 403, { error: 'No puedes votar tu propio post' });

  const user = session.username;
  let removed = false;
  for (const r of REACTIONS) {
    if (!post.reactions[r]) post.reactions[r] = [];
    const i = post.reactions[r].indexOf(user);
    if (i !== -1) { post.reactions[r].splice(i, 1); if (r === reaction) removed = true; }
  }
  if (!removed) post.reactions[reaction].push(user);

  saveDB(db);
  ok(res, 200, { reactions: post.reactions });
}

// ─── Social: DELETE /social/posts/:id ────────────────────────────────────────
async function handleDeletePost(req, res, postId) {
  const session = getSession(req);
  if (!session) return ok(res, 401, { error: 'No autenticado' });

  const db  = loadDB();
  const idx = (db.posts || []).findIndex(p => p.id === postId);
  if (idx === -1) return ok(res, 404, { error: 'Post no encontrado' });
  if (db.posts[idx]._author !== session.username) return ok(res, 403, { error: 'Solo el autor puede borrar este post' });

  if (db.posts[idx].imageUrl) {
    try { fs.unlinkSync(path.join(UPLOADS_DIR, path.basename(db.posts[idx].imageUrl))); } catch {}
  }
  db.posts.splice(idx, 1);
  saveDB(db);
  ok(res, 200, { ok: true });
}

// ─── Social: GET /social/stats ────────────────────────────────────────────────
function handleStats(res) {
  const db    = loadDB();
  const posts = db.posts || [];
  const tc    = {};
  posts.filter(p => p.type === 'funa' && p.targetName).forEach(p => {
    tc[p.targetName] = (tc[p.targetName] || 0) + 1;
  });
  ok(res, 200, {
    totalPosts:     posts.length,
    totalFunas:     posts.filter(p => p.type === 'funa').length,
    totalGeneral:   posts.filter(p => p.type === 'post').length,
    totalRecommend: posts.filter(p => p.type === 'recommend').length,
    totalAnon:      posts.filter(p => p.anonymous).length,
    totalWithImg:   posts.filter(p => p.imageUrl).length,
    totalReactions: posts.reduce((s, p) => s + totR(p), 0),
    topReported: Object.entries(tc).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([name,count])=>({name,count})),
  });
}

// ─── Router ───────────────────────────────────────────────────────────────────
http.createServer(async (req, res) => {
  const ip     = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const parsed = url.parse(req.url, true);
  const pn     = parsed.pathname.replace(/\/+$/, '') || '/';
  const q      = parsed.query;
  const method = req.method.toUpperCase();

  if (method === 'OPTIONS') { setCORS(res); res.writeHead(204); res.end(); return; }

  if ((pn.startsWith('/auth') || pn.startsWith('/social') || pn.startsWith('/api')) && isRateLimited(ip, 60))
    return ok(res, 429, { error: 'Demasiadas peticiones. Espera un momento.' });

  console.log(`${new Date().toISOString().slice(11,19)} ${method} ${pn}`);

  // Health
  if (pn === '/health') {
    const db = loadDB();
    return ok(res, 200, { status: 'ok', posts: (db.posts||[]).length, users: Object.keys(db.users||{}).length });
  }

  // Auth
  if (pn === '/auth/register' && method === 'POST') return handleRegister(req, res);
  if (pn === '/auth/login'    && method === 'POST') return handleLogin(req, res);
  if (pn === '/auth/me'       && method === 'GET') {
    const s = getSession(req);
    return s ? ok(res, 200, { username: s.username, habboName: s.habboName }) : ok(res, 401, { error: 'No autenticado' });
  }

  // Social
  if (pn === '/social/stats'  && method === 'GET')  return handleStats(res);
  if (pn === '/social/posts'  && method === 'GET')  return handleGetPosts(res, q);
  if (pn === '/social/posts'  && method === 'POST') return handleCreatePost(req, res);

  let m;
  if ((m = pn.match(/^\/social\/posts\/([a-f0-9]{1,32})\/react$/)) && method === 'POST')  return handleReact(req, res, m[1]);
  if ((m = pn.match(/^\/social\/posts\/([a-f0-9]{1,32})$/))        && method === 'DELETE') return handleDeletePost(req, res, m[1]);

  // Uploads
  if (pn.startsWith('/uploads/') && method === 'GET') {
    const fname = path.basename(pn);
    const fpath = path.join(UPLOADS_DIR, fname);
    if (!fs.existsSync(fpath)) { res.writeHead(404); res.end(); return; }
    const ctMap = { '.jpg':'.jpg', '.jpeg':'image/jpeg', '.png':'image/png', '.gif':'image/gif', '.webp':'image/webp' };
    const ct = { '.jpg':'image/jpeg', '.jpeg':'image/jpeg', '.png':'image/png', '.gif':'image/gif', '.webp':'image/webp' }[path.extname(fname).toLowerCase()] || 'application/octet-stream';
    setCORS(res);
    res.writeHead(200, { 'Content-Type': ct, 'Cache-Control': 'public, max-age=86400' });
    fs.createReadStream(fpath).pipe(res);
    return;
  }

  // Solo GET para Habbo proxy
  if (method !== 'GET') return ok(res, 405, { error: 'Método no permitido' });

  if (pn === '/api/users' && q.name) return proxyJSON(res, `/api/public/users?name=${encodeURIComponent(q.name)}`);
  if ((m = pn.match(/^\/api\/users\/([^/]{1,50})\/profile$/)))      return proxyJSON(res, `/api/public/users/${encodeURIComponent(m[1])}/profile`);
  if ((m = pn.match(/^\/api\/users\/([^/]{1,50})\/achievements$/))) return proxyJSON(res, `/api/public/users/${encodeURIComponent(m[1])}/achievements`);
  if ((m = pn.match(/^\/api\/rooms\/([^/]{1,30})$/)))               return proxyJSON(res, `/api/public/rooms/${encodeURIComponent(m[1])}`);
  if ((m = pn.match(/^\/api\/groups\/([^/]{1,50})\/members$/)))     return proxyJSON(res, `/api/public/groups/${encodeURIComponent(m[1])}/members`);
  if ((m = pn.match(/^\/api\/groups\/([^/]{1,50})$/)))              return proxyJSON(res, `/api/public/groups/${encodeURIComponent(m[1])}`);

  if (pn === '/avatar' && q.figure)
    return proxyImg(res, `/habbo-imaging/avatarimage?figure=${encodeURIComponent(q.figure)}&size=${q.size||'l'}&gesture=${q.gesture||'sml'}&head_direction=${q.head_direction||'3'}&direction=${q.direction||'3'}`, 3600);

  if ((m = pn.match(/^\/badge\/([a-zA-Z0-9_-]{1,20})$/)))
    return proxyImg(res, `/habbo-imaging/badge/${m[1]}.gif`, 86400);

  ok(res, 404, { error: 'Ruta no encontrada' });

}).listen(PORT, '0.0.0.0', () => {
  console.log(`\n  🍄  HabboTracker API v5 — by Fungi`);
  console.log(`  Puerto: ${PORT}  |  CORS: ${FRONTEND_ORIGIN}\n`);
});
