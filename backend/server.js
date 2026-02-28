'use strict';
/**
 * HabboTracker API — by Fungi 🍄 (v6)
 * - Sin login/auth
 * - Funas anónimas por defecto
 * - Persistencia en Turso (SQLite remoto)
 * - Rate limiting por IP
 */

const http   = require('http');
const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const url    = require('url');
const crypto = require('crypto');

// ─── Config ───────────────────────────────────────────────────────────────────
const PORT            = parseInt(process.env.PORT || '3001', 10);
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || '*';
const TURSO_URL       = process.env.TURSO_URL;
const TURSO_TOKEN     = process.env.TURSO_TOKEN;
const HABBO_HOST      = 'www.habbo.es';
const HABBO_TIMEOUT   = 10_000;
const DATA_DIR        = path.join(__dirname, 'data');
const UPLOADS_DIR     = path.join(DATA_DIR, 'uploads');
const MAX_IMG_BYTES   = 5 * 1024 * 1024;
const MAX_BODY_BYTES  = 6 * 1024 * 1024;
const ALLOWED_IMG     = new Set(['image/jpeg','image/jpg','image/png','image/gif','image/webp']);
const FUNAS_PER_PAGE  = 20;
const FUNAS_PER_HOUR  = 5;

// ─── Dirs ─────────────────────────────────────────────────────────────────────
for (const d of [DATA_DIR, UPLOADS_DIR])
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });

// ─── Turso HTTP client ────────────────────────────────────────────────────────
function sqlArg(v) {
  if (v === null || v === undefined) return { type: 'null' };
  if (typeof v === 'number') return Number.isInteger(v) ? { type: 'integer', value: String(v) } : { type: 'float', value: v };
  return { type: 'text', value: String(v) };
}

async function turso(statements) {
  if (!TURSO_URL || !TURSO_TOKEN) throw new Error('TURSO_URL y TURSO_TOKEN no configurados');

  const body = JSON.stringify({
    requests: statements.map(s =>
      typeof s === 'string'
        ? { type: 'execute', stmt: { sql: s } }
        : { type: 'execute', stmt: { sql: s.sql, args: (s.args || []).map(sqlArg) } }
    ).concat([{ type: 'close' }])
  });

  return new Promise((resolve, reject) => {
    const u = new url.URL('/v2/pipeline', TURSO_URL);
    const opts = {
      hostname: u.hostname,
      path:     u.pathname,
      method:   'POST',
      headers: {
        'Authorization':  `Bearer ${TURSO_TOKEN}`,
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
      timeout: 10_000,
    };
    const req = https.request(opts, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try {
          const data = JSON.parse(Buffer.concat(chunks).toString());
          if (res.statusCode >= 400) return reject(new Error(`Turso HTTP ${res.statusCode}`));
          resolve(data.results);
        } catch (e) { reject(e); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('Turso timeout')); });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function query(sql, args = []) {
  const results = await turso([{ sql, args }]);
  const r = results[0];
  if (r.type === 'error') throw new Error(r.error?.message || 'Turso error');
  const cols = r.response?.result?.cols?.map(c => c.name) || [];
  const rows = r.response?.result?.rows || [];
  return rows.map(row => Object.fromEntries(cols.map((c, i) => [c, row[i]?.value ?? null])));
}

async function exec(sql, args = []) {
  const results = await turso([{ sql, args }]);
  const r = results[0];
  if (r.type === 'error') throw new Error(r.error?.message || 'Turso error');
  return r.response?.result;
}

// ─── Init DB ──────────────────────────────────────────────────────────────────
async function initDB() {
  await turso([
    { sql: `CREATE TABLE IF NOT EXISTS funas (
        id         TEXT PRIMARY KEY,
        habbo_name TEXT,
        target     TEXT,
        content    TEXT NOT NULL,
        image_url  TEXT,
        ip_hash    TEXT,
        votes_si   INTEGER DEFAULT 0,
        votes_no   INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL
      )` },
    { sql: `CREATE TABLE IF NOT EXISTS votes (
        funa_id  TEXT NOT NULL,
        ip_hash  TEXT NOT NULL,
        vote     TEXT NOT NULL,
        PRIMARY KEY (funa_id, ip_hash)
      )` },
  ]);
  console.log('  ✓ Turso DB lista');
}

// ─── Rate limit ───────────────────────────────────────────────────────────────
const rlMap = new Map();
function isRateLimited(ip, maxPerMin = 120) {
  const now = Date.now();
  let e = rlMap.get(ip);
  if (!e || now > e.reset) e = { n: 0, reset: now + 60_000 };
  e.n++;
  rlMap.set(ip, e);
  return e.n > maxPerMin;
}
setInterval(() => { const now = Date.now(); for (const [k,v] of rlMap) if (now > v.reset) rlMap.delete(k); }, 60_000).unref();

async function canPostFuna(ipHash) {
  const oneHourAgo = Date.now() - 3_600_000;
  const rows = await query('SELECT COUNT(*) as cnt FROM funas WHERE ip_hash = ? AND created_at > ?', [ipHash, oneHourAgo]);
  return parseInt(rows[0]?.cnt || 0) < FUNAS_PER_HOUR;
}

function hashIP(ip) {
  return crypto.createHash('sha256').update(ip + (process.env.IP_SALT || 'hbt-salt-v6')).digest('hex').slice(0, 32);
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────
function setCORS(res) {
  res.setHeader('Access-Control-Allow-Origin',  FRONTEND_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
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

const san = (s, max) => String(s ?? '').trim().slice(0, max).replace(/[<>]/g, '');

// ─── Multipart ────────────────────────────────────────────────────────────────
function parseMultipart(buf, boundary) {
  const fields = {}; let file = null;
  let pos = buf.indexOf('--' + boundary);
  while (pos !== -1) {
    const after = pos + boundary.length + 2;
    if (buf[after] === 45 && buf[after+1] === 45) break;
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
    const r = https.request({
      hostname: HABBO_HOST, path: p, method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; HabboTracker/6.0)',
        'Accept': 'application/json,image/*,*/*',
        'Accept-Language': 'es-ES,es;q=0.9',
      },
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
    if (status < 200 || status >= 300) return ok(res, status, { error: `habbo.es devolvió ${status}` });
    ok(res, 200, JSON.parse(body.toString('utf8')));
  } catch (e) {
    ok(res, e.message === 'Timeout' ? 504 : 502, { error: e.message });
  }
}

async function proxyImg(res, p, cacheSeconds = 3600) {
  try {
    const { status, headers, body } = await habboFetch(p);
    if (status < 200 || status >= 300) { res.writeHead(status); res.end(); return; }
    setCORS(res);
    res.writeHead(200, {
      'Content-Type':   headers['content-type'] || 'image/gif',
      'Cache-Control':  `public, max-age=${cacheSeconds}`,
      'Content-Length': body.length,
    });
    res.end(body);
  } catch { res.writeHead(502); res.end(); }
}

// ─── Funas ────────────────────────────────────────────────────────────────────
async function handleGetFunas(res, q, ipHash) {
  const page   = Math.max(1, parseInt(q.page || '1'));
  const offset = (page - 1) * FUNAS_PER_PAGE;
  const target = q.target ? san(q.target, 60) : null;
  const sort   = q.sort === 'top' ? 'votes_si DESC, created_at DESC' : 'created_at DESC';
  const where  = target ? 'WHERE lower(target) = lower(?)' : '';
  const args   = target ? [target] : [];

  const [countRows, funas] = await Promise.all([
    query(`SELECT COUNT(*) as cnt FROM funas ${where}`, args),
    query(`SELECT id,habbo_name,target,content,image_url,votes_si,votes_no,created_at FROM funas ${where} ORDER BY ${sort} LIMIT ? OFFSET ?`, [...args, FUNAS_PER_PAGE, offset]),
  ]);

  const total = parseInt(countRows[0]?.cnt || 0);
  const funaIds = funas.map(f => f.id);
  let myVotes = {};
  if (funaIds.length > 0 && ipHash) {
    const ph = funaIds.map(() => '?').join(',');
    const voteRows = await query(`SELECT funa_id,vote FROM votes WHERE ip_hash=? AND funa_id IN (${ph})`, [ipHash, ...funaIds]);
    for (const v of voteRows) myVotes[v.funa_id] = v.vote;
  }

  ok(res, 200, {
    items: funas.map(f => ({
      id:        f.id,
      habboName: f.habbo_name || null,
      target:    f.target     || null,
      content:   f.content,
      imageUrl:  f.image_url  || null,
      votesSi:   parseInt(f.votes_si || 0),
      votesNo:   parseInt(f.votes_no || 0),
      myVote:    myVotes[f.id] || null,
      createdAt: parseInt(f.created_at),
    })),
    total,
    page,
    pages: Math.max(1, Math.ceil(total / FUNAS_PER_PAGE)),
  });
}

async function handleCreateFuna(req, res, ip) {
  const ipHash = hashIP(ip);
  const ct     = req.headers['content-type'] || '';
  let fields = {}, imageFile = null;

  if (ct.includes('multipart/form-data')) {
    const boundary = ct.match(/boundary=([^\s;]+)/)?.[1];
    if (!boundary) return ok(res, 400, { error: 'Boundary inválido' });
    const buf = await readRaw(req);
    const parsed = parseMultipart(buf, boundary);
    fields = parsed.fields; imageFile = parsed.file;
  } else {
    fields = await readJSON(req);
  }

  const content   = san(fields.content   || '', 500);
  const target    = san(fields.target    || '', 60);
  const habboName = san(fields.habboName || '', 60);

  if (content.length < 5)   return ok(res, 400, { error: 'El contenido debe tener al menos 5 caracteres' });
  if (content.length > 500) return ok(res, 400, { error: 'Máximo 500 caracteres' });

  const canPost = await canPostFuna(ipHash);
  if (!canPost) return ok(res, 429, { error: `Máximo ${FUNAS_PER_HOUR} funas por hora. Vuelve más tarde.` });

  let imageUrl = null;
  if (imageFile && imageFile.data.length > 0) {
    if (!ALLOWED_IMG.has(imageFile.mimetype)) return ok(res, 400, { error: 'Formato no permitido. Usa JPG, PNG, GIF o WEBP' });
    if (imageFile.data.length > MAX_IMG_BYTES) return ok(res, 413, { error: 'Imagen demasiado grande (máx 5 MB)' });
    const extMap = { 'image/gif':'.gif','image/png':'.png','image/webp':'.webp','image/jpeg':'.jpg','image/jpg':'.jpg' };
    const ext    = extMap[imageFile.mimetype] || '.jpg';
    const fname  = crypto.randomBytes(16).toString('hex') + ext;
    fs.writeFileSync(path.join(UPLOADS_DIR, fname), imageFile.data);
    imageUrl = `/uploads/${fname}`;
  }

  const id  = crypto.randomBytes(8).toString('hex');
  const now = Date.now();
  await exec('INSERT INTO funas (id,habbo_name,target,content,image_url,ip_hash,votes_si,votes_no,created_at) VALUES (?,?,?,?,?,?,0,0,?)',
    [id, habboName || null, target || null, content, imageUrl, ipHash, now]);

  ok(res, 201, { id, habboName: habboName || null, target: target || null, content, imageUrl, votesSi: 0, votesNo: 0, myVote: null, createdAt: now });
}

async function handleVote(req, res, funaId, ip) {
  const ipHash = hashIP(ip);
  let body; try { body = await readJSON(req); } catch (e) { return ok(res, 400, { error: e.message }); }
  const vote = body.vote;
  if (!['si', 'no'].includes(vote)) return ok(res, 400, { error: 'Voto inválido' });

  const rows = await query('SELECT id,votes_si,votes_no FROM funas WHERE id=?', [funaId]);
  if (!rows.length) return ok(res, 404, { error: 'Funa no encontrada' });

  const funa     = rows[0];
  const existing = await query('SELECT vote FROM votes WHERE funa_id=? AND ip_hash=?', [funaId, ipHash]);
  let votesSi = parseInt(funa.votes_si || 0);
  let votesNo = parseInt(funa.votes_no || 0);
  let myVote  = null;

  if (existing.length > 0) {
    const prev = existing[0].vote;
    if (prev === vote) {
      await exec('DELETE FROM votes WHERE funa_id=? AND ip_hash=?', [funaId, ipHash]);
      if (vote === 'si') votesSi = Math.max(0, votesSi - 1);
      else               votesNo = Math.max(0, votesNo - 1);
    } else {
      await exec('UPDATE votes SET vote=? WHERE funa_id=? AND ip_hash=?', [vote, funaId, ipHash]);
      if (vote === 'si') { votesSi++; votesNo = Math.max(0, votesNo - 1); }
      else               { votesNo++; votesSi = Math.max(0, votesSi - 1); }
      myVote = vote;
    }
  } else {
    await exec('INSERT INTO votes (funa_id,ip_hash,vote) VALUES (?,?,?)', [funaId, ipHash, vote]);
    if (vote === 'si') votesSi++; else votesNo++;
    myVote = vote;
  }

  await exec('UPDATE funas SET votes_si=?,votes_no=? WHERE id=?', [votesSi, votesNo, funaId]);
  ok(res, 200, { votesSi, votesNo, myVote });
}

async function handleStats(res) {
  const [totals, top] = await Promise.all([
    query('SELECT COUNT(*) as total, COUNT(CASE WHEN habbo_name IS NOT NULL AND habbo_name != "" THEN 1 END) as con_nombre, COUNT(CASE WHEN image_url IS NOT NULL THEN 1 END) as con_img FROM funas'),
    query('SELECT target, COUNT(*) as cnt FROM funas WHERE target IS NOT NULL AND target != "" GROUP BY lower(target) ORDER BY cnt DESC LIMIT 10'),
  ]);
  ok(res, 200, {
    totalFunas: parseInt(totals[0]?.total      || 0),
    conNombre:  parseInt(totals[0]?.con_nombre || 0),
    conImagen:  parseInt(totals[0]?.con_img    || 0),
    topFunados: top.map(r => ({ name: r.target, count: parseInt(r.cnt) })),
  });
}

// ─── Router ───────────────────────────────────────────────────────────────────
http.createServer(async (req, res) => {
  const ip     = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const parsed = new url.URL(req.url, 'http://localhost');
  const pn     = parsed.pathname.replace(/\/+$/, '') || '/';
  const q      = Object.fromEntries(parsed.searchParams.entries());
  const method = req.method.toUpperCase();

  if (method === 'OPTIONS') { setCORS(res); res.writeHead(204); res.end(); return; }
  if (isRateLimited(ip, 120)) return ok(res, 429, { error: 'Demasiadas peticiones' });

  console.log(`${new Date().toISOString().slice(11,19)} ${method} ${pn}`);

  try {
    if (pn === '/health' && method === 'GET') {
      const rows = await query('SELECT COUNT(*) as cnt FROM funas').catch(() => [{ cnt: 0 }]);
      return ok(res, 200, { status: 'ok', funas: parseInt(rows[0]?.cnt || 0), db: 'turso' });
    }

    // Funas
    if (pn === '/funas/stats' && method === 'GET') return await handleStats(res);
    if (pn === '/funas' && method === 'GET')        return await handleGetFunas(res, q, hashIP(ip));
    if (pn === '/funas' && method === 'POST')       return await handleCreateFuna(req, res, ip);

    let m;
    if ((m = pn.match(/^\/funas\/([a-f0-9]{1,32})\/vote$/)) && method === 'POST')
      return await handleVote(req, res, m[1], ip);

    // Uploads
    if (pn.startsWith('/uploads/') && method === 'GET') {
      const fname = path.basename(pn);
      const fpath = path.join(UPLOADS_DIR, fname);
      if (!fs.existsSync(fpath)) { res.writeHead(404); res.end(); return; }
      const ct = { '.jpg':'image/jpeg','.jpeg':'image/jpeg','.png':'image/png','.gif':'image/gif','.webp':'image/webp' }[path.extname(fname).toLowerCase()] || 'application/octet-stream';
      setCORS(res);
      res.writeHead(200, { 'Content-Type': ct, 'Cache-Control': 'public, max-age=86400' });
      fs.createReadStream(fpath).pipe(res);
      return;
    }

    if (method !== 'GET') return ok(res, 405, { error: 'Método no permitido' });

    // Habbo API proxy
    if (pn === '/api/users' && q.name)
      return proxyJSON(res, `/api/public/users?name=${encodeURIComponent(q.name)}`);
    if ((m = pn.match(/^\/api\/users\/([^/]{1,50})\/profile$/)))
      return proxyJSON(res, `/api/public/users/${encodeURIComponent(m[1])}/profile`);
    if ((m = pn.match(/^\/api\/users\/([^/]{1,50})\/friends$/)))
      return proxyJSON(res, `/api/public/users/${encodeURIComponent(m[1])}/friends`);

    // Avatar proxy
    if (pn === '/avatar' && q.figure)
      return proxyImg(res, `/habbo-imaging/avatarimage?figure=${encodeURIComponent(q.figure)}&size=${q.size||'l'}&gesture=sml&head_direction=3&direction=3`, 3600);

    // Badge proxy — corregido
    if ((m = pn.match(/^\/badge\/([a-zA-Z0-9_-]{1,30})$/))) {
      const code = m[1];
      try {
        const { status, headers, body } = await habboFetch(`/habbo-imaging/badge/${code}.gif`);
        if (status === 200) {
          setCORS(res);
          res.writeHead(200, { 'Content-Type': headers['content-type'] || 'image/gif', 'Cache-Control': 'public, max-age=86400', 'Content-Length': body.length });
          return res.end(body);
        }
      } catch {}
      return proxyImg(res, `/habbo-imaging/badge/${code}.png`, 86400);
    }

    ok(res, 404, { error: 'Ruta no encontrada' });

  } catch (e) {
    console.error('Error:', e.message);
    ok(res, 500, { error: 'Error interno del servidor' });
  }

}).listen(PORT, '0.0.0.0', async () => {
  console.log(`\n  🍄  HabboTracker API v6 — by Fungi`);
  console.log(`  Puerto: ${PORT} | CORS: ${FRONTEND_ORIGIN}`);
  if (!TURSO_URL || !TURSO_TOKEN) {
    console.warn('  ⚠️  TURSO_URL / TURSO_TOKEN no configurados');
  } else {
    try { await initDB(); } catch (e) { console.error('  ✗ Error Turso:', e.message); }
  }
  console.log('');
});
