'use strict';
const express = require('express');
const Database = require('better-sqlite3');
const QRCode = require('qrcode');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/$/, '');
const IS_PROD = process.env.NODE_ENV === 'production';
const MAX_FILE = 2_000_000;      // 2 MB, same as the UI promises
const MAX_ATTEMPTS = 5;          // wrong PINs before a link locks
const SESSION_MS = 7 * 24 * 3600 * 1000;
const EMAIL = /^\S+@\S+\.\S+$/;

fs.mkdirSync(DATA_DIR, { recursive: true });

/* ---------- server secret (pepper) for encryption at rest ---------- */
function loadSecret() {
  if (process.env.SERVER_SECRET) return crypto.createHash('sha256').update(process.env.SERVER_SECRET).digest();
  const f = path.join(DATA_DIR, 'secret.key');
  if (!fs.existsSync(f)) fs.writeFileSync(f, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
  return Buffer.from(fs.readFileSync(f, 'utf8').trim(), 'hex');
}
const SECRET = loadSecret();

/* ---------- database ---------- */
const db = new Database(path.join(DATA_DIR, 'app.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(email TEXT PRIMARY KEY, salt TEXT NOT NULL, hash TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, email TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS links(
  token TEXT PRIMARY KEY, owner TEXT NOT NULL, file_name TEXT NOT NULL, mime TEXT, size INTEGER,
  salt BLOB, iv BLOB, tag BLOB, blob BLOB,
  created INTEGER NOT NULL, expiry INTEGER NOT NULL, max_downloads INTEGER NOT NULL,
  download_count INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
  revoked INTEGER NOT NULL DEFAULT 0, allowed TEXT NOT NULL DEFAULT '[]');
CREATE INDEX IF NOT EXISTS links_owner ON links(owner, created);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, action TEXT, status TEXT,
  file TEXT, by TEXT, acc INTEGER, allowed TEXT, owner TEXT);
CREATE INDEX IF NOT EXISTS audit_owner ON audit(owner, ts);
CREATE TABLE IF NOT EXISTS received(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, ts INTEGER, name TEXT, status TEXT);
CREATE TABLE IF NOT EXISTS downloads(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, ts INTEGER, name TEXT);
`);

/* ---------- crypto helpers ---------- */
const scrypt = (pw, salt, len = 32) => crypto.scryptSync(pw, salt, len, { N: 16384, r: 8, p: 1 });
function fileKey(pin, salt) {            // PIN + per-file salt + server secret
  return crypto.createHmac('sha256', SECRET).update(scrypt(pin, salt)).digest();
}
function encryptFile(buf, pin, token) {
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', fileKey(pin, salt), iv);
  c.setAAD(Buffer.from(token));
  const blob = Buffer.concat([c.update(buf), c.final()]);
  return { salt, iv, tag: c.getAuthTag(), blob };
}
function decryptFile(r, pin) {           // returns Buffer or null on wrong PIN
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', fileKey(pin, r.salt), r.iv);
    d.setAAD(Buffer.from(r.token)); d.setAuthTag(r.tag);
    return Buffer.concat([d.update(r.blob), d.final()]);
  } catch { return null; }
}
const hashPw = (pw, salt) => scrypt(pw, Buffer.from(salt, 'hex'), 64).toString('hex');
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const safeEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
function makeToken() {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let t;
  do { t = Array.from(crypto.randomBytes(6), (n) => A[n % 36]).join(''); }
  while (db.prepare('SELECT 1 FROM links WHERE token=?').get(t));
  return t;
}

/* ---------- audit / history ---------- */
function log(action, status, x = {}) {
  db.prepare('INSERT INTO audit(ts,action,status,file,by,acc,allowed,owner) VALUES(?,?,?,?,?,?,?,?)')
    .run(Date.now(), action, status, x.file || '—', x.by || '—', x.acc ? 1 : 0, x.allowed || '—', x.owner ?? null);
}
const addReceived = (email, r, status) => {
  if (email && r && r.owner !== email)
    db.prepare('INSERT INTO received(email,ts,name,status) VALUES(?,?,?,?)').run(email, Date.now(), r.file_name, status);
};

/* ---------- tiny rate limiter ---------- */
const buckets = new Map();
function limit(name, max, windowMs, keyFn = (req) => req.ip) {
  return (req, res, next) => {
    const k = name + ':' + keyFn(req), now = Date.now();
    const arr = (buckets.get(k) || []).filter((t) => now - t < windowMs);
    if (arr.length >= max) return res.status(429).json({ b: 'Too many requests', s: 'Please wait a moment and try again.' });
    arr.push(now); buckets.set(k, arr); next();
  };
}
setInterval(() => { const now = Date.now(); for (const [k, v] of buckets) if (!v.some((t) => now - t < 3600e3)) buckets.delete(k); }, 600e3).unref();

/* ---------- app + security middleware ---------- */
const app = express();
if (process.env.TRUST_PROXY) app.set('trust proxy', process.env.TRUST_PROXY === 'true' ? 1 : process.env.TRUST_PROXY);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; " +
    "media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');          // keeps ?token= out of Referer headers
  res.setHeader('X-Frame-Options', 'DENY');
  if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
  next();
});
app.use(express.json({ limit: '3.5mb' }));
app.use((req, res, next) => {                               // CSRF: same-origin only for state changes
  if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    const o = req.get('origin');
    if (o) { try { if (new URL(o).host !== req.get('host')) return res.status(403).json({ b: 'Forbidden', s: 'Cross-site request blocked.' }); } catch { return res.status(403).end(); } }
  }
  next();
});

/* ---------- sessions ---------- */
function cookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').map((c) => c.trim().split(/=(.*)/s).slice(0, 2)).filter((p) => p[0]));
}
function startSession(req, res, email) {
  const id = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions(id,email,expires) VALUES(?,?,?)').run(sha(id), email, Date.now() + SESSION_MS);
  const secure = IS_PROD || req.secure ? '; Secure' : '';
  res.setHeader('Set-Cookie', `sid=${id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_MS / 1000}${secure}`);
}
function endSession(req, res) {
  const id = cookies(req).sid;
  if (id) db.prepare('DELETE FROM sessions WHERE id=?').run(sha(id));
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
}
app.use((req, res, next) => {                               // attach req.user (or null)
  req.user = null;
  const id = cookies(req).sid;
  if (id) {
    const s = db.prepare('SELECT email FROM sessions WHERE id=? AND expires>?').get(sha(id), Date.now());
    if (s) req.user = s.email;
  }
  next();
});
const needAuth = (req, res, next) => req.user ? next() : res.status(401).json({ b: 'Not signed in', s: 'Please log in.' });

/* ---------- auth routes ---------- */
const DUMMY_SALT = crypto.randomBytes(16).toString('hex');
const authLimit = limit('auth', 10, 15 * 60e3, (req) => req.ip + '|' + String(req.body?.email || '').toLowerCase());

app.post('/api/signup', authLimit, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  if (!EMAIL.test(email) || email.length > 254) return res.status(400).json({ s: 'Enter a valid email address.' });
  if (pw.length < 8 || pw.length > 200) return res.status(400).json({ s: 'Password must be at least 8 characters.' });
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) return res.status(409).json({ s: 'An account with this email already exists.' });
  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO users VALUES(?,?,?,?)').run(email, salt, hashPw(pw, salt), Date.now());
  log('Account created', 'Success', { owner: email, by: email });
  startSession(req, res, email);
  log('User logged in', 'Success', { owner: email, by: email });
  res.json({ email });
});

app.post('/api/login', authLimit, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  const h = hashPw(pw.slice(0, 200), u ? u.salt : DUMMY_SALT);   // same work whether or not the user exists
  if (!u || !safeEq(h, u.hash)) {
    if (u) log('Failed login attempt', 'Failed', { owner: email, by: email });
    return res.status(401).json({ s: 'Incorrect email or password.' });
  }
  startSession(req, res, email);
  log('User logged in', 'Success', { owner: email, by: email });
  res.json({ email });
});

app.post('/api/logout', (req, res) => {
  if (req.user) log('User logged out', 'Success', { owner: req.user, by: req.user });
  endSession(req, res); res.json({ ok: 1 });
});
app.get('/api/me', (req, res) => res.json({ email: req.user }));

app.post('/api/password', needAuth, authLimit, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(req.user);
  const cur = String(req.body.current || ''), next = String(req.body.next || '');
  if (!safeEq(hashPw(cur.slice(0, 200), u.salt), u.hash)) return res.status(400).json({ s: 'Current password is incorrect.' });
  if (next.length < 8 || next.length > 200) return res.status(400).json({ s: 'New password must be at least 8 characters.' });
  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare('UPDATE users SET salt=?,hash=? WHERE email=?').run(salt, hashPw(next, salt), req.user);
  const keep = sha(cookies(req).sid);                         // sign out every other device
  db.prepare('DELETE FROM sessions WHERE email=? AND id<>?').run(req.user, keep);
  log('Password changed', 'Success', { owner: req.user, by: req.user });
  res.json({ ok: 1 });
});

/* ---------- link state ---------- */
const stateOf = (r, now = Date.now()) =>
  r.revoked ? 'revoked'
  : r.attempts >= MAX_ATTEMPTS ? 'locked'
  : r.max_downloads !== -1 && r.download_count >= r.max_downloads ? 'limit'
  : now > r.expiry ? 'expired' : 'active';

const DEAD = {
  revoked: { b: 'ACCESS REVOKED', s: 'The owner has revoked all access to this file.', st: 'Denied', rc: 'Revoked' },
  locked:  { b: 'ACCESS LOCKED', s: `Too many incorrect PIN attempts (Limit: ${MAX_ATTEMPTS}). Access is locked.`, st: 'Denied', rc: 'Denied' },
  limit:   { b: 'DOWNLOAD LIMIT REACHED', s: 'This link has reached its maximum allowed downloads.', st: 'Expired', rc: 'Expired' },
  expired: { b: 'ACCESS DENIED: LINK EXPIRED', s: 'This link is no longer valid.', st: 'Expired', rc: 'Expired' },
};
const normTok = (t) => String(t || '').toUpperCase();
const validTok = (t) => /^[A-Z0-9]{6}$/.test(t);

/* ---------- sharing routes ---------- */
function publicBase(req) { return PUBLIC_URL || `${req.protocol}://${req.get('host')}`; }

app.post('/api/shares', needAuth, limit('create', 30, 3600e3, (r) => r.user), async (req, res) => {
  const { name, mime, data, pin, minutes, maxDownloads, allowed } = req.body || {};
  if (typeof data !== 'string' || !data) return res.status(400).json({ s: 'No file received.' });
  if (!/^\d{4}$/.test(String(pin))) return res.status(400).json({ s: 'PIN must be exactly 4 digits.' });
  const mins = Number(minutes), maxDl = Number(maxDownloads);
  if (!Number.isInteger(mins) || mins < 1 || mins > 10080) return res.status(400).json({ s: 'Invalid expiry.' });
  if (!(maxDl === -1 || (Number.isInteger(maxDl) && maxDl >= 1 && maxDl <= 1000))) return res.status(400).json({ s: 'Invalid download limit.' });
  const list = [...new Set((Array.isArray(allowed) ? allowed : []).map((x) => String(x).trim().toLowerCase()).filter(Boolean))];
  if (list.length > 50 || list.some((x) => !EMAIL.test(x))) return res.status(400).json({ s: 'Check the email addresses in “Who can open it”.' });
  const buf = Buffer.from(data, 'base64');
  if (!buf.length) return res.status(400).json({ s: 'The file is empty.' });
  if (buf.length > MAX_FILE) return res.status(413).json({ s: 'That file is too large. The limit is 2MB.' });
  const fileName = path.basename(String(name || 'file').replace(/\\/g, '/')).slice(0, 200) || 'file';

  const token = makeToken(), now = Date.now(), enc = encryptFile(buf, String(pin), token);
  db.prepare(`INSERT INTO links(token,owner,file_name,mime,size,salt,iv,tag,blob,created,expiry,max_downloads,allowed)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(token, req.user, fileName, String(mime || 'application/octet-stream').slice(0, 100), buf.length,
         enc.salt, enc.iv, enc.tag, enc.blob, now, now + mins * 60000, maxDl, JSON.stringify(list));
  log('Link Generated for Token ' + token, 'Created', { file: fileName, by: req.user, allowed: list.join(', ') || '—', owner: req.user });
  const link = `${publicBase(req)}/?token=${token}`;
  const qr = await QRCode.toDataURL(link, { width: 250, margin: 2 });
  res.json({ token, link, qr, expiry: now + mins * 60000 });
});

app.get('/api/shares', needAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM links WHERE owner=? ORDER BY created DESC').all(req.user);
  res.json(rows.map((r) => {
    const s = stateOf(r);
    return { token: r.token, fileName: r.file_name, created: r.created, downloads: r.download_count, maxDownloads: r.max_downloads,
      status: s === 'revoked' ? 'Revoked' : s === 'locked' ? 'Denied' : s === 'active' ? 'In use' : 'Expired' };
  }));
});

function ownLink(req, res) {
  const r = db.prepare('SELECT * FROM links WHERE token=? AND owner=?').get(normTok(req.params.token), req.user);
  if (!r) res.status(404).json({ s: 'Not found.' });
  return r;
}
app.post('/api/shares/:token/revoke', needAuth, (req, res) => {
  const r = ownLink(req, res); if (!r) return;
  db.prepare('UPDATE links SET revoked=1, blob=NULL WHERE token=?').run(r.token);
  log('Access revoked for token ' + r.token, 'Revoked', { file: r.file_name, by: req.user, owner: req.user });
  res.json({ ok: 1 });
});
app.post('/api/shares/:token/expire', needAuth, (req, res) => {
  const r = ownLink(req, res); if (!r) return;
  db.prepare('UPDATE links SET expiry=?, blob=NULL WHERE token=?').run(Date.now() - 1000, r.token);
  log('Link expired early for token ' + r.token, 'Expired', { file: r.file_name, by: req.user, owner: req.user });
  res.json({ ok: 1 });
});

/* ---------- history routes ---------- */
const auditRows = (u) => db.prepare('SELECT * FROM audit WHERE owner=? ORDER BY ts DESC, id DESC LIMIT 1000').all(u);
app.get('/api/audit', needAuth, (req, res) => res.json(auditRows(req.user)));
app.get('/api/audit.csv', needAuth, (req, res) => {
  const q = (v) => '"' + String(v).replace(/"/g, '""').replace(/^([=+\-@])/, "'$1") + '"';   // block CSV formula injection
  const fmt = (t) => new Date(t).toISOString().replace('T', ' ').slice(0, 19);
  const csv = 'Time,File name,Action,Opened by,Opened at,Allowed to open,Status\n' +
    auditRows(req.user).map((r) => [fmt(r.ts), r.file, r.action, r.by, r.acc ? fmt(r.ts).slice(11) : '—', r.allowed, r.status].map(q).join(',')).join('\n');
  res.type('text/csv').attachment('Audit_Logs.csv').send(csv);
});
app.get('/api/received', needAuth, (req, res) =>
  res.json(db.prepare('SELECT ts,name AS n,status AS st FROM received WHERE email=? ORDER BY ts DESC LIMIT 500').all(req.user)));
app.get('/api/downloaded', needAuth, (req, res) =>
  res.json(db.prepare('SELECT id,ts,name AS n FROM downloads WHERE email=? ORDER BY ts DESC LIMIT 500').all(req.user)));
app.delete('/api/downloaded/:id', needAuth, (req, res) => {
  db.prepare('DELETE FROM downloads WHERE id=? AND email=?').run(Number(req.params.id), req.user); res.json({ ok: 1 });
});

/* ---------- receiver routes ---------- */
// Status never reveals the file name or owner, only what the countdown needs.
app.get('/api/links/:token/status', limit('status', 120, 60e3), (req, res) => {
  const t = normTok(req.params.token);
  const r = validTok(t) && db.prepare('SELECT * FROM links WHERE token=?').get(t);
  if (!r) return res.json({ state: 'invalid' });
  const s = stateOf(r);
  res.json({ state: s, expiry: r.expiry, remaining: r.max_downloads === -1 ? null : r.max_downloads - r.download_count,
             restricted: JSON.parse(r.allowed).length > 0 });
});

app.post('/api/links/:token/download', limit('dl', 30, 60e3), (req, res) => {
  const t = normTok(req.params.token), pin = String(req.body?.pin ?? '');
  const me = req.user, by = me || `anonymous (${req.ip})`;
  const r = validTok(t) && db.prepare('SELECT * FROM links WHERE token=?').get(t);
  if (!r) {
    log('Access attempt: unknown token ' + t, 'Denied', { by, acc: 1 });
    return res.status(404).json({ b: 'INVALID LINK', s: 'Access denied. No file matches this link.', dead: 1 });
  }
  const allowed = JSON.parse(r.allowed);
  const x = { file: r.file_name, by, acc: 1, allowed: allowed.length ? allowed.join(', ') : '—', owner: r.owner };

  const s = stateOf(r);
  if (s !== 'active') {
    const d = DEAD[s];
    log(`Access blocked: ${s === 'locked' ? 'Too many wrong attempts for' : s === 'limit' ? 'Download limit reached for' : s === 'revoked' ? 'Link revoked' : 'Expired link used,'} token ${t}`, d.st, x);
    addReceived(me, r, d.rc);
    return res.status(410).json({ b: d.b, s: d.s, dead: 1 });
  }
  if (allowed.length && !allowed.includes(me || '')) {
    log('Email not allowed for token ' + t, 'Denied', x); addReceived(me, r, 'Denied');
    return res.status(403).json({ b: 'Not allowed', needLogin: !me,
      s: me ? 'Access denied. This email was not approved by the sender.' : 'This file is restricted. Log in with an approved email to open it.' });
  }

  const plain = /^\d{4}$/.test(pin) ? decryptFile(r, pin) : null;
  if (!plain) {
    const attempts = r.attempts + 1;
    db.prepare('UPDATE links SET attempts=? WHERE token=?').run(attempts, t);
    log('Wrong PIN entered for token ' + t, 'Denied', x); addReceived(me, r, 'Denied');
    const rem = MAX_ATTEMPTS - attempts;
    return res.status(401).json({ b: 'Wrong PIN', s: rem > 0 ? `Access denied. ${rem} attempt(s) remaining.` : 'Access locked due to 5 failed attempts.' });
  }

  const count = r.download_count + 1, spent = r.max_downloads !== -1 && count >= r.max_downloads;
  db.transaction(() => {
    db.prepare(`UPDATE links SET download_count=?, attempts=0${spent ? ', blob=NULL' : ''} WHERE token=?`).run(count, t);
    log('File downloaded for token ' + t, 'Opened', x); addReceived(me, r, 'Opened');
    if (me) db.prepare('INSERT INTO downloads(email,ts,name) VALUES(?,?,?)').run(me, Date.now(), r.file_name);
  })();
  res.set({
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(r.file_name)}`,
    'X-File-Name': encodeURIComponent(r.file_name),
    'Content-Length': plain.length,
  }).end(plain);
});

/* ---------- static files ---------- */
app.get('/vendor/jsQR.js', (req, res) => res.sendFile(require.resolve('jsqr/dist/jsQR.js')));
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', maxAge: IS_PROD ? '1h' : 0 }));
app.use('/api', (req, res) => res.status(404).json({ s: 'Not found.' }));
app.use((err, req, res, next) => {                       // body-too-large / bad JSON etc.
  if (err.type === 'entity.too.large') return res.status(413).json({ s: 'That file is too large. The limit is 2MB.' });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ s: 'Bad request.' });
  console.error(err); res.status(500).json({ s: 'Server error.' });
});

/* ---------- housekeeping: actually delete expired data ---------- */
function sweep() {
  const now = Date.now();
  db.prepare(`UPDATE links SET blob=NULL WHERE blob IS NOT NULL AND
    (expiry<=? OR revoked=1 OR (max_downloads<>-1 AND download_count>=max_downloads))`).run(now);
  db.prepare('DELETE FROM sessions WHERE expires<?').run(now);
}
sweep(); setInterval(sweep, 60e3).unref();

if (require.main === module) app.listen(PORT, () => console.log(`Secure Expiring File Share running on http://localhost:${PORT}`));
module.exports = app;
