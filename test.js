// End-to-end test: run with `npm test` (starts its own server on a temp DB)
process.env.DATA_DIR = require('fs').mkdtempSync(require('os').tmpdir() + '/ss-');
const app = require('./server');
const assert = require('assert');
const srv = app.listen(0);
const base = `http://127.0.0.1:${srv.address().port}`;

class Client {
  constructor() { this.cookie = ''; }
  async req(path, body, method, headers = {}) {
    const r = await fetch(base + path, { method: method || (body === undefined ? 'GET' : 'POST'),
      headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(this.cookie ? { cookie: this.cookie } : {}), ...headers },
      body: body === undefined ? undefined : JSON.stringify(body) });
    const sc = r.headers.get('set-cookie'); if (sc) this.cookie = sc.split(';')[0];
    return r;
  }
}
const b64 = (s) => Buffer.from(s).toString('base64');
let n = 0; const ok = (m) => console.log(`  ✓ ${++n}. ${m}`);

(async () => {
  const alice = new Client(), bob = new Client(), anon = new Client();
  const share = (c, o = {}) => c.req('/api/shares', { name: 'secret.txt', mime: 'text/plain', data: b64('top secret ✓'),
    pin: '1234', minutes: 30, maxDownloads: -1, allowed: [], ...o }).then((r) => r.json());

  // auth
  assert.equal((await alice.req('/api/signup', { email: 'alice@x.com', password: 'short' })).status, 400);
  assert.equal((await alice.req('/api/signup', { email: 'alice@x.com', password: 'password123' })).status, 200);
  assert.equal((await bob.req('/api/signup', { email: 'bob@x.com', password: 'password123' })).status, 200);
  assert.equal((await alice.req('/api/signup', { email: 'alice@x.com', password: 'password123' })).status, 409);
  assert.equal((await new Client().req('/api/login', { email: 'alice@x.com', password: 'wrongpass1' })).status, 401);
  assert.equal((await anon.req('/api/shares')).status, 401);
  assert.equal((await alice.req('/api/me').then((r) => r.json())).email, 'alice@x.com');
  ok('signup / login / session / validation');

  // create + QR is a server-side data URL
  const s1 = await share(alice);
  assert.match(s1.token, /^[A-Z0-9]{6}$/); assert.ok(s1.qr.startsWith('data:image/png'));
  assert.ok(s1.link.endsWith('?token=' + s1.token));
  ok('share created with server-generated QR');

  // stored data is ciphertext
  const Database = require('better-sqlite3');
  const raw = new Database(process.env.DATA_DIR + '/app.db', { readonly: true }).prepare('SELECT blob FROM links WHERE token=?').get(s1.token).blob;
  assert.ok(!raw.includes('top secret'));
  ok('file is encrypted at rest');

  // public status never leaks the filename
  const st = await anon.req(`/api/links/${s1.token}/status`).then((r) => r.json());
  assert.equal(st.state, 'active'); assert.ok(!JSON.stringify(st).includes('secret.txt'));
  ok('public status endpoint leaks no file info');

  // PIN lockout (5 attempts), then even the right PIN is refused
  for (let i = 4; i >= 0; i--) {
    const r = await anon.req(`/api/links/${s1.token}/download`, { pin: '0000' });
    const j = await r.json(); assert.equal(r.status, 401); if (i) assert.match(j.s, new RegExp(`${i} attempt`));
  }
  let r = await anon.req(`/api/links/${s1.token}/download`, { pin: '1234' });
  assert.equal(r.status, 410); assert.equal((await r.json()).b, 'ACCESS LOCKED');
  ok('5 wrong PINs lock the link; correct PIN then refused');

  // happy path, anonymous, with unicode round trip + download counter
  const s2 = await share(alice, { maxDownloads: 2 });
  r = await anon.req(`/api/links/${s2.token}/download`, { pin: '1234' });
  assert.equal(r.status, 200); assert.equal(await r.text(), 'top secret ✓');
  assert.equal(decodeURIComponent(r.headers.get('x-file-name')), 'secret.txt');
  ok('correct PIN returns the decrypted file');
  assert.equal((await anon.req(`/api/links/${s2.token}/download`, { pin: '1234' })).status, 200);
  r = await anon.req(`/api/links/${s2.token}/download`, { pin: '1234' });
  assert.equal(r.status, 410); assert.equal((await r.json()).b, 'DOWNLOAD LIMIT REACHED');
  assert.equal(new Database(process.env.DATA_DIR + '/app.db', { readonly: true }).prepare('SELECT blob FROM links WHERE token=?').get(s2.token).blob, null);
  ok('download limit enforced and ciphertext deleted when spent');

  // allow-list
  const s3 = await share(alice, { allowed: ['bob@x.com'] });
  r = await anon.req(`/api/links/${s3.token}/download`, { pin: '1234' });
  assert.equal(r.status, 403); assert.equal((await r.json()).needLogin, true);
  const carol = new Client(); await carol.req('/api/signup', { email: 'carol@x.com', password: 'password123' });
  assert.equal((await carol.req(`/api/links/${s3.token}/download`, { pin: '1234' })).status, 403);
  assert.equal((await bob.req(`/api/links/${s3.token}/download`, { pin: '1234' })).status, 200);
  ok('email allow-list enforced (anon, wrong user, right user)');

  // histories
  const rec = await bob.req('/api/received').then((r) => r.json());
  assert.ok(rec.some((x) => x.n === 'secret.txt' && x.st === 'Opened'));
  const dls = await bob.req('/api/downloaded').then((r) => r.json()); assert.equal(dls.length, 1);
  await bob.req('/api/downloaded/' + dls[0].id, undefined, 'DELETE');
  assert.equal((await bob.req('/api/downloaded').then((r) => r.json())).length, 0);
  const audit = await alice.req('/api/audit').then((r) => r.json());
  assert.ok(audit.some((a) => a.status === 'Opened' && a.by === 'bob@x.com'));
  assert.ok(!(await bob.req('/api/audit').then((r) => r.json())).some((a) => a.file === 'secret.txt'), "bob can't see alice's audit");
  const csv = await (await alice.req('/api/audit.csv')).text(); assert.match(csv, /^Time,File name/);
  ok('received / downloaded / audit (owner-scoped) / CSV');

  // revoke + expire + ownership
  const s4 = await share(alice), s5 = await share(alice);
  assert.equal((await bob.req(`/api/shares/${s4.token}/revoke`, {})).status, 404);
  await alice.req(`/api/shares/${s4.token}/revoke`, {});
  assert.equal((await anon.req(`/api/links/${s4.token}/download`, { pin: '1234' }).then((r) => r.json())).b, 'ACCESS REVOKED');
  await alice.req(`/api/shares/${s5.token}/expire`, {});
  assert.equal((await anon.req(`/api/links/${s5.token}/download`, { pin: '1234' }).then((r) => r.json())).b, 'ACCESS DENIED: LINK EXPIRED');
  const mine = await alice.req('/api/shares').then((r) => r.json());
  assert.equal(mine.find((x) => x.token === s4.token).status, 'Revoked');
  ok('revoke / early-expire work; only the owner can do it');

  // validation + limits
  assert.equal((await alice.req('/api/shares', { name: 'a', data: b64('x'), pin: '12', minutes: 5, maxDownloads: -1, allowed: [] })).status, 400);
  assert.equal((await alice.req('/api/shares', { name: 'a', data: Buffer.alloc(2_100_000).toString('base64'), pin: '1234', minutes: 5, maxDownloads: -1, allowed: [] })).status, 413);
  assert.equal((await alice.req('/api/shares', { name: 'a', data: b64('x'), pin: '1234', minutes: 5, maxDownloads: -1, allowed: ['nope'] })).status, 400);
  ok('PIN / size / email validation');

  // CSRF + password change
  assert.equal((await alice.req('/api/logout', {}, 'POST', { origin: 'https://evil.example' })).status, 403);
  assert.equal((await alice.req('/api/me').then((r) => r.json())).email, 'alice@x.com');
  assert.equal((await alice.req('/api/password', { current: 'password123', next: 'newpassword9' })).status, 200);
  assert.equal((await new Client().req('/api/login', { email: 'alice@x.com', password: 'newpassword9' })).status, 200);
  await alice.req('/api/logout', {}); assert.equal((await alice.req('/api/shares')).status, 401);
  ok('cross-origin POST blocked; password change; logout kills session');

  // static
  assert.equal((await anon.req('/')).status, 200);
  assert.equal((await anon.req('/vendor/jsQR.js')).status, 200);
  assert.ok((await anon.req('/')).headers.get('content-security-policy').includes("script-src 'self'"));
  ok('static files + CSP served');
  console.log(`\nAll ${n} checks passed`); srv.close(); process.exit(0);
})().catch((e) => { console.error('\n✗ FAILED:', e); process.exit(1); });
