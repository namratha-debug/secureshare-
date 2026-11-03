# Secure Expiring File Share

Share a file through a link or QR code that is **PIN-protected, encrypted, and self-destructing**.
Every access is recorded in an audit log.

## Run it

```bash
npm install
npm start          # http://localhost:3000
npm test           # 13 end-to-end checks on a throw-away database
```

Requires Node 18+. Data lives in `./data/` (SQLite database + an auto-generated `secret.key`).

## Features

- Email/password accounts (scrypt-hashed), httpOnly session cookies
- Upload a file (max 2 MB), pick a PIN, expiry (1 min – 24 h), download limit, optional email allow-list
- Share as a **link** or a **QR code** (generated on the server, nothing sent to third parties)
- Receiver can open a link **without an account** (unless the sender restricted it to specific emails)
- Live countdown, remaining downloads, and clear states: expired / revoked / locked / limit reached
- Owner dashboard: My Shares (revoke / expire early), Audit Logs (+ CSV export), Received, Downloaded
- Camera QR scanner and QR-image upload on the receiving side

## How it is secured

| Concern | What the server does |
|---|---|
| Files at rest | AES-256-GCM. Key = HMAC(server secret, scrypt(PIN, per-file salt)), so a stolen database alone cannot be brute-forced (a 4-digit PIN has only 10,000 possibilities) |
| PIN guessing | The PIN is verified **server-side**; 5 wrong attempts lock the link permanently |
| Expiry / limits | Enforced on the server. A background job (and the last permitted download) **deletes the ciphertext** |
| Allow-list | Checked against the logged-in session email, not anything the client sends |
| Passwords | scrypt + per-user salt, timing-safe compare, login rate limiting |
| Sessions | Random 256-bit id, only its SHA-256 is stored; password change signs out other devices |
| CSRF / XSS | SameSite=Lax cookies + same-origin check on writes; strict CSP (`script-src 'self'`); all output HTML-escaped; CSV export neutralises formula injection |
| Link privacy | `Referrer-Policy: no-referrer`; the public status endpoint never reveals file name or owner |

## Configuration (environment variables)

| Variable | Purpose |
|---|---|
| `PORT` | Port to listen on (default 3000) |
| `PUBLIC_URL` | Base URL used in links/QR codes, e.g. `https://share.example.org` |
| `SERVER_SECRET` | Encryption pepper. If unset, one is generated in `data/secret.key`. **Back it up: without it, stored files cannot be decrypted** |
| `DATA_DIR` | Where the database and secret live |
| `TRUST_PROXY` | Set to `true` when behind a reverse proxy (so rate limits and the audit log see real client IPs) |
| `NODE_ENV=production` | Marks cookies `Secure` |

## Deploying

Put it behind HTTPS (Render, Railway, Fly.io, or nginx/Caddy on a VPS), set `PUBLIC_URL`, `TRUST_PROXY=true`,
`NODE_ENV=production`, and mount a persistent disk at `DATA_DIR`.
**HTTPS is required for the camera scanner** (browsers block `getUserMedia` on plain http, except on localhost).

## Project layout

```
server.js        Express API + SQLite + encryption
test.js          End-to-end tests
public/
  index.html     App shell
  styles.css     Your original styling
  app.js         Your original UI, now talking to the API
```

## Known limitations (good next steps)

- Single server instance: SQLite file + in-memory rate limiter. For multiple instances use Postgres/Redis and object storage.
- No email verification or password reset (needs an email provider).
- A link locked by 5 wrong PINs stays locked; the owner must create a new share.
- 2 MB limit because files are uploaded as JSON/base64; switch to multipart/streaming for larger files.
