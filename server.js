const express = require('express');
const cookieSession = require('cookie-session');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const { Pool } = require('pg');
const { google } = require('googleapis');

const {
  BASE_URL = 'http://localhost:3000', DATABASE_URL, SESSION_SECRET = 'dev-secret',
  GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, MAIL_SENDER, MAIL_REFRESH_TOKEN, PORT = 3000,
} = process.env;

const missing = ['DATABASE_URL', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'MAIL_SENDER', 'MAIL_REFRESH_TOKEN'].filter((k) => !process.env[k]);
if (missing.length) console.error('MISSING ENVIRONMENT VARIABLES:', missing.join(', '));

const RECIPIENTS = ['delan2337@ellerslie.school.nz', 'gogetaishereforever77@gmail.com'];
const GAMES = { rng3: '17 News RNG 3 (2026)', rng2: '17 News RNG 2 (2025)' };
const TYPES = { bug: 'Bug report', question: 'Question', suggestion: 'Game suggestion', account: 'Account help', other: 'Something else' };

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL && !/localhost|127\.0\.0\.1/.test(DATABASE_URL) ? { rejectUnauthorized: false } : false,
});
// Neon closes idle connections; log instead of crashing
pool.on('error', (e) => console.error('DB pool error:', e.message));
pool.query(`CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY, name TEXT NOT NULL, name_key TEXT UNIQUE NOT NULL,
  pw_hash TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now())`)
  .catch((e) => console.error('DB setup failed:', e.message));

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '50kb' }));
app.use(cookieSession({
  name: 'rng-support', keys: [SESSION_SECRET], maxAge: 7 * 24 * 3600 * 1000,
  sameSite: 'lax', secure: BASE_URL.startsWith('https'), httpOnly: true,
}));
// Serve the page from /public, or from index.html in the root if the folder is missing.
// Only index.html is ever served from the root, never server.js or package.json.
const publicDir = path.join(__dirname, 'public');
const indexFile = [path.join(publicDir, 'index.html'), path.join(__dirname, 'index.html')].find((f) => fs.existsSync(f));
if (fs.existsSync(publicDir)) app.use(express.static(publicDir));
if (!indexFile) console.error('index.html not found. Put it in a folder named "public".');
app.get('/', (req, res) => indexFile ? res.sendFile(indexFile) : res.status(500).send('index.html is missing from the repo.'));

// --- Accounts: username + password ---
const scrypt = promisify(crypto.scrypt);
const clean = (s) => String(s || '').trim().replace(/\s+/g, ' ');
const keyOf = (name) => clean(name).toLowerCase();

async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  return `${salt.toString('hex')}:${(await scrypt(pw, salt, 64)).toString('hex')}`;
}
async function checkPw(pw, stored) {
  const [salt, hash] = stored.split(':');
  const got = await scrypt(pw, Buffer.from(salt, 'hex'), 64);
  return crypto.timingSafeEqual(got, Buffer.from(hash, 'hex'));
}

const fails = new Map();
const throttleKey = (req, name) => `${req.ip}|${keyOf(name)}`;
const locked = (k) => { const f = fails.get(k); return f && f.n >= 5 && Date.now() - f.t < 10 * 60 * 1000; };
const fail = (k) => { const f = fails.get(k); fails.set(k, { n: f && Date.now() - f.t < 10 * 60 * 1000 ? f.n + 1 : 1, t: Date.now() }); };

app.post('/auth/signup', async (req, res) => {
  const name = clean(req.body?.name), password = String(req.body?.password || '');
  if (!/^[\w .-]{2,30}$/.test(name)) return res.status(400).json({ error: 'Usernames are 2 to 30 characters: letters, numbers, spaces, _ . or -' });
  if (password.length < 8 || password.length > 100) return res.status(400).json({ error: 'Your password needs at least 8 characters.' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO users (name, name_key, pw_hash) VALUES ($1,$2,$3) ON CONFLICT (name_key) DO NOTHING RETURNING id, name',
      [name, keyOf(name), await hashPw(password)]);
    if (!rows.length) return res.status(409).json({ error: 'That username already has a support account. Log in instead.' });
    req.session = { user: { id: rows[0].id, name: rows[0].name } };
    res.json({ user: req.session.user });
  } catch (e) {
    console.error('Signup failed:', e.message);
    res.status(500).json({ error: 'Could not create your account. Try again.' });
  }
});

app.post('/auth/login', async (req, res) => {
  const name = clean(req.body?.name), password = String(req.body?.password || '');
  const k = throttleKey(req, name);
  if (locked(k)) return res.status(429).json({ error: 'Too many tries. Wait 10 minutes and try again.' });
  try {
    const { rows } = await pool.query('SELECT id, name, pw_hash FROM users WHERE name_key=$1', [keyOf(name)]);
    if (!rows.length || !(await checkPw(password, rows[0].pw_hash))) {
      fail(k);
      return res.status(401).json({ error: 'Wrong username or password.' });
    }
    fails.delete(k);
    req.session = { user: { id: rows[0].id, name: rows[0].name } };
    res.json({ user: req.session.user });
  } catch (e) {
    console.error('Login failed:', e.message);
    res.status(500).json({ error: 'Could not log you in. Try again.' });
  }
});

app.post('/auth/logout', (req, res) => { req.session = null; res.json({ ok: true }); });
app.get('/api/me', (req, res) => res.json({ user: req.session?.user || null }));

// --- Send support request through the Gmail API ---
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
const lastSent = new Map();

async function sendMail({ subject, html, replyTo }) {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !MAIL_SENDER || !MAIL_REFRESH_TOKEN) throw new Error('Mail environment variables are missing');
  const auth = new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET);
  auth.setCredentials({ refresh_token: MAIL_REFRESH_TOKEN });
  const gmail = google.gmail({ version: 'v1', auth });
  const mime = [
    `From: 17 News RNG Support <${MAIL_SENDER}>`,
    `To: ${RECIPIENTS.join(', ')}`,
    ...(replyTo ? [`Reply-To: ${replyTo}`] : []),
    `Subject: =?UTF-8?B?${b64(subject)}?=`,
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    b64(html),
  ].join('\r\n');
  const raw = Buffer.from(mime).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  await gmail.users.messages.send({ userId: 'me', requestBody: { raw } });
}

app.post('/api/support', async (req, res) => {
  const user = req.session?.user;
  if (!user) return res.status(401).json({ error: 'Log in first.' });

  const { game, type, subject, message } = req.body || {};
  const contact = String(req.body?.contact || '').trim();
  if (!GAMES[game] || !TYPES[type]) return res.status(400).json({ error: 'Pick a game and a request type.' });
  if (!subject?.trim() || !message?.trim()) return res.status(400).json({ error: 'Add a subject and a message.' });
  if (subject.length > 120 || message.length > 4000) return res.status(400).json({ error: 'Your message is too long.' });
  if (contact && !/^[^\s@<>,;]+@[^\s@<>,;]+\.[^\s@<>,;]+$/.test(contact)) return res.status(400).json({ error: 'That reply email does not look right.' });

  if (Date.now() - (lastSent.get(user.id) || 0) < 30000)
    return res.status(429).json({ error: 'Wait 30 seconds before sending another request.' });

  const html = `
    <div style="font-family:Arial,sans-serif;max-width:600px">
      <h2 style="margin:0 0 12px">${esc(TYPES[type])} – ${esc(GAMES[game])}</h2>
      <p><b>Username:</b> ${esc(user.name)}</p>
      <p><b>Reply email:</b> ${contact ? esc(contact) : 'Not given'}</p>
      <p><b>Subject:</b> ${esc(subject)}</p>
      <hr><p style="white-space:pre-wrap">${esc(message)}</p>
    </div>`;
  try {
    await sendMail({ subject: `[${GAMES[game]}] ${TYPES[type]}: ${subject.trim()}`, html, replyTo: contact });
    lastSent.set(user.id, Date.now());
    res.json({ ok: true });
  } catch (e) {
    console.error('MAIL FAILED:', e.message, JSON.stringify(e.response?.data || e.errors || ''));
    res.status(500).json({ error: 'Could not send your request. Try again in a minute.' });
  }
});

app.listen(PORT, () => console.log(`17 News RNG Support on :${PORT}`));
