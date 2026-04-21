const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const db = require('./database');

const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json());

const FORCE_HTTPS = String(process.env.FORCE_HTTPS || '').toLowerCase() === 'true';
if (FORCE_HTTPS) {
  app.use((req, res, next) => {
    if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
      return next();
    }
    return res.redirect(301, `https://${req.headers.host}${req.originalUrl}`);
  });
}

app.use(express.static(path.join(__dirname, 'public')));

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function normalizeBackupCode(code) {
  return String(code || '').replace(/[^A-Za-z0-9]/g, '').toUpperCase();
}

function getBearerToken(req) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return null;
  return header.slice(7).trim() || null;
}

function getAccountByUsername(username) {
  const account = db.prepare(`
    SELECT username, password_hash, password_salt, two_factor_enabled, two_factor_secret, two_factor_temp_secret, two_factor_last_counter
    FROM auth_accounts
    WHERE username = ?
  `).get(username);
  if (account) return account;
  if (username === 'admin') {
    return db.prepare('SELECT username, password_hash, password_salt FROM auth_settings WHERE id = 1').get() || null;
  }
  return null;
}

function getUserByToken(token) {
  const tokenHash = hashToken(token);
  const session = db.prepare('SELECT username, expires_at FROM auth_tokens WHERE token_hash = ?').get(tokenHash);
  if (!session) return null;
  const expiresAt = new Date(`${session.expires_at}Z`);
  if (Number.isNaN(expiresAt.getTime()) || expiresAt <= new Date()) {
    db.prepare('DELETE FROM auth_tokens WHERE token_hash = ?').run(tokenHash);
    return null;
  }
  return session.username;
}

function normalizeUsername(username) {
  return String(username || '').trim();
}

function accountExists(username) {
  const cleanUsername = normalizeUsername(username);
  return Boolean(db.prepare(`
    SELECT 1 AS found FROM auth_accounts WHERE username = ?
    UNION ALL
    SELECT 1 AS found FROM auth_settings WHERE id = 1 AND username = ?
    LIMIT 1
  `).get(cleanUsername, cleanUsername));
}

function getTotpSecret(account) {
  return account?.two_factor_enabled ? account.two_factor_secret : account?.two_factor_temp_secret || account?.two_factor_secret || null;
}

function countBackupCodes(username) {
  return db.prepare(`
    SELECT COUNT(*) AS count
    FROM auth_backup_codes
    WHERE username = ? AND used_at IS NULL
  `).get(username)?.count || 0;
}

function redeemBackupCode(username, code) {
  const normalized = normalizeBackupCode(code);
  if (!normalized) return false;

  const codeHash = hashToken(normalized);
  const row = db.prepare(`
    SELECT code_hash, used_at
    FROM auth_backup_codes
    WHERE username = ? AND code_hash = ?
  `).get(username, codeHash);

  if (!row || row.used_at) return false;

  db.prepare(`
    UPDATE auth_backup_codes
    SET used_at = datetime('now')
    WHERE code_hash = ?
  `).run(codeHash);
  return true;
}

function generateBackupCodes(username, amount = 10) {
  const codes = [];
  const insert = db.prepare(`
    INSERT INTO auth_backup_codes (code_hash, username)
    VALUES (?, ?)
  `);

  const transaction = db.transaction(() => {
    db.prepare('DELETE FROM auth_backup_codes WHERE username = ?').run(username);
    for (let i = 0; i < amount; i += 1) {
      const raw = crypto.randomBytes(8).toString('hex').toUpperCase();
      const formatted = raw.match(/.{1,4}/g).join('-');
      const normalized = normalizeBackupCode(formatted);
      insert.run(hashToken(normalized), username);
      codes.push(formatted);
    }
  });

  transaction();
  return codes;
}

function createAuthToken(username, remember) {
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + (remember ? 1000 * 60 * 60 * 24 * 30 : 1000 * 60 * 60 * 12));
  const expiresSql = expires.toISOString().slice(0, 19).replace('T', ' ');

  db.prepare(`
    INSERT INTO auth_tokens (token_hash, username, expires_at)
    VALUES (?, ?, ?)
  `).run(hashToken(token), username, expiresSql);

  return { token, expiresAt: expires.toISOString() };
}

function createLoginChallenge(username) {
  const challengeToken = crypto.randomBytes(24).toString('hex');
  const expires = new Date(Date.now() + 1000 * 60 * 10);
  const expiresSql = expires.toISOString().slice(0, 19).replace('T', ' ');
  db.prepare(`
    INSERT INTO auth_login_challenges (challenge_token, username, expires_at)
    VALUES (?, ?, ?)
  `).run(challengeToken, username, expiresSql);
  return { challengeToken, expiresAt: expires.toISOString() };
}

function verifyTotpCode(secret, token, lastCounter = 0) {
  const result = speakeasy.totp.verifyDelta({
    secret,
    encoding: 'base32',
    token: String(token || '').trim(),
    window: 1,
  });
  if (!result || typeof result.delta !== 'number') return null;

  const currentCounter = Math.floor(Date.now() / 30000);
  const acceptedCounter = currentCounter + result.delta;
  if (acceptedCounter <= Number(lastCounter || 0)) return null;
  return acceptedCounter;
}

function verifyTwoFactorRecoveryCode(account, code) {
  const secret = getTotpSecret(account);
  if (secret) {
    const acceptedCounter = verifyTotpCode(secret, code, account.two_factor_last_counter);
    if (acceptedCounter !== null) {
      return { type: 'totp', acceptedCounter };
    }
  }

  if (redeemBackupCode(account.username, code)) {
    return { type: 'backup' };
  }

  return null;
}

function persistPasswordUpdate(username, passwordHash, passwordSalt, extra = {}) {
  const current = db.prepare('SELECT username FROM auth_accounts WHERE username = ?').get(username);
  if (current) {
    db.prepare(`
      UPDATE auth_accounts
      SET password_hash = ?, password_salt = ?, two_factor_enabled = COALESCE(?, two_factor_enabled),
          two_factor_secret = COALESCE(?, two_factor_secret),
          two_factor_temp_secret = COALESCE(?, two_factor_temp_secret),
          two_factor_last_counter = COALESCE(?, two_factor_last_counter),
          updated_at = datetime('now')
      WHERE username = ?
    `).run(
      passwordHash,
      passwordSalt,
      extra.two_factor_enabled ?? null,
      extra.two_factor_secret ?? null,
      extra.two_factor_temp_secret ?? null,
      extra.two_factor_last_counter ?? null,
      username,
    );
  } else {
    db.prepare(`
      INSERT INTO auth_accounts (
        username, password_hash, password_salt, two_factor_enabled, two_factor_secret,
        two_factor_temp_secret, two_factor_last_counter
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      username,
      passwordHash,
      passwordSalt,
      extra.two_factor_enabled || 0,
      extra.two_factor_secret || null,
      extra.two_factor_temp_secret || null,
      extra.two_factor_last_counter || 0,
    );
  }
  if (username === 'admin') {
    db.prepare(`
      UPDATE auth_settings
      SET password_hash = ?, password_salt = ?, updated_at = datetime('now')
      WHERE id = 1
    `).run(passwordHash, passwordSalt);
  }
}

function updatePasswordForAccount(username, password) {
  const cleanUsername = normalizeUsername(username);
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(password, salt);

  persistPasswordUpdate(cleanUsername, hash, salt);

  db.prepare('DELETE FROM auth_tokens WHERE username = ?').run(cleanUsername);
  db.prepare('DELETE FROM auth_reset_tokens WHERE username = ?').run(cleanUsername);
  db.prepare('DELETE FROM auth_login_challenges WHERE username = ?').run(cleanUsername);
}

function updateUsernameForAccount(currentUsername, nextUsername) {
  const oldUsername = normalizeUsername(currentUsername);
  const newUsername = normalizeUsername(nextUsername);

  const currentAccount = db.prepare('SELECT * FROM auth_accounts WHERE username = ?').get(oldUsername);
  if (!currentAccount) return false;

  const tx = db.transaction(() => {
    db.prepare(`
      INSERT INTO auth_accounts (
        username, password_hash, password_salt, two_factor_enabled, two_factor_secret,
        two_factor_temp_secret, two_factor_last_counter, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).run(
      newUsername,
      currentAccount.password_hash,
      currentAccount.password_salt,
      currentAccount.two_factor_enabled || 0,
      currentAccount.two_factor_secret || null,
      currentAccount.two_factor_temp_secret || null,
      currentAccount.two_factor_last_counter || 0,
      currentAccount.created_at || null,
    );

    db.prepare('UPDATE auth_tokens SET username = ? WHERE username = ?').run(newUsername, oldUsername);
    db.prepare('UPDATE auth_reset_tokens SET username = ? WHERE username = ?').run(newUsername, oldUsername);
    db.prepare('UPDATE auth_login_challenges SET username = ? WHERE username = ?').run(newUsername, oldUsername);
    db.prepare('UPDATE auth_backup_codes SET username = ? WHERE username = ?').run(newUsername, oldUsername);

    db.prepare('DELETE FROM auth_accounts WHERE username = ?').run(oldUsername);

    db.prepare(`
      UPDATE auth_settings
      SET username = CASE WHEN username = ? THEN ? ELSE username END,
          updated_at = datetime('now')
      WHERE id = 1
    `).run(oldUsername, newUsername);
  });

  tx();
  return true;
}

function isAuthTokenValid(req) {
  const token = getBearerToken(req);
  if (!token) return false;
  return Boolean(getUserByToken(token));
}

app.get('/api/auth/status', (req, res) => {
  const token = getBearerToken(req);
  const username = token ? getUserByToken(token) : null;
  const account = username ? getAccountByUsername(username) : null;
  res.json({
    configured: true,
    authenticated: Boolean(username),
    username: username || 'admin',
    twoFactorEnabled: Boolean(account?.two_factor_enabled),
  });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password, remember } = req.body || {};
  const cleanUsername = normalizeUsername(username);
  const account = getAccountByUsername(cleanUsername);
  if (!account?.password_hash || !account?.password_salt) {
    return res.status(500).json({ error: 'Compte administrateur non configuré.' });
  }

  if (!cleanUsername || !password) {
    return res.status(400).json({ error: 'Identifiants manquants.' });
  }

  const expectedHash = hashPassword(password, account.password_salt);
  if (cleanUsername !== account.username || expectedHash !== account.password_hash) {
    return res.status(401).json({ error: 'Identifiants invalides.' });
  }

  const totpSecret = getTotpSecret(account);
  if (account.two_factor_enabled && totpSecret) {
    const challenge = createLoginChallenge(account.username);
    return res.json({
      requiresTwoFactor: true,
      challengeToken: challenge.challengeToken,
      expiresAt: challenge.expiresAt,
      username: account.username,
    });
  }

  const session = createAuthToken(account.username, remember);

  res.json({
    token: session.token,
    expiresAt: session.expiresAt,
    username: account.username,
  });
});

app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body || {};
  const cleanUsername = String(username || '').trim();
  const cleanPassword = String(password || '');

  if (cleanUsername.length < 3) {
    return res.status(400).json({ error: 'Le nom d’utilisateur doit contenir au moins 3 caractères.' });
  }
  if (cleanPassword.length < 6) {
    return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 6 caractères.' });
  }
  if (!/^[A-Za-z0-9._-]+$/.test(cleanUsername)) {
    return res.status(400).json({ error: 'Nom d’utilisateur invalide.' });
  }

  const exists = db.prepare(`
    SELECT 1 AS found FROM auth_accounts WHERE username = ?
    UNION ALL
    SELECT 1 AS found FROM auth_settings WHERE id = 1 AND username = ?
    LIMIT 1
  `).get(cleanUsername, cleanUsername);
  if (exists) {
    return res.status(409).json({ error: 'Ce nom d’utilisateur existe déjà.' });
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(cleanPassword, salt);
  db.prepare(`
    INSERT INTO auth_accounts (username, password_hash, password_salt)
    VALUES (?, ?, ?)
  `).run(cleanUsername, hash, salt);

  const token = crypto.randomBytes(32).toString('hex');
  const session = createAuthToken(cleanUsername, false);

  res.status(201).json({ token: session.token, expiresAt: session.expiresAt, username: cleanUsername });
});

app.post('/api/auth/2fa/verify', (req, res) => {
  const { challengeToken, code } = req.body || {};
  const challenge = db.prepare(`
    SELECT challenge_token, username, expires_at
    FROM auth_login_challenges
    WHERE challenge_token = ?
  `).get(String(challengeToken || '').trim());

  if (!challenge) {
    return res.status(401).json({ error: 'Challenge invalide.' });
  }

  const expiresAt = new Date(`${challenge.expires_at}Z`);
  if (Number.isNaN(expiresAt.getTime()) || expiresAt <= new Date()) {
    db.prepare('DELETE FROM auth_login_challenges WHERE challenge_token = ?').run(challenge.challenge_token);
    return res.status(401).json({ error: 'Challenge expiré.' });
  }

  const account = getAccountByUsername(challenge.username);
  const secret = getTotpSecret(account);
  if (!secret) {
    return res.status(400).json({ error: '2FA non configuré pour ce compte.' });
  }

  const acceptedCounter = verifyTotpCode(secret, code, account.two_factor_last_counter);
  if (acceptedCounter === null) {
    if (!redeemBackupCode(challenge.username, code)) {
      return res.status(401).json({ error: 'Code 2FA invalide.' });
    }

    db.prepare('DELETE FROM auth_login_challenges WHERE challenge_token = ?').run(challenge.challenge_token);
    const session = createAuthToken(challenge.username, false);
    return res.json({ token: session.token, expiresAt: session.expiresAt, username: challenge.username, backupCodeUsed: true });
  }

  db.prepare('DELETE FROM auth_login_challenges WHERE challenge_token = ?').run(challenge.challenge_token);
  db.prepare(`
    UPDATE auth_accounts
    SET two_factor_last_counter = ?, updated_at = datetime('now')
    WHERE username = ?
  `).run(acceptedCounter, challenge.username);

  const session = createAuthToken(challenge.username, false);
  res.json({ token: session.token, expiresAt: session.expiresAt, username: challenge.username });
});

app.get('/api/auth/2fa/status', (req, res) => {
  const token = getBearerToken(req);
  const username = token ? getUserByToken(token) : null;
  if (!username) {
    return res.status(401).json({ error: 'Authentification requise.' });
  }

  const account = getAccountByUsername(username);
  res.json({
    enabled: Boolean(account?.two_factor_enabled),
    backupCodesRemaining: countBackupCodes(username),
    username,
  });
});

app.post('/api/auth/2fa/setup/start', async (req, res) => {
  const token = getBearerToken(req);
  const username = token ? getUserByToken(token) : null;
  if (!username) {
    return res.status(401).json({ error: 'Authentification requise.' });
  }

  const account = getAccountByUsername(username);
  if (!account?.password_hash) {
    return res.status(404).json({ error: 'Compte introuvable.' });
  }

  const secret = speakeasy.generateSecret({
    name: `MesConges (${username})`,
    length: 20,
  });

  db.prepare(`
    UPDATE auth_accounts
    SET two_factor_temp_secret = ?, updated_at = datetime('now')
    WHERE username = ?
  `).run(secret.base32, username);

  const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url, { margin: 1, width: 220 });
  res.json({
    secret: secret.base32,
    otpauthUrl: secret.otpauth_url,
    qrDataUrl,
    username,
  });
});

app.post('/api/auth/2fa/setup/confirm', (req, res) => {
  const token = getBearerToken(req);
  const username = token ? getUserByToken(token) : null;
  if (!username) {
    return res.status(401).json({ error: 'Authentification requise.' });
  }

  const { password, code } = req.body || {};
  if (!password || !code) {
    return res.status(400).json({ error: 'Champs manquants.' });
  }

  const account = getAccountByUsername(username);
  const expectedHash = hashPassword(String(password), account.password_salt);
  if (expectedHash !== account.password_hash) {
    return res.status(401).json({ error: 'Mot de passe incorrect.' });
  }

  const secret = account.two_factor_temp_secret;
  if (!secret) {
    return res.status(400).json({ error: 'Aucune configuration 2FA en attente.' });
  }

  const acceptedCounter = verifyTotpCode(secret, code, account.two_factor_last_counter);
  if (acceptedCounter === null) {
    return res.status(401).json({ error: 'Code 2FA invalide.' });
  }

  db.prepare(`
    UPDATE auth_accounts
    SET two_factor_enabled = 1,
        two_factor_secret = ?,
        two_factor_temp_secret = NULL,
        two_factor_last_counter = ?,
        updated_at = datetime('now')
    WHERE username = ?
  `).run(secret, acceptedCounter, username);

  res.json({ success: true, enabled: true });
});

app.post('/api/auth/2fa/disable', (req, res) => {
  const token = getBearerToken(req);
  const username = token ? getUserByToken(token) : null;
  if (!username) {
    return res.status(401).json({ error: 'Authentification requise.' });
  }

  const { password } = req.body || {};
  if (!password) {
    return res.status(400).json({ error: 'Mot de passe manquant.' });
  }

  const account = getAccountByUsername(username);
  const expectedHash = hashPassword(String(password), account.password_salt);
  if (expectedHash !== account.password_hash) {
    return res.status(401).json({ error: 'Mot de passe incorrect.' });
  }

  db.prepare(`
    UPDATE auth_accounts
    SET two_factor_enabled = 0,
        two_factor_secret = NULL,
        two_factor_temp_secret = NULL,
        two_factor_last_counter = 0,
        updated_at = datetime('now')
    WHERE username = ?
  `).run(username);
  res.json({ success: true, enabled: false });
});

app.post('/api/auth/2fa/backup-codes/generate', (req, res) => {
  const token = getBearerToken(req);
  const username = token ? getUserByToken(token) : null;
  if (!username) {
    return res.status(401).json({ error: 'Authentification requise.' });
  }

  const { password } = req.body || {};
  if (!password) {
    return res.status(400).json({ error: 'Mot de passe manquant.' });
  }

  const account = getAccountByUsername(username);
  if (!account?.two_factor_enabled) {
    return res.status(400).json({ error: 'Activez d’abord l’authentification à deux facteurs.' });
  }
  const expectedHash = hashPassword(String(password), account.password_salt);
  if (expectedHash !== account.password_hash) {
    return res.status(401).json({ error: 'Mot de passe incorrect.' });
  }

  const codes = generateBackupCodes(username, 10);
  res.json({ codes, remaining: codes.length });
});

app.post('/api/auth/change-password', (req, res) => {
  const token = getBearerToken(req);
  const username = token ? getUserByToken(token) : null;
  if (!username) {
    return res.status(401).json({ error: 'Authentification requise.' });
  }

  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Champs manquants.' });
  }
  if (String(newPassword).length < 6) {
    return res.status(400).json({ error: 'Le nouveau mot de passe doit contenir au moins 6 caractères.' });
  }

  const account = getAccountByUsername(username);
  const expectedHash = hashPassword(String(currentPassword), account.password_salt);
  if (expectedHash !== account.password_hash) {
    return res.status(401).json({ error: 'Mot de passe actuel incorrect.' });
  }

  updatePasswordForAccount(username, String(newPassword));
  res.json({ success: true });
});

app.post('/api/auth/change-username', (req, res) => {
  const token = getBearerToken(req);
  const username = token ? getUserByToken(token) : null;
  if (!username) {
    return res.status(401).json({ error: 'Authentification requise.' });
  }

  const { currentPassword, newUsername } = req.body || {};
  const cleanUsername = normalizeUsername(newUsername);

  if (!currentPassword || !cleanUsername) {
    return res.status(400).json({ error: 'Champs manquants.' });
  }
  if (cleanUsername.length < 3) {
    return res.status(400).json({ error: 'Le nom d’utilisateur doit contenir au moins 3 caractères.' });
  }
  if (!/^[A-Za-z0-9._-]+$/.test(cleanUsername)) {
    return res.status(400).json({ error: 'Nom d’utilisateur invalide.' });
  }
  if (cleanUsername === username) {
    return res.status(400).json({ error: 'Le nouvel identifiant est identique à l’actuel.' });
  }
  if (accountExists(cleanUsername)) {
    return res.status(409).json({ error: 'Ce nom d’utilisateur existe déjà.' });
  }

  const account = db.prepare('SELECT username, password_hash, password_salt FROM auth_accounts WHERE username = ?').get(username);
  if (!account?.password_hash || !account?.password_salt) {
    return res.status(404).json({ error: 'Compte introuvable.' });
  }

  const expectedHash = hashPassword(String(currentPassword), account.password_salt);
  if (expectedHash !== account.password_hash) {
    return res.status(401).json({ error: 'Mot de passe actuel incorrect.' });
  }

  const updated = updateUsernameForAccount(username, cleanUsername);
  if (!updated) {
    return res.status(500).json({ error: 'Impossible de mettre à jour l’identifiant.' });
  }

  res.json({ success: true, username: cleanUsername });
});

app.post('/api/auth/forgot-password/request', (req, res) => {
  return res.status(410).json({ error: 'Utilisez directement un code 2FA ou un code de secours.' });
});

app.post('/api/auth/forgot-password/reset', (req, res) => {
  const { username, code, newPassword } = req.body || {};
  const cleanUsername = normalizeUsername(username);
  const cleanCode = String(code || '').trim().toUpperCase();
  const cleanPassword = String(newPassword || '');

  if (!cleanUsername || !cleanCode || !cleanPassword) {
    return res.status(400).json({ error: 'Champs manquants.' });
  }
  if (cleanPassword.length < 6) {
    return res.status(400).json({ error: 'Le nouveau mot de passe doit contenir au moins 6 caractères.' });
  }

  const account = getAccountByUsername(cleanUsername);
  if (!account?.password_hash) {
    return res.status(404).json({ error: 'Compte introuvable.' });
  }

  const recovery = verifyTwoFactorRecoveryCode(account, cleanCode);
  if (!recovery) {
    return res.status(401).json({ error: 'Code 2FA ou code de secours invalide.' });
  }

  updatePasswordForAccount(cleanUsername, cleanPassword);

  res.json({ success: true });
});

app.post('/api/auth/logout', (req, res) => {
  const token = getBearerToken(req);
  if (token) {
    db.prepare('DELETE FROM auth_tokens WHERE token_hash = ?').run(hashToken(token));
  }
  res.json({ success: true });
});

app.use('/api', (req, res, next) => {
  if (req.path.startsWith('/auth/')) return next();
  if (isAuthTokenValid(req)) return next();
  return res.status(401).json({ error: 'Authentification requise.' });
});

function fetchWithTimeout(url, timeoutMs = 5000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  return fetch(url, { signal: controller.signal }).finally(() => {
    clearTimeout(timer);
  });
}

// ─── CACHE JOURS FERIES (Nager.Date API) ─────────────────────────────────────

const feriesCache = {};

async function fetchFeriesYear(year) {
  if (feriesCache[year]) return feriesCache[year];
  try {
    const res = await fetchWithTimeout(`https://date.nager.at/api/v3/PublicHolidays/${year}/FR`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const dates = data.filter(h => h.global).map(h => h.date);
    feriesCache[year] = dates;
    console.log(`✅ Fériés ${year} chargés (${dates.length} jours)`);
    return dates;
  } catch (err) {
    console.error(`⚠️  Fériés ${year} indisponibles:`, err.message);
    feriesCache[year] = [];
    return [];
  }
}

async function getFeriesRange(dateDebut, dateFin) {
  const yearStart = new Date(dateDebut).getFullYear();
  const yearEnd = new Date(dateFin).getFullYear();
  const years = [];
  for (let y = yearStart; y <= yearEnd; y++) years.push(y);
  const results = await Promise.all(years.map(y => fetchFeriesYear(y)));
  const all = results.flat();
  return [...new Set(all)];
}

function getCachedFeriesRange(dateDebut, dateFin) {
  const yearStart = new Date(dateDebut).getFullYear();
  const yearEnd = new Date(dateFin).getFullYear();
  const all = [];

  for (let y = yearStart; y <= yearEnd; y++) {
    const cached = feriesCache[y];
    if (Array.isArray(cached)) all.push(...cached);
  }

  return [...new Set(all)];
}

async function preloadFeries() {
  const y = new Date().getFullYear();
  await Promise.all([
    fetchFeriesYear(y - 1),
    fetchFeriesYear(y),
    fetchFeriesYear(y + 1),
    fetchFeriesYear(y + 2),
  ]);
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────

function isWeekend(dateStr) {
  const d = new Date(`${dateStr}T00:00:00Z`);
  return d.getUTCDay() === 0 || d.getUTCDay() === 6;
}

function addDays(dateStr, n) {
  const d = new Date(`${dateStr}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().split('T')[0];
}

function isValidIsoDate(dateStr) {
  if (!dateStr || !/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return false;
  const d = new Date(`${dateStr}T00:00:00Z`);
  return !Number.isNaN(d.getTime());
}

function parseCoursJours(csv) {
  if (!csv) return new Set();
  return new Set(
    String(csv)
      .split(',')
      .map(s => Number(s.trim()))
      .filter(n => Number.isInteger(n) && n >= 0 && n <= 6)
  );
}

function parseCoursDates(csv) {
  if (!csv) return new Set();
  return new Set(
    String(csv)
      .split(',')
      .map(s => s.trim())
      .filter(isValidIsoDate)
  );
}

function getCoursDaysInRange(debut, fin, prefs) {
  const coursJours = parseCoursJours(prefs.cours_jours);
  const coursDates = parseCoursDates(prefs.cours_dates);
  if (!coursJours.size && !coursDates.size) return [];

  const hits = [];
  let cur = debut;
  while (cur <= fin) {
    const d = new Date(`${cur}T00:00:00Z`);
    if (coursJours.has(d.getUTCDay()) || coursDates.has(cur)) hits.push(cur);
    cur = addDays(cur, 1);
  }
  return hits;
}

async function countJoursOuvres(debut, fin) {
  const feries = getCachedFeriesRange(debut, fin);
  let count = 0;
  let cur = debut;
  while (cur <= fin) {
    if (!isWeekend(cur) && !feries.includes(cur)) count++;
    cur = addDays(cur, 1);
  }
  return count;
}

// ─── ROUTE : jours fériés ────────────────────────────────────────────────────

app.get('/api/feries/:year', async (req, res) => {
  const { year } = req.params;
  if (!/^\d{4}$/.test(year)) return res.status(400).json({ error: 'Année invalide' });
  res.json(await fetchFeriesYear(year));
});

app.get('/api/feries', async (req, res) => {
  const y = new Date().getFullYear();
  const years = [y - 1, y, y + 1, y + 2];
  const fetched = await Promise.all(years.map(async yr => [yr, await fetchFeriesYear(yr)]));
  const results = Object.fromEntries(fetched);
  res.json(results);
});

// ─── CALCUL SOLDE CONGES (période 01/01 → 31/12 stricte) ─────────────────────

async function calculSoldeConges(prefs, excludeId = null) {
  const debut = prefs.conges_date_debut_periode;
  const fin = prefs.conges_date_fin_periode;

  if (!debut || !fin) {
    return {
      initial: prefs.solde_conges,
      pose: 0,
      disponible: prefs.solde_conges,
      debut: null,
      fin: null,
    };
  }

  // Seules les absences dont date_debut est dans la période active
  const congesPoses = db.prepare(`
    SELECT date_debut, date_fin, demi_journee FROM absences
    WHERE type = 'conge'
      AND date_debut >= ?
      AND date_debut <= ?
      ${excludeId ? 'AND id <> ?' : ''}
  `).all(...(excludeId ? [debut, fin, excludeId] : [debut, fin]));

  let pose = 0;
  for (const c of congesPoses) {
    const j = await countJoursOuvres(c.date_debut, c.date_fin);
    pose += (c.demi_journee !== 'journee') ? 0.5 : j;
  }

  return {
    initial: prefs.solde_conges,
    pose: Math.round(pose * 2) / 2,
    disponible: Math.max(0, Math.round((prefs.solde_conges - pose) * 2) / 2),
    debut,
    fin,
  };
}

// ─── CALCUL SOLDE RQ (période libre, indépendante des congés) ────────────────

async function calculSoldeRQ(prefs, targetDate = null, excludeId = null) {
  const today = targetDate || new Date().toISOString().split('T')[0];
  const dateDebut = prefs.rq_date_debut_periode;

  if (!dateDebut || dateDebut > today) {
    return {
      acquis: 0,
      pose: 0,
      disponible: 0,
      mode: prefs.rq_mode,
      date_debut_periode: dateDebut,
    };
  }

  let acquis = 0;

  if (prefs.rq_mode === 'forfaitaire') {
    // Pro-rata sur 1 an depuis date_debut
    const debut = new Date(dateDebut);
    const fin = new Date(debut);
    fin.setFullYear(fin.getFullYear() + 1);
    const now = new Date(today);
    const totalMs = fin - debut;
    const ecoulMs = Math.min(Math.max(now - debut, 0), totalMs);
    const ratio = ecoulMs / totalMs;
    acquis = Math.floor(prefs.rq_forfait_annuel * ratio * 2) / 2;
  } else {
    // Mode réel : compte les jours ouvrés travaillés depuis rq_date_debut_periode
    const feriesList = getCachedFeriesRange(dateDebut, today);
    let joursOuvresBruts = 0;
    let cur = dateDebut;
    while (cur <= today) {
      const dow = new Date(cur).getDay();
      if (dow !== 0 && dow !== 6 && !feriesList.includes(cur)) joursOuvresBruts++;
      cur = addDays(cur, 1);
    }

    // Déduit toutes les absences (congés + RQ) sur cette même période
    const absences = db.prepare(`
      SELECT date_debut, date_fin, type, demi_journee FROM absences
      WHERE date_debut >= ? AND date_debut <= ?
      ${excludeId ? 'AND id <> ?' : ''}
    `).all(...(excludeId ? [dateDebut, today, excludeId] : [dateDebut, today]));

    let joursAbsents = 0;
    for (const a of absences) {
      const j = await countJoursOuvres(a.date_debut, a.date_fin);
      joursAbsents += (a.type === 'conge' && a.demi_journee !== 'journee') ? 0.5 : j;
    }

    const joursTravailes = Math.max(0, joursOuvresBruts - joursAbsents);
    const nbCycles = Math.floor(joursTravailes / prefs.rq_cycle_jours_travailles);
    acquis = nbCycles * prefs.rq_jours_par_acquisition;
  }

  // RQ posés depuis rq_date_debut_periode (indépendant de la période congés)
  const rqPoses = db.prepare(`
    SELECT date_debut, date_fin FROM absences
    WHERE type = 'rq' AND date_debut >= ?
    ${excludeId ? 'AND id <> ?' : ''}
  `).all(...(excludeId ? [dateDebut, excludeId] : [dateDebut]));

  let pose = 0;
  for (const r of rqPoses) {
    pose += await countJoursOuvres(r.date_debut, r.date_fin);
  }

  const disponible = Math.max(0, acquis - pose);

  return {
    acquis: Math.round(acquis * 2) / 2,
    pose: Math.round(pose * 2) / 2,
    disponible: Math.round(disponible * 2) / 2,
    mode: prefs.rq_mode,
    date_debut_periode: dateDebut,
  };
}

// ─── ROUTE : solde global ─────────────────────────────────────────────────────

app.get('/api/solde', async (req, res) => {
  try {
    const targetDate = (req.query.targetDate || '').toString();
    if (targetDate && !isValidIsoDate(targetDate)) {
      return res.status(400).json({ error: 'targetDate invalide (format attendu: YYYY-MM-DD)' });
    }

    const prefs = db.prepare('SELECT * FROM preferences WHERE id = 1').get();
    const [conges, rq] = await Promise.all([
      calculSoldeConges(prefs),
      calculSoldeRQ(prefs, targetDate || null),
    ]);
    res.json({ conges, rq });
  } catch (err) {
    console.error('Erreur /api/solde:', err);
    res.status(500).json({ error: 'Erreur lors du calcul du solde' });
  }
});

// ─── ROUTE : simulation RQ ────────────────────────────────────────────────────

app.get('/api/rq/simulation', async (req, res) => {
  try {
    const prefs = db.prepare('SELECT * FROM preferences WHERE id = 1').get();
    const dateDebut = prefs.rq_date_debut_periode;
    if (!dateDebut) return res.json({ points: [], mode: prefs.rq_mode });

    if (!isValidIsoDate(dateDebut)) {
      return res.status(400).json({
        error: 'La date de debut RQ est invalide. Corrigez-la dans les parametres.',
        points: [],
        mode: prefs.rq_mode,
      });
    }

    const dateFin = addDays(dateDebut, 365);
    const points = [];

    const absences = db.prepare(`
      SELECT date_debut, date_fin, type, demi_journee
      FROM absences
      WHERE date_fin >= ? AND date_debut <= ?
    `).all(dateDebut, dateFin);

    function countWeekdaysFast(startStr, endStr) {
      const start = new Date(`${startStr}T00:00:00Z`);
      const end = new Date(`${endStr}T00:00:00Z`);
      if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || start > end) return 0;
      let c = 0;
      const d = new Date(start);
      while (d <= end) {
        const dow = d.getUTCDay();
        if (dow !== 0 && dow !== 6) c++;
        d.setUTCDate(d.getUTCDate() + 1);
      }
      return c;
    }

    function overlapWeekdays(aStart, aEnd, bStart, bEnd) {
      const start = aStart > bStart ? aStart : bStart;
      const end = aEnd < bEnd ? aEnd : bEnd;
      return start <= end ? countWeekdaysFast(start, end) : 0;
    }

    let cur = dateDebut;
    let guard = 0;

    while (cur <= dateFin && guard < 18) {
      let acquis = 0;
      let pose = 0;

      if (prefs.rq_mode === 'forfaitaire') {
        const debutRef = new Date(`${dateDebut}T00:00:00Z`);
        const finRef = new Date(debutRef);
        finRef.setFullYear(finRef.getFullYear() + 1);
        const now = new Date(`${cur}T00:00:00Z`);
        const totalMs = finRef - debutRef;
        const ecoulMs = Math.min(Math.max(now - debutRef, 0), totalMs);
        const ratio = totalMs > 0 ? (ecoulMs / totalMs) : 0;
        acquis = Math.floor((prefs.rq_forfait_annuel || 0) * ratio * 2) / 2;
      } else {
        const joursOuvresBruts = countWeekdaysFast(dateDebut, cur);

        let joursAbsents = 0;
        for (const a of absences) {
          const overlap = overlapWeekdays(a.date_debut, a.date_fin, dateDebut, cur);
          if (!overlap) continue;
          joursAbsents += (a.type === 'conge' && a.demi_journee !== 'journee') ? 0.5 : overlap;
        }

        const joursTravailes = Math.max(0, joursOuvresBruts - joursAbsents);
        const cycle = Math.max(1, Number(prefs.rq_cycle_jours_travailles) || 1);
        const gain = Number(prefs.rq_jours_par_acquisition) || 0;
        acquis = Math.floor(joursTravailes / cycle) * gain;
      }

      for (const a of absences) {
        if (a.type !== 'rq') continue;
        pose += overlapWeekdays(a.date_debut, a.date_fin, dateDebut, cur);
      }

      const disponible = Math.max(0, acquis - pose);
      points.push({
        date: cur,
        acquis: Math.round(acquis * 2) / 2,
        pose: Math.round(pose * 2) / 2,
        disponible: Math.round(disponible * 2) / 2,
      });

      const d = new Date(`${cur}T00:00:00Z`);
      if (Number.isNaN(d.getTime())) break;
      d.setUTCMonth(d.getUTCMonth() + 1);
      cur = d.toISOString().split('T')[0];
      guard++;
    }

    res.json({ points, mode: prefs.rq_mode, approximate: prefs.rq_mode === 'reel' });
  } catch (err) {
    console.error('Erreur simulation RQ:', err.message);
    res.status(500).json({
      error: 'Erreur lors de la simulation RQ',
      points: [],
    });
  }
});

// ─── ROUTES ABSENCES ─────────────────────────────────────────────────────────

app.get('/api/absences', (req, res) => {
  const rows = db.prepare('SELECT * FROM absences ORDER BY date_debut').all();
  res.json(rows);
});

app.post('/api/absences', async (req, res) => {
  const { type, date_debut, date_fin, demi_journee, note } = req.body;

  if (!type || !date_debut || !date_fin || !demi_journee)
    return res.status(400).json({ error: 'Champs obligatoires manquants' });
  if (type === 'rq' && demi_journee !== 'journee')
    return res.status(400).json({ error: 'Les RQ doivent être en journée complète' });
  if (type === 'conge' && !['matin', 'apres-midi', 'journee'].includes(demi_journee))
    return res.status(400).json({ error: 'demi_journee invalide pour congé' });

  const prefs = db.prepare('SELECT * FROM preferences WHERE id = 1').get();
  const coursDays = getCoursDaysInRange(date_debut, date_fin, prefs);
  if (coursDays.length) {
    return res.status(400).json({
      error: `Impossible de poser une absence sur un jour de cours (${coursDays.slice(0, 3).join(', ')}${coursDays.length > 3 ? ', ...' : ''}).`,
      cours_jours: coursDays,
    });
  }

  const joursAbsence = await countJoursOuvres(date_debut, date_fin);

  if (type === 'conge') {
    // Vérifie que la date est dans la période congés active
    if (prefs.conges_date_debut_periode && prefs.conges_date_fin_periode) {
      if (
        date_debut < prefs.conges_date_debut_periode ||
        date_debut > prefs.conges_date_fin_periode
      ) {
        return res.status(400).json({
          error: `Date hors de la période de congés active (${prefs.conges_date_debut_periode} → ${prefs.conges_date_fin_periode}).`,
        });
      }
    }
    const soldeConges = await calculSoldeConges(prefs);
    const joursNecessaires = demi_journee !== 'journee' ? 0.5 : joursAbsence;
    if (soldeConges.disponible < joursNecessaires) {
      return res.status(400).json({
        error: `Solde congés insuffisant : ${soldeConges.disponible}j disponibles, ${joursNecessaires}j nécessaires.`,
        solde: soldeConges,
      });
    }
  } else {
    // RQ : pas de contrainte de période, uniquement solde acquis à la date de début
    const soldeRQ = await calculSoldeRQ(prefs, date_debut);
    if (soldeRQ.disponible < joursAbsence) {
      return res.status(400).json({
        error: `Solde RQ insuffisant : ${soldeRQ.disponible}j disponibles au ${date_debut}, ${joursAbsence}j nécessaires.`,
        solde: soldeRQ,
      });
    }
  }

  const id = uuidv4();
  db.prepare(`
    INSERT INTO absences (id, type, date_debut, date_fin, demi_journee, note)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, type, date_debut, date_fin, demi_journee, note || null);

  res.status(201).json({ id, type, date_debut, date_fin, demi_journee, note });
});

app.put('/api/absences/:id', async (req, res) => {
  const { id } = req.params;
  const { type, date_debut, date_fin, demi_journee, note } = req.body;

  if (!type || !date_debut || !date_fin || !demi_journee)
    return res.status(400).json({ error: 'Champs obligatoires manquants' });
  if (type === 'rq' && demi_journee !== 'journee')
    return res.status(400).json({ error: 'Les RQ doivent être en journée complète' });
  if (type === 'conge' && !['matin', 'apres-midi', 'journee'].includes(demi_journee))
    return res.status(400).json({ error: 'demi_journee invalide pour congé' });

  const existing = db.prepare('SELECT * FROM absences WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Absence introuvable' });

  const prefs = db.prepare('SELECT * FROM preferences WHERE id = 1').get();
  const coursDays = getCoursDaysInRange(date_debut, date_fin, prefs);
  if (coursDays.length) {
    return res.status(400).json({
      error: `Impossible de poser une absence sur un jour de cours (${coursDays.slice(0, 3).join(', ')}${coursDays.length > 3 ? ', ...' : ''}).`,
      cours_jours: coursDays,
    });
  }

  const joursAbsence = await countJoursOuvres(date_debut, date_fin);

  if (type === 'conge') {
    if (prefs.conges_date_debut_periode && prefs.conges_date_fin_periode) {
      if (
        date_debut < prefs.conges_date_debut_periode ||
        date_debut > prefs.conges_date_fin_periode
      ) {
        return res.status(400).json({
          error: `Date hors de la période de congés active (${prefs.conges_date_debut_periode} → ${prefs.conges_date_fin_periode}).`,
        });
      }
    }
    const soldeConges = await calculSoldeConges(prefs, id);
    const joursNecessaires = demi_journee !== 'journee' ? 0.5 : joursAbsence;
    if (soldeConges.disponible < joursNecessaires) {
      return res.status(400).json({
        error: `Solde congés insuffisant : ${soldeConges.disponible}j disponibles, ${joursNecessaires}j nécessaires.`,
        solde: soldeConges,
      });
    }
  } else {
    const soldeRQ = await calculSoldeRQ(prefs, date_debut, id);
    if (soldeRQ.disponible < joursAbsence) {
      return res.status(400).json({
        error: `Solde RQ insuffisant : ${soldeRQ.disponible}j disponibles au ${date_debut}, ${joursAbsence}j nécessaires.`,
        solde: soldeRQ,
      });
    }
  }

  db.prepare(`
    UPDATE absences SET
      type = ?,
      date_debut = ?,
      date_fin = ?,
      demi_journee = ?,
      note = ?
    WHERE id = ?
  `).run(type, date_debut, date_fin, demi_journee, note || null, id);

  res.json({ id, type, date_debut, date_fin, demi_journee, note: note || null });
});

app.delete('/api/absences/:id', (req, res) => {
  db.prepare('DELETE FROM absences WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ─── PREFERENCES ─────────────────────────────────────────────────────────────

app.get('/api/preferences', (req, res) => {
  res.json(db.prepare('SELECT * FROM preferences WHERE id = 1').get());
});

app.put('/api/preferences', (req, res) => {
  const {
    solde_conges,
    conges_date_debut_periode,
    conges_date_fin_periode,
    rq_mode,
    rq_forfait_annuel,
    rq_jours_par_acquisition,
    rq_cycle_jours_travailles,
    rq_date_debut_periode,
    cours_jours,
    cours_dates,
  } = req.body;

  db.prepare(`
    UPDATE preferences SET
      solde_conges = ?,
      conges_date_debut_periode = ?,
      conges_date_fin_periode = ?,
      rq_mode = ?,
      rq_forfait_annuel = ?,
      rq_jours_par_acquisition = ?,
      rq_cycle_jours_travailles = ?,
      rq_date_debut_periode = ?,
      cours_jours = ?,
      cours_dates = ?,
      updated_at = datetime('now')
    WHERE id = 1
  `).run(
    solde_conges,
    conges_date_debut_periode,
    conges_date_fin_periode,
    rq_mode,
    rq_forfait_annuel,
    rq_jours_par_acquisition,
    rq_cycle_jours_travailles,
    rq_date_debut_periode,
    cours_jours || '',
    cours_dates || '',
  );

  res.json({ success: true });
});

app.put('/api/preferences/cours', (req, res) => {
  const { cours_jours, cours_dates } = req.body || {};

  db.prepare(`
    UPDATE preferences SET
      cours_jours = ?,
      cours_dates = ?,
      updated_at = datetime('now')
    WHERE id = 1
  `).run(String(cours_jours || ''), String(cours_dates || ''));

  res.json({ success: true });
});

// ─── SUGGESTIONS IA ──────────────────────────────────────────────────────────

app.post('/api/suggestions', async (req, res) => {
  const { periodes_souhaitees } = req.body;

  const y = new Date().getFullYear();
  const allFeries = [];
  for (let yr = y; yr <= y + 3; yr++) allFeries.push(...(await fetchFeriesYear(yr)));

  const suggestions = [];

  // Ponts
  for (const ferie of allFeries) {
    const dow = new Date(ferie).getDay();
    let bridgeDate = null, label = '';

    if (dow === 4) {
      bridgeDate = addDays(ferie, 1);
      label = `Jeudi ${ferie} férié → poser le vendredi ${bridgeDate}`;
    } else if (dow === 2) {
      bridgeDate = addDays(ferie, -1);
      label = `Mardi ${ferie} férié → poser le lundi ${bridgeDate}`;
    }

    if (bridgeDate && !allFeries.includes(bridgeDate) && !isWeekend(bridgeDate)) {
      const debut = dow === 4 ? ferie : bridgeDate;
      const fin   = dow === 4 ? bridgeDate : ferie;
      const inPeriode = !periodes_souhaitees?.length ||
        periodes_souhaitees.some(p => debut >= p.debut && fin <= p.fin);
      if (inPeriode) {
        suggestions.push({
          type: 'pont',
          description: `${label} = 4 jours de repos consécutifs pour 1 seul jour posé`,
          date_debut: debut, date_fin: fin,
          jours_poses: 1, jours_gagnes: 4, score: 4,
        });
      }
    }
  }

  // Semaines riches en fériés
  const feriesParSemaine = {};
  for (const f of allFeries) {
    const d = new Date(f);
    const mon = new Date(d);
    mon.setDate(d.getDate() - (d.getDay() === 0 ? 6 : d.getDay() - 1));
    const key = mon.toISOString().split('T')[0];
    if (!feriesParSemaine[key]) feriesParSemaine[key] = [];
    feriesParSemaine[key].push(f);
  }

  for (const [lundi, feriesDeLaSemaine] of Object.entries(feriesParSemaine)) {
    if (feriesDeLaSemaine.length >= 2) {
      const vendredi = addDays(lundi, 4);
      const joursAPoses = await countJoursOuvres(lundi, vendredi);
      const inPeriode = !periodes_souhaitees?.length ||
        periodes_souhaitees.some(p => lundi >= p.debut && vendredi <= p.fin);
      if (inPeriode && joursAPoses <= 3) {
        suggestions.push({
          type: 'semaine_riche',
          description: `Semaine du ${lundi} : ${feriesDeLaSemaine.length} fériés (${feriesDeLaSemaine.join(', ')}) — ${joursAPoses}j seulement à poser pour toute la semaine`,
          date_debut: lundi, date_fin: vendredi,
          jours_poses: joursAPoses, jours_gagnes: 7,
          score: (feriesDeLaSemaine.length * 2) / Math.max(joursAPoses, 1),
        });
      }
    }
  }

  // Meilleure semaine dans chaque période souhaitée
  if (periodes_souhaitees?.length) {
    for (const p of periodes_souhaitees) {
      let bestStart = null, bestScore = -1;
      let cur = p.debut;
      while (cur <= addDays(p.fin, -6)) {
        const weekEnd = addDays(cur, 4);
        const feriesInWeek = allFeries.filter(f => f >= cur && f <= weekEnd).length;
        const joursOuvres = await countJoursOuvres(cur, weekEnd);
        if (joursOuvres > 0) {
          const score = feriesInWeek / joursOuvres;
          if (score > bestScore) { bestScore = score; bestStart = cur; }
        }
        cur = addDays(cur, 1);
      }
      if (bestStart) {
        const bestEnd = addDays(bestStart, 6);
        const jPoses = await countJoursOuvres(bestStart, bestEnd);
        if (!suggestions.find(s => s.date_debut === bestStart)) {
          suggestions.push({
            type: 'vacances',
            description: `Meilleure semaine dans "${p.debut} → ${p.fin}" : du ${bestStart} au ${bestEnd}, ${jPoses}j à poser (max fériés inclus)`,
            date_debut: bestStart, date_fin: bestEnd,
            jours_poses: jPoses, jours_gagnes: 7, score: bestScore,
          });
        }
      }
    }
  }

  res.json({
    suggestions: suggestions.sort((a, b) => b.score - a.score),
    feries: allFeries,
  });
});

// ─── START ────────────────────────────────────────────────────────────────────

const BASE_PORT = Number(process.env.PORT || 5000);
const SSL_KEY_PATH = process.env.SSL_KEY_PATH;
const SSL_CERT_PATH = process.env.SSL_CERT_PATH;

function buildServer() {
  if (SSL_KEY_PATH && SSL_CERT_PATH) {
    try {
      const key = fs.readFileSync(SSL_KEY_PATH);
      const cert = fs.readFileSync(SSL_CERT_PATH);
      return { server: https.createServer({ key, cert }, app), scheme: 'https' };
    } catch (err) {
      console.warn(`⚠️ Certificat HTTPS invalide, bascule en HTTP: ${err.message}`);
    }
  }

  return { server: http.createServer(app), scheme: 'http' };
}

function startServer(port) {
  const built = buildServer();
  const server = built.server;

  server.listen(port, () => {
    console.log(`✅ Serveur démarré sur ${built.scheme}://localhost:${port}`);
    console.log(`📅 Jours fériés chargés via https://date.nager.at`);
    preloadFeries().catch(err => {
      console.error('⚠️ Préchargement des jours fériés interrompu:', err.message);
    });
  });

  server.on('error', err => {
    if (err.code === 'EADDRINUSE' && port < BASE_PORT + 20) {
      console.warn(`⚠️ Port ${port} occupé, tentative sur ${port + 1}`);
      startServer(port + 1);
      return;
    }
    throw err;
  });
}

startServer(BASE_PORT);
