const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const db = new Database(path.join(__dirname, 'conges.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS absences (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL CHECK(type IN ('conge', 'rq')),
    date_debut TEXT NOT NULL,
    date_fin TEXT NOT NULL,
    demi_journee TEXT,
    note TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS preferences (
    id INTEGER PRIMARY KEY CHECK(id = 1),

    -- Congés payés (période 01/01 → 31/12)
    solde_conges REAL DEFAULT 25,
    conges_date_debut_periode TEXT DEFAULT (date('now', 'start of year')),
    conges_date_fin_periode TEXT DEFAULT (date('now', 'start of year', '+1 year', '-1 day')),

    -- RQ : indépendant, période libre
    rq_mode TEXT DEFAULT 'forfaitaire' CHECK(rq_mode IN ('forfaitaire', 'reel')),
    rq_forfait_annuel REAL DEFAULT 12,
    rq_jours_par_acquisition REAL DEFAULT 1,
    rq_cycle_jours_travailles INTEGER DEFAULT 20,
    rq_date_debut_periode TEXT DEFAULT (date('now', 'start of year')),

    -- Alternance : jours de cours récurrents (0=dimanche ... 6=samedi)
    cours_jours TEXT DEFAULT '',
    cours_dates TEXT DEFAULT '',

    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS rq_acquisitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date_acquisition TEXT NOT NULL,
    jours_acquis REAL NOT NULL,
    motif TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS auth_accounts (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    two_factor_enabled INTEGER DEFAULT 0,
    two_factor_secret TEXT,
    two_factor_temp_secret TEXT,
    two_factor_last_counter INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS auth_tokens (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(username) REFERENCES auth_accounts(username) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS auth_reset_tokens (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(username) REFERENCES auth_accounts(username) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS auth_login_challenges (
    challenge_token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(username) REFERENCES auth_accounts(username) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS auth_backup_codes (
    code_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(username) REFERENCES auth_accounts(username) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS auth_settings (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    username TEXT NOT NULL DEFAULT 'admin',
    password_hash TEXT,
    password_salt TEXT,
    token_hash TEXT,
    token_expires_at TEXT,
    updated_at TEXT DEFAULT (datetime('now'))
  );

  INSERT OR IGNORE INTO preferences (id) VALUES (1);
  INSERT OR IGNORE INTO auth_settings (id, username) VALUES (1, 'admin');
`);

const prefColumns = db.prepare(`PRAGMA table_info(preferences)`).all().map(c => c.name);
if (!prefColumns.includes('cours_jours')) {
  db.exec(`ALTER TABLE preferences ADD COLUMN cours_jours TEXT DEFAULT ''`);
}
if (!prefColumns.includes('cours_dates')) {
  db.exec(`ALTER TABLE preferences ADD COLUMN cours_dates TEXT DEFAULT ''`);
}

const auth = db.prepare(`SELECT * FROM auth_settings WHERE id = 1`).get();
if (!auth.password_hash || !auth.password_salt) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync('conges123', salt, 100000, 32, 'sha256').toString('hex');
  db.prepare(`
    UPDATE auth_settings
    SET password_hash = ?, password_salt = ?, updated_at = datetime('now')
    WHERE id = 1
  `).run(hash, salt);
}

const adminAuth = db.prepare(`SELECT username, password_hash, password_salt FROM auth_settings WHERE id = 1`).get();
const existingAdmin = adminAuth?.username
  ? db.prepare(`SELECT username FROM auth_accounts WHERE username = ?`).get(adminAuth.username)
  : null;
if (adminAuth?.username && !existingAdmin) {
  db.prepare(`
    INSERT INTO auth_accounts (username, password_hash, password_salt)
    VALUES (?, ?, ?)
  `).run(adminAuth.username, adminAuth.password_hash, adminAuth.password_salt);
}

const authAccountColumns = db.prepare(`PRAGMA table_info(auth_accounts)`).all().map(c => c.name);
for (const column of ['two_factor_enabled', 'two_factor_secret', 'two_factor_temp_secret', 'two_factor_last_counter']) {
  if (!authAccountColumns.includes(column)) {
    const defaultSql = column === 'two_factor_enabled' || column === 'two_factor_last_counter' ? 'INTEGER DEFAULT 0' : 'TEXT';
    db.exec(`ALTER TABLE auth_accounts ADD COLUMN ${column} ${defaultSql}`);
  }
}

module.exports = db;
