const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'gateway.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    path_prefix TEXT NOT NULL UNIQUE,
    target_url TEXT NOT NULL,
    strip_prefix INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    title TEXT NOT NULL DEFAULT 'Gateway',
    public_root_message TEXT NOT NULL DEFAULT 'Choisissez une application à ouvrir.',
    updated_at TEXT DEFAULT (datetime('now'))
  );

  INSERT OR IGNORE INTO settings (id) VALUES (1);
`);

module.exports = db;
