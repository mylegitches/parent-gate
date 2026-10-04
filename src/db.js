import { existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { SERVICE_CATALOG } from './catalog.js';

export function openDatabase(dataDir) {
  mkdirSync(dataDir, { recursive: true });
  // Installs created before the rename keep their original database file.
  const legacyPath = join(dataDir, 'crackdown.db');
  const databasePath = existsSync(legacyPath) ? legacyPath : join(dataDir, 'parentgate.db');
  const database = new DatabaseSync(databasePath);
  database.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  migrate(database);
  seedCatalog(database);
  return database;
}

function migrate(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS parents (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      display_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      pin_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      parent_id TEXT NOT NULL REFERENCES parents(id) ON DELETE CASCADE,
      csrf_token TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      platform TEXT NOT NULL,
      os_version TEXT,
      client_version TEXT,
      capabilities_json TEXT NOT NULL DEFAULT '[]',
      credential_hash TEXT NOT NULL UNIQUE,
      push_token TEXT,
      desired_revision INTEGER NOT NULL DEFAULT 1,
      applied_revision INTEGER NOT NULL DEFAULT 0,
      last_seen TEXT,
      status_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS enrollment_codes (
      code_hash TEXT PRIMARY KEY,
      created_by TEXT NOT NULL REFERENCES parents(id),
      expires_at TEXT NOT NULL,
      used_at TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS services (
      id TEXT PRIMARY KEY,
      display_name TEXT NOT NULL,
      category TEXT NOT NULL,
      definition_json TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS device_targets (
      device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      target_key TEXT NOT NULL,
      display_name TEXT NOT NULL,
      target_kind TEXT NOT NULL,
      category_guess TEXT,
      mapping_json TEXT NOT NULL,
      source TEXT NOT NULL,
      currently_running INTEGER NOT NULL DEFAULT 0,
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      PRIMARY KEY (device_id, target_key)
    );

    CREATE TABLE IF NOT EXISTS device_target_profiles (
      device_id TEXT NOT NULL,
      target_key TEXT NOT NULL,
      profile_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (device_id, target_key, profile_id),
      FOREIGN KEY (device_id, target_key) REFERENCES device_targets(device_id, target_key) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS custom_websites (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      display_name TEXT NOT NULL,
      domain TEXT NOT NULL,
      default_blocked INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      UNIQUE (device_id, domain)
    );

    CREATE TABLE IF NOT EXISTS application_events (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      target_key TEXT NOT NULL,
      display_name TEXT NOT NULL,
      event_type TEXT NOT NULL CHECK (event_type IN ('started', 'stopped')),
      occurred_at TEXT NOT NULL,
      received_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS website_events (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      domain TEXT NOT NULL,
      browser TEXT NOT NULL,
      occurred_at TEXT NOT NULL,
      received_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS overrides (
      id TEXT PRIMARY KEY,
      operation_id TEXT UNIQUE,
      device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      target_type TEXT NOT NULL,
      target_id TEXT NOT NULL,
      action TEXT NOT NULL,
      effective_until TEXT,
      source TEXT NOT NULL,
      parent_id TEXT REFERENCES parents(id),
      base_revision INTEGER,
      message TEXT,
      status TEXT NOT NULL DEFAULT 'accepted',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      occurred_at TEXT NOT NULL,
      parent_id TEXT,
      device_id TEXT,
      event_type TEXT NOT NULL,
      summary TEXT NOT NULL,
      details_json TEXT NOT NULL DEFAULT '{}'
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
    CREATE INDEX IF NOT EXISTS idx_overrides_device ON overrides(device_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_device_targets_seen ON device_targets(device_id, last_seen DESC);
    CREATE INDEX IF NOT EXISTS idx_custom_websites_device ON custom_websites(device_id, display_name);
    CREATE INDEX IF NOT EXISTS idx_application_events_device_time ON application_events(device_id, occurred_at DESC);
    CREATE INDEX IF NOT EXISTS idx_website_events_device_time ON website_events(device_id, occurred_at DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(occurred_at DESC);
  `);

  const overrideColumns = new Set(db.prepare('PRAGMA table_info(overrides)').all().map((column) => column.name));
  if (!overrideColumns.has('message')) db.exec('ALTER TABLE overrides ADD COLUMN message TEXT');

  const deviceColumns = new Set(db.prepare('PRAGMA table_info(devices)').all().map((column) => column.name));
  if (!deviceColumns.has('screenshot_request_id')) db.exec('ALTER TABLE devices ADD COLUMN screenshot_request_id TEXT');
  if (!deviceColumns.has('screenshot_captured_at')) db.exec('ALTER TABLE devices ADD COLUMN screenshot_captured_at TEXT');
  if (!deviceColumns.has('screenshot_error')) db.exec('ALTER TABLE devices ADD COLUMN screenshot_error TEXT');
}

function seedCatalog(db) {
  const statement = db.prepare(`
    INSERT INTO services (id, display_name, category, definition_json, updated_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      display_name = excluded.display_name,
      category = excluded.category,
      definition_json = excluded.definition_json,
      updated_at = excluded.updated_at
  `);
  const now = new Date().toISOString();
  for (const service of SERVICE_CATALOG) {
    statement.run(service.id, service.displayName, service.category, JSON.stringify(service), now);
  }
}

export function audit(db, { parentId = null, deviceId = null, eventType, summary, details = {} }) {
  db.prepare(`
    INSERT INTO audit_events (occurred_at, parent_id, device_id, event_type, summary, details_json)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(new Date().toISOString(), parentId, deviceId, eventType, summary, JSON.stringify(details));
}
