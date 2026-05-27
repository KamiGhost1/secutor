import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  jwk_thumbprint TEXT NOT NULL UNIQUE,
  jwk_json TEXT NOT NULL,
  contact_json TEXT,
  status TEXT NOT NULL DEFAULT 'valid',
  terms_agreed INTEGER NOT NULL DEFAULT 1,
  allow_list_json TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id),
  status TEXT NOT NULL,
  identifiers_json TEXT NOT NULL,
  not_before TEXT,
  not_after TEXT,
  expires_at TEXT NOT NULL,
  error_json TEXT,
  certificate_id TEXT,
  csr_der BLOB,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_orders_account ON orders(account_id, status);
CREATE INDEX IF NOT EXISTS idx_orders_expires ON orders(expires_at);

CREATE TABLE IF NOT EXISTS authorizations (
  id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL REFERENCES orders(id),
  identifier_type TEXT NOT NULL,
  identifier_value TEXT NOT NULL,
  wildcard INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_authz_order ON authorizations(order_id);
CREATE INDEX IF NOT EXISTS idx_authz_value ON authorizations(identifier_value, status);

CREATE TABLE IF NOT EXISTS challenges (
  id TEXT PRIMARY KEY,
  authz_id TEXT NOT NULL REFERENCES authorizations(id),
  type TEXT NOT NULL,
  token TEXT NOT NULL,
  status TEXT NOT NULL,
  validated_at TEXT,
  error_json TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_check_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chall_authz ON challenges(authz_id);
CREATE INDEX IF NOT EXISTS idx_chall_pending ON challenges(status, next_check_at);

CREATE TABLE IF NOT EXISTS nonces (
  value TEXT PRIMARY KEY,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nonces_expires ON nonces(expires_at);

CREATE TABLE IF NOT EXISTS certificates (
  id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL REFERENCES orders(id),
  account_id TEXT NOT NULL REFERENCES accounts(id),
  serial_hex TEXT NOT NULL UNIQUE,
  pem TEXT NOT NULL,
  chain_pem TEXT NOT NULL,
  not_before TEXT NOT NULL,
  not_after TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  revoked_at TEXT,
  revocation_reason INTEGER,
  issued_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_certs_account ON certificates(account_id, issued_at);
CREATE INDEX IF NOT EXISTS idx_certs_revoked ON certificates(revoked, not_after);

CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  actor_type TEXT NOT NULL,
  actor_id TEXT,
  action TEXT NOT NULL,
  target TEXT,
  ip TEXT,
  details_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
`;

export function openDb(filePath: string): Database.Database {
	fs.mkdirSync(path.dirname(filePath), {recursive: true});
	const db = new Database(filePath);
	db.pragma('journal_mode = WAL');
	db.pragma('foreign_keys = ON');
	db.exec(SCHEMA);
	return db;
}
