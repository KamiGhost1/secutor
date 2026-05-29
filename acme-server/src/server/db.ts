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

// Migration 0002 — admin API support. Aditive only:
//  • accounts.deactivated_at, status now also allows 'deactivated' / 'banned'
//    (no CHECK in schema, validated by the app)
//  • certificates.revoked_by ('account' | 'admin:<fp>' | 'admin:<fp>:ban')
//  • certificates.revoke_event_id (groups cascade revokes for ban operations)
//  • orders.status now also allows 'expired' (set by expireOrdersWorker)
//  • indexes for the new filter shapes used by admin stats and listings
// Migration 0003 — server-managed DNS placement tracking.
// Lets the cleanup-on-restart logic find TXT records the server published
// before a crash, so the DNS zone doesn't accumulate stale challenge data.
function migrate0003DnsPlacements(db: Database.Database): void {
	db.exec(`
		CREATE TABLE IF NOT EXISTS dns_placements (
			id TEXT PRIMARY KEY,
			challenge_id TEXT NOT NULL,
			record_name TEXT NOT NULL,
			record_value TEXT NOT NULL,
			provider_label TEXT NOT NULL,
			placed_at TEXT NOT NULL,
			cleaned_at TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_dns_placements_ch    ON dns_placements(challenge_id);
		CREATE INDEX IF NOT EXISTS idx_dns_placements_open  ON dns_placements(cleaned_at);
	`);
	// Also extend orders so we can remember which orders the server is
	// managing TXT for (the per-order config travels with the order).
	const cols = (db.prepare("PRAGMA table_info(orders)").all() as Array<{name: string}>)
		.map(c => c.name);
	if (!cols.includes('dns_placement')) {
		db.exec(`ALTER TABLE orders ADD COLUMN dns_placement TEXT`); // 'client' (default) | 'server-managed'
	}
}

function migrate0002Admin(db: Database.Database): void {
	const accCols = (db.prepare("PRAGMA table_info(accounts)").all() as Array<{name: string}>)
		.map(c => c.name);
	if (!accCols.includes('deactivated_at')) {
		db.exec('ALTER TABLE accounts ADD COLUMN deactivated_at TEXT');
	}
	const certCols = (db.prepare("PRAGMA table_info(certificates)").all() as Array<{name: string}>)
		.map(c => c.name);
	if (!certCols.includes('revoked_by')) {
		db.exec('ALTER TABLE certificates ADD COLUMN revoked_by TEXT');
	}
	if (!certCols.includes('revoke_event_id')) {
		db.exec('ALTER TABLE certificates ADD COLUMN revoke_event_id TEXT');
	}
	db.exec(`
		CREATE INDEX IF NOT EXISTS idx_certs_issued      ON certificates(issued_at);
		CREATE INDEX IF NOT EXISTS idx_certs_not_after   ON certificates(not_after);
		CREATE INDEX IF NOT EXISTS idx_certs_revoked_at  ON certificates(revoked, revoked_at);
		CREATE INDEX IF NOT EXISTS idx_certs_account_v   ON certificates(account_id, revoked, not_after);
		CREATE INDEX IF NOT EXISTS idx_orders_created    ON orders(created_at);
		CREATE INDEX IF NOT EXISTS idx_orders_status_ts  ON orders(status, created_at);
		CREATE INDEX IF NOT EXISTS idx_authz_status      ON authorizations(status);
		CREATE INDEX IF NOT EXISTS idx_chall_status      ON challenges(status);
		CREATE INDEX IF NOT EXISTS idx_audit_action      ON audit_log(action, ts);
		CREATE INDEX IF NOT EXISTS idx_audit_target      ON audit_log(target);
	`);
}

// Migration 0004 — reissue jobs. The CA-rotation flow can ask the server
// to re-sign all (or a filtered subset of) active leaf certs with the new
// CA key. This runs as a background worker; the tables here track its
// state so it survives a restart.
function migrate0004ReissueJobs(db: Database.Database): void {
	db.exec(`
		CREATE TABLE IF NOT EXISTS reissue_jobs (
			id TEXT PRIMARY KEY,
			scope TEXT NOT NULL,
			params_json TEXT,
			status TEXT NOT NULL,            -- 'running' | 'done' | 'failed' | 'cancelled'
			total INTEGER NOT NULL DEFAULT 0,
			done INTEGER NOT NULL DEFAULT 0,
			failed INTEGER NOT NULL DEFAULT 0,
			rate_per_sec INTEGER NOT NULL DEFAULT 10,
			started_at TEXT NOT NULL,
			finished_at TEXT,
			actor_fp TEXT
		);
		CREATE TABLE IF NOT EXISTS reissue_job_items (
			id TEXT PRIMARY KEY,
			job_id TEXT NOT NULL,
			cert_id TEXT NOT NULL,
			status TEXT NOT NULL,            -- 'pending' | 'done' | 'failed'
			error TEXT,
			finished_at TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_reissue_items_job ON reissue_job_items(job_id, status);
	`);
}

// Migration 0005 — denormalised identifiers on certificates. Previously
// derived via a 3-way join (cert → order → authorizations); that's
// expensive on listings and impossible to index well for "find cert by
// SAN" queries. Now stored alongside the cert as a JSON array of strings
// (wildcards keep their `*.` prefix).
function migrate0005CertIdentifiers(db: Database.Database): void {
	const cols = (db.prepare("PRAGMA table_info(certificates)").all() as Array<{name: string}>)
		.map(c => c.name);
	if (!cols.includes('identifiers_json')) {
		db.exec('ALTER TABLE certificates ADD COLUMN identifiers_json TEXT');
	}
	// Backfill: any row left over from before this migration gets its
	// identifiers reconstructed from the order's authz rows.
	const stale = db
		.prepare('SELECT id, order_id FROM certificates WHERE identifiers_json IS NULL')
		.all() as Array<{id: string; order_id: string}>;
	if (stale.length) {
		const authzStmt = db.prepare(
			'SELECT identifier_value, wildcard FROM authorizations WHERE order_id=?',
		);
		const updateStmt = db.prepare('UPDATE certificates SET identifiers_json=? WHERE id=?');
		const fill = db.transaction(() => {
			for (const c of stale) {
				const rows = authzStmt.all(c.order_id) as Array<{
					identifier_value: string;
					wildcard: number;
				}>;
				const ids = Array.from(
					new Set(rows.map(a => (a.wildcard ? '*.' : '') + a.identifier_value)),
				);
				updateStmt.run(JSON.stringify(ids), c.id);
			}
		});
		fill();
	}
	db.exec(`CREATE INDEX IF NOT EXISTS idx_certs_idents ON certificates(identifiers_json);`);
}

export function openDb(filePath: string): Database.Database {
	fs.mkdirSync(path.dirname(filePath), {recursive: true});
	const db = new Database(filePath);
	db.pragma('journal_mode = WAL');
	db.pragma('foreign_keys = ON');
	db.exec(SCHEMA);
	migrate0002Admin(db);
	migrate0003DnsPlacements(db);
	migrate0004ReissueJobs(db);
	migrate0005CertIdentifiers(db);
	return db;
}
