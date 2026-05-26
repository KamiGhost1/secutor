import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import Database from 'better-sqlite3';
import {
	contextDbFile,
	contextEncryptedFile,
	contextDir,
} from './paths.js';
import {encryptBuffer, decryptBuffer} from './crypto.js';
import {getContextMeta, ContextMeta} from './contextStore.js';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS certificates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL CHECK(type IN ('ca','server','client')),
  common_name TEXT NOT NULL,
  organization TEXT,
  issuer_id INTEGER,
  serial TEXT NOT NULL,
  not_before TEXT NOT NULL,
  not_after TEXT NOT NULL,
  san TEXT,
  cert_pem TEXT NOT NULL,
  key_pem TEXT NOT NULL DEFAULT '',
  fingerprint TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(issuer_id) REFERENCES certificates(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_certs_type ON certificates(type);
CREATE INDEX IF NOT EXISTS idx_certs_cn ON certificates(common_name);
CREATE INDEX IF NOT EXISTS idx_certs_issuer ON certificates(issuer_id);

CREATE TABLE IF NOT EXISTS profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  cert_id INTEGER NOT NULL,
  format TEXT NOT NULL DEFAULT 'p12',
  friendly_name TEXT,
  data BLOB NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(cert_id) REFERENCES certificates(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ssh_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  algorithm TEXT NOT NULL,
  comment TEXT,
  public_key TEXT NOT NULL,
  private_key TEXT NOT NULL,
  encrypted INTEGER NOT NULL DEFAULT 0,
  fingerprint TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ssh_keys_name ON ssh_keys(name);
`;

function migrate(db: Database.Database): void {
	const cols = db
		.prepare("PRAGMA table_info(certificates)")
		.all() as Array<{name: string}>;
	const have = new Set(cols.map(c => c.name));
	if (!have.has('revoked_at')) {
		db.exec('ALTER TABLE certificates ADD COLUMN revoked_at TEXT');
	}
	if (!have.has('revocation_reason')) {
		db.exec('ALTER TABLE certificates ADD COLUMN revocation_reason TEXT');
	}

	// ssh_keys was added in a later version of the schema; the CREATE TABLE
	// IF NOT EXISTS in SCHEMA handles new installs, but for older contexts
	// without the table the migration is a no-op (the SCHEMA exec creates it).
}

export type OpenSession = {
	contextName: string;
	encrypted: boolean;
	password: string | null;
	db: Database.Database;
	tempPath: string | null;
	plainPath: string;
};

let current: OpenSession | null = null;

function newTempPath(): string {
	return path.join(
		os.tmpdir(),
		`secutor-${crypto.randomBytes(8).toString('hex')}.db`,
	);
}

export function openContext(name: string, password: string | null): OpenSession {
	closeContext();
	const meta = getContextMeta(name);
	if (!meta) throw new Error(`Context "${name}" not found`);
	fs.mkdirSync(contextDir(name), {recursive: true});

	if (meta.encrypted) {
		if (!password) throw new Error('Password required for encrypted context');
		const encFile = contextEncryptedFile(name);
		const tempPath = newTempPath();
		if (fs.existsSync(encFile)) {
			const blob = fs.readFileSync(encFile);
			const plain = decryptBuffer(blob, password);
			fs.writeFileSync(tempPath, plain, {mode: 0o600});
		}
		const db = new Database(tempPath);
		db.pragma('journal_mode = MEMORY');
		db.pragma('foreign_keys = ON');
		db.exec(SCHEMA);
		migrate(db);
		current = {
			contextName: name,
			encrypted: true,
			password,
			db,
			tempPath,
			plainPath: tempPath,
		};
	} else {
		const dbFile = contextDbFile(name);
		const db = new Database(dbFile);
		db.pragma('journal_mode = WAL');
		db.pragma('foreign_keys = ON');
		db.exec(SCHEMA);
		migrate(db);
		current = {
			contextName: name,
			encrypted: false,
			password: null,
			db,
			tempPath: null,
			plainPath: dbFile,
		};
	}
	return current;
}

export function getDb(): Database.Database {
	if (!current) throw new Error('No context opened');
	return current.db;
}

export function getCurrentSession(): OpenSession | null {
	return current;
}

export function persist(): void {
	if (!current) return;
	if (!current.encrypted) return;
	current.db.pragma('wal_checkpoint(TRUNCATE)');
	const buf = fs.readFileSync(current.plainPath);
	const enc = encryptBuffer(buf, current.password!);
	fs.writeFileSync(contextEncryptedFile(current.contextName), enc, {mode: 0o600});
}

export function closeContext(): void {
	if (!current) return;
	try {
		current.db.close();
	} catch {}
	if (current.encrypted && current.tempPath) {
		try {
			fs.unlinkSync(current.tempPath);
		} catch {}
	}
	current = null;
}

export function migrateContextEncryption(
	name: string,
	oldPassword: string | null,
	newPassword: string | null,
): void {
	const meta = getContextMeta(name);
	if (!meta) throw new Error(`Context "${name}" not found`);

	const encFile = contextEncryptedFile(name);
	const dbFile = contextDbFile(name);

	let plainBuf: Buffer | null = null;
	if (meta.encrypted) {
		if (fs.existsSync(encFile)) {
			plainBuf = decryptBuffer(fs.readFileSync(encFile), oldPassword || '');
		}
	} else if (fs.existsSync(dbFile)) {
		plainBuf = fs.readFileSync(dbFile);
	}

	if (newPassword) {
		const buf = plainBuf || Buffer.alloc(0);
		fs.writeFileSync(encFile, encryptBuffer(buf, newPassword), {mode: 0o600});
		if (fs.existsSync(dbFile)) fs.unlinkSync(dbFile);
		const walFile = dbFile + '-wal';
		const shmFile = dbFile + '-shm';
		if (fs.existsSync(walFile)) fs.unlinkSync(walFile);
		if (fs.existsSync(shmFile)) fs.unlinkSync(shmFile);
	} else {
		if (plainBuf) fs.writeFileSync(dbFile, plainBuf, {mode: 0o600});
		if (fs.existsSync(encFile)) fs.unlinkSync(encFile);
	}
}

export function importContext(opts: {
	name: string;
	sourcePath: string;
	sourcePassword?: string | null;
	newPassword?: string | null;
}): void {
	const {name, sourcePath} = opts;
	if (!fs.existsSync(sourcePath))
		throw new Error(`Source file not found: ${sourcePath}`);
	const buf = fs.readFileSync(sourcePath);
	const isEnc = buf.length >= 5 && buf.subarray(0, 5).toString('utf8') === 'CMGR1';
	let plain: Buffer;
	if (isEnc) {
		if (!opts.sourcePassword)
			throw new Error('Source file is encrypted; password required');
		plain = decryptBuffer(buf, opts.sourcePassword);
	} else {
		plain = buf;
	}

	fs.mkdirSync(contextDir(name), {recursive: true});
	if (opts.newPassword) {
		fs.writeFileSync(
			contextEncryptedFile(name),
			encryptBuffer(plain, opts.newPassword),
			{mode: 0o600},
		);
	} else {
		fs.writeFileSync(contextDbFile(name), plain, {mode: 0o600});
	}
}
