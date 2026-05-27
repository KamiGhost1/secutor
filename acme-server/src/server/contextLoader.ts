// Loads a secutor context (encrypted or plain), extracts the CA certificate
// + private key, and keeps them in memory. Read-only: never writes back to the
// context directory.
//
// The on-disk format is owned by ../../src/storage/* in the main repo. We
// re-implement just the read path to keep this package self-contained for
// Docker builds.

import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import Database from 'better-sqlite3';

const MAGIC = Buffer.from('CMGR1', 'utf8');
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;

function deriveKey(password: string, salt: Buffer, iters: number): Buffer {
	return crypto.pbkdf2Sync(password, salt, iters, KEY_LEN, 'sha256');
}

function decryptBuffer(blob: Buffer, password: string): Buffer {
	if (!blob.subarray(0, MAGIC.length).equals(MAGIC)) {
		throw new Error('Context file: bad magic (not a secutor encrypted store)');
	}
	let off = MAGIC.length;
	const iters = blob.readUInt32BE(off);
	off += 4;
	const salt = blob.subarray(off, off + SALT_LEN);
	off += SALT_LEN;
	const iv = blob.subarray(off, off + IV_LEN);
	off += IV_LEN;
	const tag = blob.subarray(off, off + TAG_LEN);
	off += TAG_LEN;
	const enc = blob.subarray(off);
	const key = deriveKey(password, salt, iters);
	const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
	decipher.setAuthTag(tag);
	try {
		return Buffer.concat([decipher.update(enc), decipher.final()]);
	} catch {
		throw new Error('Context decryption failed: wrong password or corrupted file');
	}
}

export type CaMaterial = {
	name: string;
	commonName: string;
	/** The signing CA's own cert (PEM). */
	certPem: string;
	/** The signing CA's private key (plain PEM, already decrypted if needed). */
	keyPem: string;
	/**
	 * What goes into application/pem-certificate-chain after the issued leaf.
	 * Per RFC 8555 §7.4.2 conventions: signing CA + parents, EXCLUDING the root.
	 * Empty string if the signing CA is itself the root.
	 */
	chainPem: string;
	/** The root certificate (self-signed). Served from /ca.pem for trust distribution. */
	rootCertPem: string;
	/** Depth of the chain from signing CA up to (and including) root. 1 = signing CA is root. */
	chainDepth: number;
	notAfter: Date;
	serial: string;
};

type CertRow = {
	id: number;
	name: string;
	type: string;
	common_name: string;
	cert_pem: string;
	key_pem: string;
	not_after: string;
	serial: string;
	issuer_id: number | null;
};

function maybeDecryptKey(keyPem: string, password: string | null): string {
	// secutor encrypts via PKCS#8 / AES-256-CBC; node:crypto handles it natively.
	if (!/ENCRYPTED PRIVATE KEY/.test(keyPem)) return keyPem;
	if (!password) throw new Error('CA key is encrypted, no caKeyPasswordFile provided');
	const k = crypto.createPrivateKey({key: keyPem, passphrase: password});
	return k.export({type: 'pkcs8', format: 'pem'}) as string;
}

export function loadCa(opts: {
	contextDir: string;
	contextPassword: string | null;
	caCertName: string | null;
	caKeyPassword: string | null;
}): CaMaterial {
	const dir = opts.contextDir;
	if (!fs.existsSync(dir)) throw new Error(`Context dir not found: ${dir}`);

	const encFile = path.join(dir, 'store.enc');
	const plainFile = path.join(dir, 'store.db');

	let plainBuf: Buffer;
	if (fs.existsSync(encFile)) {
		if (!opts.contextPassword) throw new Error('Context is encrypted but no password file provided');
		plainBuf = decryptBuffer(fs.readFileSync(encFile), opts.contextPassword);
	} else if (fs.existsSync(plainFile)) {
		plainBuf = fs.readFileSync(plainFile);
	} else {
		throw new Error(`No store.enc or store.db in ${dir}`);
	}

	// Write plain SQLite to a tmpfile (memory if possible). We open read-only.
	const tmp = path.join(os.tmpdir(), `secutor-acme-${crypto.randomBytes(8).toString('hex')}.db`);
	fs.writeFileSync(tmp, plainBuf, {mode: 0o600});
	const db = new Database(tmp, {readonly: true, fileMustExist: true});
	try {
		const SELECT_COLS = `id, name, type, common_name, cert_pem, key_pem, not_after, serial, issuer_id`;
		let row: CertRow | undefined;
		if (opts.caCertName) {
			row = db
				.prepare(
					`SELECT ${SELECT_COLS} FROM certificates
					 WHERE type='ca' AND name = ? LIMIT 1`,
				)
				.get(opts.caCertName) as CertRow | undefined;
		} else {
			row = db
				.prepare(
					`SELECT ${SELECT_COLS} FROM certificates
					 WHERE type='ca' ORDER BY id LIMIT 1`,
				)
				.get() as CertRow | undefined;
		}
		if (!row) {
			throw new Error(
				`No CA certificate in context${opts.caCertName ? ` (name=${opts.caCertName})` : ''}`,
			);
		}
		if (!row.key_pem) {
			throw new Error(`CA "${row.name}" has no private key in the store`);
		}
		const keyPem = maybeDecryptKey(row.key_pem, opts.caKeyPassword);

		// Walk up the issuer chain. Per ACME RFC 8555 §7.4.2 conventions, the
		// chain returned alongside an issued cert contains the signing CA and
		// its intermediates but NOT the root. We collect both forms here.
		const lookupById = db.prepare(
			`SELECT ${SELECT_COLS} FROM certificates WHERE id = ? LIMIT 1`,
		);
		const ancestors: CertRow[] = [row];
		let cursor: CertRow | undefined = row;
		const seen = new Set<number>([row.id]);
		while (cursor && cursor.issuer_id != null && !seen.has(cursor.issuer_id)) {
			const parent = lookupById.get(cursor.issuer_id) as CertRow | undefined;
			if (!parent) break;
			seen.add(parent.id);
			ancestors.push(parent);
			cursor = parent;
		}
		// `ancestors` now: [signingCA, parent, ..., root]. Root is the last one
		// whose issuer_id is null. If the signing CA itself is the root, the
		// array has exactly one element.
		const rootCert = ancestors[ancestors.length - 1]!;
		const intermediatesAndSigner = ancestors.slice(0, ancestors.length - 1);
		const chainPem = intermediatesAndSigner.map(c => c.cert_pem.trim()).join('\n');

		return {
			name: row.name,
			commonName: row.common_name,
			certPem: row.cert_pem,
			keyPem,
			chainPem,
			rootCertPem: rootCert.cert_pem,
			chainDepth: ancestors.length,
			notAfter: new Date(row.not_after),
			serial: row.serial,
		};
	} finally {
		db.close();
		try {
			fs.unlinkSync(tmp);
		} catch {}
	}
}
