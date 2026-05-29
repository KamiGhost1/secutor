// Standalone keystore for client identities used to log in to hubs over mTLS.
// Layout: ~/.secutor/hubkeys/<entry>/{cert.pem, key.pem(.enc), meta.json}.
// Separate from contexts so a hub login can be a one-off file imported from
// MDM / corp PKI, with no fictional CA relationships in a context's DB.

import fs from 'fs';
import path from 'path';
import {rootDir, ensureRoot} from './paths.js';
import {encryptBuffer, decryptBuffer} from './crypto.js';

const SUBDIR = 'hubkeys';

export type HubKeystoreEntryMeta = {
	name: string;
	createdAt: string;
	encrypted: boolean;
	/** SHA-256 of the cert DER, hex. */
	fingerprint: string;
};

function dirRoot(): string {
	return path.join(rootDir(), SUBDIR);
}

function entryDir(name: string): string {
	return path.join(dirRoot(), name);
}

function metaPath(name: string): string {
	return path.join(entryDir(name), 'meta.json');
}

function certPath(name: string): string {
	return path.join(entryDir(name), 'cert.pem');
}

function keyPathFor(name: string, encrypted: boolean): string {
	return path.join(entryDir(name), encrypted ? 'key.pem.enc' : 'key.pem');
}

export function listEntries(): HubKeystoreEntryMeta[] {
	try {
		const items = fs.readdirSync(dirRoot(), {withFileTypes: true});
		const out: HubKeystoreEntryMeta[] = [];
		for (const it of items) {
			if (!it.isDirectory()) continue;
			try {
				const m = JSON.parse(fs.readFileSync(metaPath(it.name), 'utf8')) as HubKeystoreEntryMeta;
				out.push(m);
			} catch {
				/* skip broken entries */
			}
		}
		return out.sort((a, b) => a.name.localeCompare(b.name));
	} catch {
		return [];
	}
}

export function getEntryMeta(name: string): HubKeystoreEntryMeta | null {
	try {
		return JSON.parse(fs.readFileSync(metaPath(name), 'utf8')) as HubKeystoreEntryMeta;
	} catch {
		return null;
	}
}

export function readCertPem(name: string): string {
	return fs.readFileSync(certPath(name), 'utf8');
}

/**
 * Returns the unencrypted PKCS#8 PEM for the entry's key, decrypting on the
 * fly if necessary. Throws if encrypted and password is wrong/missing.
 */
export function readKeyPem(name: string, password?: string | null): string {
	const meta = getEntryMeta(name);
	if (!meta) throw new Error(`Hub keystore entry "${name}" not found`);
	if (!meta.encrypted) {
		return fs.readFileSync(keyPathFor(name, false), 'utf8');
	}
	if (!password) throw new Error(`Hub keystore entry "${name}" is encrypted`);
	const blob = fs.readFileSync(keyPathFor(name, true));
	const plain = decryptBuffer(blob, password);
	return plain.toString('utf8');
}

export function saveEntry(opts: {
	name: string;
	certPem: string;
	keyPem: string;
	encryptWith?: string | null;
	fingerprint: string;
}): HubKeystoreEntryMeta {
	if (!/^[a-zA-Z0-9._-]+$/.test(opts.name)) {
		throw new Error('Entry name must use letters/digits/._-');
	}
	ensureRoot();
	fs.mkdirSync(entryDir(opts.name), {recursive: true, mode: 0o700});
	fs.writeFileSync(certPath(opts.name), opts.certPem, {mode: 0o600});
	if (opts.encryptWith) {
		const enc = encryptBuffer(Buffer.from(opts.keyPem, 'utf8'), opts.encryptWith);
		fs.writeFileSync(keyPathFor(opts.name, true), enc, {mode: 0o600});
	} else {
		fs.writeFileSync(keyPathFor(opts.name, false), opts.keyPem, {mode: 0o600});
	}
	const meta: HubKeystoreEntryMeta = {
		name: opts.name,
		createdAt: new Date().toISOString(),
		encrypted: !!opts.encryptWith,
		fingerprint: opts.fingerprint,
	};
	fs.writeFileSync(metaPath(opts.name), JSON.stringify(meta, null, 2), {mode: 0o600});
	return meta;
}

export function deleteEntry(name: string): void {
	try {
		fs.rmSync(entryDir(name), {recursive: true, force: true});
	} catch {
		/* nothing to do */
	}
}
