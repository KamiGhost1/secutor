// Resolves a HubClientAuth handle to the actual (cert_pem, key_pem) the
// mTLS handshake needs. Three sources, one type — callers don't have to know
// which one fired.
//
// Password handling: each resolver can either be given a password up-front
// (`opts.keyPassword`) or it will throw `EncryptedKeyError`, and the caller
// (TUI) prompts the user. We never persist passwords.

import fs from 'fs';
import {certRepo} from '../storage/repos.js';
import {decryptPrivateKey, isEncryptedKey} from '../certs/keys.js';
import {readCertPem as keystoreReadCert, readKeyPem as keystoreReadKey} from '../storage/hubKeystore.js';
import type {HubClientAuth} from '../storage/hubStore.js';

export type ResolvedIdentity = {
	certPem: string;
	/** Already-decrypted PKCS#8 PEM (TLS only accepts plaintext keys). */
	keyPem: string;
	/** Where it came from, for error messages and audit. */
	source: HubClientAuth['kind'];
};

export class EncryptedKeyError extends Error {
	constructor(public source: HubClientAuth['kind'], message?: string) {
		super(message ?? `private key for ${source} is encrypted`);
		this.name = 'EncryptedKeyError';
	}
}

export function resolveIdentity(
	auth: HubClientAuth,
	opts?: {keyPassword?: string | null},
): ResolvedIdentity {
	const pw = opts?.keyPassword ?? null;
	if (auth.kind === 'context') {
		const row = certRepo.findByName(auth.certName);
		if (!row) throw new Error(`No cert named "${auth.certName}" in current context`);
		if (!row.key_pem) throw new Error(`Cert "${auth.certName}" has no private key`);
		const needsPw = isEncryptedKey(row.key_pem);
		if (needsPw && !pw) throw new EncryptedKeyError('context');
		const keyPem = needsPw ? decryptPrivateKey(row.key_pem, pw) : row.key_pem;
		return {certPem: row.cert_pem, keyPem, source: 'context'};
	}
	if (auth.kind === 'file') {
		const certPem = fs.readFileSync(auth.certPath, 'utf8');
		const rawKey = fs.readFileSync(auth.keyPath, 'utf8');
		const needsPw = isEncryptedKey(rawKey);
		if (needsPw && !pw) throw new EncryptedKeyError('file');
		const keyPem = needsPw ? decryptPrivateKey(rawKey, pw) : rawKey;
		return {certPem, keyPem, source: 'file'};
	}
	// keystore
	const certPem = keystoreReadCert(auth.keystoreEntry);
	let keyPem: string;
	try {
		keyPem = keystoreReadKey(auth.keystoreEntry, pw);
	} catch (e: any) {
		if (/encrypted/i.test(e?.message ?? '')) throw new EncryptedKeyError('keystore', e.message);
		throw e;
	}
	if (isEncryptedKey(keyPem)) {
		// keystore stored it as encrypted PKCS#8 (independent of the AES envelope).
		if (!pw) throw new EncryptedKeyError('keystore');
		keyPem = decryptPrivateKey(keyPem, pw);
	}
	return {certPem, keyPem, source: 'keystore'};
}
