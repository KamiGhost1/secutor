// In-memory CA rotation lifecycle (stage → promote → rollback).
//
// Design choice: staged material lives only in process memory. After a
// restart, an operator must re-stage. Rationale: stage→promote is a manual
// minutes-long window where the operator is at the terminal anyway, so the
// loss of staged-on-restart is preferable to the operational risk of
// persisting half-rotated key material on disk in a wrong-permissions
// directory after a crash.
//
// The 'active' `CaMaterial` object is shared by reference across the whole
// server (routes.ts, admin/ca.ts, signer call sites). Promote replaces its
// fields in-place (Object.assign), so every read after that point sees the
// new key without anyone having to re-resolve a handle.

import crypto from 'crypto';
import type {CaMaterial} from './contextLoader.js';

export type StagedCa = {
	certPem: string;
	keyPem: string; // plaintext PKCS#8 (already-decrypted)
	chainPem: string;
	rootCertPem: string;
	chainDepth: number;
	notAfter: Date;
	serial: string;
	commonName: string;
	stagedAt: Date;
	fingerprint: string; // SHA-256 hex of cert DER
	keyAlgorithm: string;
};

type Snapshot = Omit<StagedCa, 'stagedAt'> & {promotedAt: Date};

export class CaStore {
	private staged: StagedCa | null = null;
	private previous: Snapshot | null = null;
	private rollbackWindowMs: number;

	constructor(private active: CaMaterial, opts?: {rollbackWindowHours?: number}) {
		this.rollbackWindowMs = (opts?.rollbackWindowHours ?? 24) * 3600_000;
	}

	current(): CaMaterial {
		return this.active;
	}

	currentFingerprint(): string {
		return fingerprintOfPem(this.active.certPem);
	}

	getStaged(): StagedCa | null {
		return this.staged;
	}

	hasRollback(): boolean {
		if (!this.previous) return false;
		return Date.now() - this.previous.promotedAt.getTime() < this.rollbackWindowMs;
	}

	getPrevious(): Snapshot | null {
		return this.previous;
	}

	/**
	 * Validate + remember new CA material as a candidate. Validation requires
	 * (1) key parses, (2) key matches cert (sign+verify a nonce), (3) cert
	 * chains to the same root as currently active, (4) cert is different
	 * from active and has reasonable validity remaining.
	 */
	stage(input: {
		certPem: string;
		keyPem: string;
		chainPem: string;
		name?: string;
	}): StagedCa {
		// (1) key parses
		let keyObj: crypto.KeyObject;
		try {
			keyObj = crypto.createPrivateKey(input.keyPem);
		} catch (e: any) {
			throw new StageError('bad-key', `key failed to parse: ${e?.message ?? e}`);
		}

		// (2) key↔cert sanity: sign+verify a nonce with both halves
		const cert = new crypto.X509Certificate(input.certPem);
		const pubFromCert = cert.publicKey;
		const nonce = crypto.randomBytes(32);
		const hash = signHashFor(keyAlgLabel(keyObj));
		let sig: Buffer;
		try {
			sig = sign(keyObj, hash, nonce);
		} catch (e: any) {
			throw new StageError('key-cert-mismatch', `key cannot sign: ${e?.message ?? e}`);
		}
		try {
			if (!verify(pubFromCert, hash, nonce, sig)) {
				throw new StageError('key-cert-mismatch', `cert public key does not pair with private key`);
			}
		} catch (e) {
			if (e instanceof StageError) throw e;
			throw new StageError('key-cert-mismatch', `verify threw: ${(e as any)?.message ?? e}`);
		}

		// (3) chain to the same root as currently active
		const incomingRoot = lastInChain(input.chainPem) ?? input.certPem;
		const activeRoot = this.active.rootCertPem;
		if (normalizePem(incomingRoot) !== normalizePem(activeRoot)) {
			throw new StageError(
				'root-mismatch',
				'staged material must chain to the same root as the currently active CA',
			);
		}

		// (4) fresh? has at least 30 days left?
		const incomingFp = fingerprintOfPem(input.certPem);
		if (incomingFp === fingerprintOfPem(this.active.certPem)) {
			throw new StageError('same-as-active', 'staged cert is identical to the active one');
		}
		const notAfter = new Date(cert.validTo);
		if (notAfter.getTime() - Date.now() < 30 * 86400_000) {
			throw new StageError('expires-too-soon', 'staged cert has less than 30 days remaining');
		}

		const chainDepth = countChainCerts(input.chainPem) + 1;
		this.staged = {
			certPem: input.certPem,
			keyPem: input.keyPem,
			chainPem: input.chainPem,
			rootCertPem: incomingRoot,
			chainDepth,
			notAfter,
			serial: cert.serialNumber,
			commonName: cert.subject,
			stagedAt: new Date(),
			fingerprint: incomingFp,
			keyAlgorithm: keyAlgLabel(keyObj),
		};
		return this.staged;
	}

	/** Discard the current staged candidate, if any. */
	discardStaged(): void {
		this.staged = null;
	}

	/**
	 * Atomically activate the staged material. Stores the prior state as
	 * `previous` (available to `rollback` for `rollbackWindowHours`). Throws
	 * StageError('no-staged') if nothing is staged.
	 */
	promote(): {previousFingerprint: string; newFingerprint: string} {
		if (!this.staged) throw new StageError('no-staged', 'nothing to promote');
		const prevFp = fingerprintOfPem(this.active.certPem);
		this.previous = {
			certPem: this.active.certPem,
			keyPem: this.active.keyPem,
			chainPem: this.active.chainPem,
			rootCertPem: this.active.rootCertPem,
			chainDepth: this.active.chainDepth,
			notAfter: this.active.notAfter,
			serial: this.active.serial,
			commonName: this.active.commonName,
			fingerprint: prevFp,
			keyAlgorithm: keyAlgLabel(crypto.createPrivateKey(this.active.keyPem)),
			promotedAt: new Date(),
		};
		// In-place replacement — every existing reader of ctx.ca sees the new
		// material on its very next field read.
		Object.assign(this.active, {
			certPem: this.staged.certPem,
			keyPem: this.staged.keyPem,
			chainPem: this.staged.chainPem,
			rootCertPem: this.staged.rootCertPem,
			chainDepth: this.staged.chainDepth,
			notAfter: this.staged.notAfter,
			serial: this.staged.serial,
			commonName: this.staged.commonName,
		});
		const newFp = this.staged.fingerprint;
		this.staged = null;
		return {previousFingerprint: prevFp, newFingerprint: newFp};
	}

	/**
	 * Restore the previously-active material. Available only within the
	 * configured rollback window after promote.
	 */
	rollback(): {restoredFingerprint: string} {
		if (!this.previous) throw new StageError('no-previous', 'no rollback target');
		if (!this.hasRollback()) {
			this.previous = null;
			throw new StageError('rollback-window-elapsed', 'rollback window has elapsed');
		}
		Object.assign(this.active, {
			certPem: this.previous.certPem,
			keyPem: this.previous.keyPem,
			chainPem: this.previous.chainPem,
			rootCertPem: this.previous.rootCertPem,
			chainDepth: this.previous.chainDepth,
			notAfter: this.previous.notAfter,
			serial: this.previous.serial,
			commonName: this.previous.commonName,
		});
		const fp = this.previous.fingerprint;
		this.previous = null;
		return {restoredFingerprint: fp};
	}
}

export class StageError extends Error {
	constructor(public code: string, message: string) {
		super(message);
		this.name = 'StageError';
	}
}

/* ─────────── helpers ─────────── */

export function fingerprintOfPem(pem: string): string {
	const body = pem.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----/g, '').replace(/\s+/g, '');
	return crypto.createHash('sha256').update(Buffer.from(body, 'base64')).digest('hex');
}

function lastInChain(chainPem: string): string | null {
	if (!chainPem) return null;
	const blocks = chainPem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
	return blocks?.[blocks.length - 1] ?? null;
}

function countChainCerts(chainPem: string): number {
	if (!chainPem) return 0;
	return (chainPem.match(/-----BEGIN CERTIFICATE-----/g) ?? []).length;
}

function normalizePem(pem: string): string {
	return pem.replace(/\s+/g, '');
}

function keyAlgLabel(key: crypto.KeyObject): string {
	const t = key.asymmetricKeyType;
	if (t === 'rsa' || t === 'rsa-pss') {
		const bits = (key.asymmetricKeyDetails as any)?.modulusLength ?? 2048;
		if (bits >= 4096) return 'rsa-4096';
		if (bits >= 3072) return 'rsa-3072';
		return 'rsa-2048';
	}
	if (t === 'ec') {
		const curve = (key.asymmetricKeyDetails as any)?.namedCurve;
		if (curve === 'P-384' || curve === 'secp384r1') return 'ecdsa-p384';
		return 'ecdsa-p256';
	}
	if (t === 'ed25519') return 'ed25519';
	throw new Error(`unsupported key type ${t}`);
}

function signHashFor(alg: string): string | null {
	if (alg === 'ed25519') return null;
	if (alg === 'ecdsa-p384') return 'sha384';
	return 'sha256';
}

function sign(key: crypto.KeyObject, hash: string | null, msg: Buffer): Buffer {
	const alg = keyAlgLabel(key);
	if (alg.startsWith('rsa')) {
		return crypto.sign(hash, msg, {
			key,
			padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
			saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
		} as any);
	}
	return crypto.sign(hash, msg, key);
}

function verify(pub: crypto.KeyObject, hash: string | null, msg: Buffer, sig: Buffer): boolean {
	const alg = keyAlgLabel(pub);
	if (alg.startsWith('rsa')) {
		return crypto.verify(hash, msg, {
			key: pub,
			padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
			saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
		} as any, sig);
	}
	return crypto.verify(hash, msg, pub, sig);
}
