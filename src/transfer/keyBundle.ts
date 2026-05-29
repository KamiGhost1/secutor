// Key bundle (.skb) — portable container for moving certificate/SSH/profile
// material between secutor contexts.
//
// Wire layout
// -----------
// Plain bundle:
//   bytes  0..9   magic         "SECUTOR_KB"
//   byte   10     variant       'P' (0x50) plain
//   byte   11     format ver    0x01
//   bytes  12..15 manifest len  uint32 big-endian
//   bytes  16..   manifest      UTF-8 JSON
//   trailing      payload       opaque bytes (DER blob for P12, otherwise empty)
//
// Encrypted bundle (password-derived AES-256-GCM envelope over plain body):
//   bytes  0..9   magic         "SECUTOR_KB"
//   byte   10     variant       'E' (0x45) encrypted
//   byte   11     format ver    0x01
//   byte   12     scrypt logN   (e.g. 17 → N=2^17). Stored as byte to allow
//                               low-cost params in tests.
//   byte   13     scrypt r
//   byte   14     scrypt p
//   byte   15     reserved      0x00
//   bytes  16..31 salt          16 bytes
//   bytes  32..43 iv            12 bytes (AES-GCM nonce)
//   bytes  44..   ciphertext    ENC(plain-body) — plain-body is the same
//                               byte sequence that a plain bundle would
//                               carry from offset 12 onward
//   trailing 16   GCM auth tag
//
// Why this layout
// ---------------
// * A single file means an operator can rsync / pbcopy / paste / store-in-S3
//   one artifact instead of tracking cert+key+meta separately.
// * The plain body and the encrypted body carry the same bytes, so the
//   decryptor produces exactly what the parser expects — no parallel code paths.
// * Private keys travel as they live in storage (possibly encrypted PKCS#8);
//   the bundle never has to know their passphrase, so cross-machine transfer
//   does not require the receiver to know more than they already would for
//   normal use.
// * scrypt parameters are inlined so a future format bump can raise the
//   defaults without breaking older files.

import crypto from 'crypto';
import {VERSION} from '../version.js';

export const BUNDLE_MAGIC = Buffer.from('SECUTOR_KB', 'utf8'); // 10 bytes
export const BUNDLE_VERSION = 1;
export const VARIANT_PLAIN = 0x50; // 'P'
export const VARIANT_ENCRYPTED = 0x45; // 'E'

const HEADER_LEN = 12;
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const ENC_PREFIX_LEN = 16; // header(12) + scrypt(3) + reserved(1)
// Encrypted payload starts at ENC_PREFIX_LEN + SALT_LEN + IV_LEN = 44.

export type BundleKind = 'ca' | 'leaf' | 'ssh' | 'profile' | 'subtree';

export type BundleItemRole =
	| 'cert'
	| 'key'
	| 'parent'         // CA cert in a subtree, above the root item
	| 'child'          // descendant cert+key pair in a subtree
	| 'ssh-pub'
	| 'ssh-priv'
	| 'p12';

export type BundleEncoding = 'pem' | 'der' | 'openssh-v1' | 'pkcs12' | 'json';

export type BundleItem = {
	/** What this blob represents inside the bundle. */
	role: BundleItemRole;
	encoding: BundleEncoding;
	/** True if a private-key blob is itself encrypted (encrypted PKCS#8 / OpenSSH passphrase). */
	encrypted?: boolean;
	/** base64 of the bytes. For text formats (PEM, OpenSSH) this is base64 of UTF-8 bytes. */
	data: string;
	/** Optional metadata for subtree children so we can reconstruct issuer relationships. */
	meta?: {
		name?: string;
		commonName?: string | null;
		organization?: string | null;
		type?: 'ca' | 'server' | 'client';
		fingerprint?: string;
		issuerFingerprint?: string | null;
		san?: string[] | null;
		notBefore?: string;
		notAfter?: string;
		serial?: string;
		comment?: string | null;
		algorithm?: string;
		friendlyName?: string | null;
	};
};

export type BundleManifest = {
	v: 1;
	kind: BundleKind;
	/** Display name suggested by the exporter — receiver may override on conflict. */
	name: string;
	exportedAt: string;
	exportedFrom: {
		contextName: string;
		secutorVersion: string;
	};
	/** SHA-256 of the primary cert DER (or SSH pubkey wire bytes) when applicable. */
	fingerprint?: string;
	/** Cross-reference hints. issuerFingerprint helps the importer relink chains. */
	links?: {
		issuerFingerprint?: string | null;
		subtreeFingerprints?: string[];
	};
	items: BundleItem[];
};

export type EncryptionParams = {
	/** scrypt cost: N = 2^logN. Default 17 (≈100 MiB, ~250 ms on a modern laptop). */
	logN?: number;
	r?: number;
	p?: number;
};

/* ─────────────────── serialization ─────────────────── */

/**
 * Build a plain (unencrypted) bundle file. Returns the raw bytes ready to
 * write to disk.
 */
export function buildPlainBundle(manifest: BundleManifest, payload?: Buffer): Buffer {
	const body = encodeBody(manifest, payload ?? Buffer.alloc(0));
	const header = Buffer.alloc(HEADER_LEN);
	BUNDLE_MAGIC.copy(header, 0);
	header[10] = VARIANT_PLAIN;
	header[11] = BUNDLE_VERSION;
	return Buffer.concat([header, body]);
}

/**
 * Build an encrypted bundle. The same `(manifest, payload)` round-trips to
 * the same bytes a plain bundle would carry, then the AES-256-GCM envelope
 * is laid over it.
 */
export function buildEncryptedBundle(
	manifest: BundleManifest,
	payload: Buffer | undefined,
	password: string,
	params?: EncryptionParams,
): Buffer {
	if (!password) throw new Error('encryption password is required');
	const logN = params?.logN ?? 17;
	const r = params?.r ?? 8;
	const p = params?.p ?? 1;
	assertScryptParams(logN, r, p);

	const salt = crypto.randomBytes(SALT_LEN);
	const iv = crypto.randomBytes(IV_LEN);
	const key = deriveBundleKey(password, salt, logN, r, p);
	const body = encodeBody(manifest, payload ?? Buffer.alloc(0));

	const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
	const ct = Buffer.concat([cipher.update(body), cipher.final()]);
	const tag = cipher.getAuthTag();

	const prefix = Buffer.alloc(ENC_PREFIX_LEN);
	BUNDLE_MAGIC.copy(prefix, 0);
	prefix[10] = VARIANT_ENCRYPTED;
	prefix[11] = BUNDLE_VERSION;
	prefix[12] = logN;
	prefix[13] = r;
	prefix[14] = p;
	prefix[15] = 0; // reserved

	return Buffer.concat([prefix, salt, iv, ct, tag]);
}

/* ─────────────────── parsing ─────────────────── */

export type ParsedBundle = {
	manifest: BundleManifest;
	payload: Buffer;
	encrypted: boolean;
};

export function isBundleFile(buf: Buffer): boolean {
	return (
		buf.length >= HEADER_LEN &&
		buf.subarray(0, BUNDLE_MAGIC.length).equals(BUNDLE_MAGIC)
	);
}

export function bundleVariant(buf: Buffer): 'plain' | 'encrypted' | null {
	if (!isBundleFile(buf)) return null;
	const v = buf[10];
	if (v === VARIANT_PLAIN) return 'plain';
	if (v === VARIANT_ENCRYPTED) return 'encrypted';
	return null;
}

export function parseBundle(buf: Buffer, password?: string): ParsedBundle {
	if (!isBundleFile(buf)) {
		throw new Error('not a secutor key bundle (bad magic)');
	}
	const variant = buf[10];
	const version = buf[11];
	if (version !== BUNDLE_VERSION) {
		throw new Error(`unsupported bundle version: ${version}`);
	}

	if (variant === VARIANT_PLAIN) {
		const body = buf.subarray(HEADER_LEN);
		const {manifest, payload} = decodeBody(body);
		return {manifest, payload, encrypted: false};
	}

	if (variant === VARIANT_ENCRYPTED) {
		if (!password) {
			throw new Error('bundle is encrypted; password required');
		}
		const logN = buf[12]!;
		const r = buf[13]!;
		const p = buf[14]!;
		assertScryptParams(logN, r, p);

		const salt = buf.subarray(ENC_PREFIX_LEN, ENC_PREFIX_LEN + SALT_LEN);
		const iv = buf.subarray(
			ENC_PREFIX_LEN + SALT_LEN,
			ENC_PREFIX_LEN + SALT_LEN + IV_LEN,
		);
		const tagOff = buf.length - TAG_LEN;
		if (tagOff <= ENC_PREFIX_LEN + SALT_LEN + IV_LEN) {
			throw new Error('encrypted bundle too short');
		}
		const ct = buf.subarray(ENC_PREFIX_LEN + SALT_LEN + IV_LEN, tagOff);
		const tag = buf.subarray(tagOff);

		const key = deriveBundleKey(password, Buffer.from(salt), logN, r, p);
		const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
		decipher.setAuthTag(tag);
		let body: Buffer;
		try {
			body = Buffer.concat([decipher.update(ct), decipher.final()]);
		} catch {
			throw new Error('wrong password or corrupted bundle');
		}
		const {manifest, payload} = decodeBody(body);
		return {manifest, payload, encrypted: true};
	}

	throw new Error(`unknown bundle variant byte: 0x${variant.toString(16)}`);
}

/* ─────────────────── manifest helpers ─────────────────── */

export function newManifest(
	kind: BundleKind,
	name: string,
	contextName: string,
	items: BundleItem[],
	extras?: {fingerprint?: string; links?: BundleManifest['links']},
): BundleManifest {
	return {
		v: 1,
		kind,
		name,
		exportedAt: new Date().toISOString(),
		exportedFrom: {contextName, secutorVersion: VERSION},
		fingerprint: extras?.fingerprint,
		links: extras?.links,
		items,
	};
}

/** Encode UTF-8 text content (PEM, OpenSSH wire format) as a base64 BundleItem.data. */
export function textToData(s: string): string {
	return Buffer.from(s, 'utf8').toString('base64');
}
export function dataToText(s: string): string {
	return Buffer.from(s, 'base64').toString('utf8');
}
export function bytesToData(b: Buffer): string {
	return b.toString('base64');
}
export function dataToBytes(s: string): Buffer {
	return Buffer.from(s, 'base64');
}

/* ─────────────────── internals ─────────────────── */

function encodeBody(manifest: BundleManifest, payload: Buffer): Buffer {
	const json = Buffer.from(JSON.stringify(manifest), 'utf8');
	const lenBuf = Buffer.alloc(4);
	lenBuf.writeUInt32BE(json.length, 0);
	return Buffer.concat([lenBuf, json, payload]);
}

function decodeBody(body: Buffer): {manifest: BundleManifest; payload: Buffer} {
	if (body.length < 4) throw new Error('bundle body too short');
	const len = body.readUInt32BE(0);
	if (len > body.length - 4) {
		throw new Error('bundle manifest length out of range');
	}
	const json = body.subarray(4, 4 + len).toString('utf8');
	const payload = Buffer.from(body.subarray(4 + len));
	let manifest: BundleManifest;
	try {
		manifest = JSON.parse(json) as BundleManifest;
	} catch (err: any) {
		throw new Error(`bundle manifest JSON invalid: ${err?.message ?? err}`);
	}
	if (!manifest || manifest.v !== 1 || !manifest.kind || !Array.isArray(manifest.items)) {
		throw new Error('bundle manifest does not match v1 schema');
	}
	return {manifest, payload};
}

function deriveBundleKey(
	password: string,
	salt: Buffer,
	logN: number,
	r: number,
	p: number,
): Buffer {
	const N = 1 << logN;
	const maxmem = 256 * 1024 * 1024; // 256 MiB upper bound; covers logN up to 22 at r=8
	return crypto.scryptSync(password, salt, 32, {N, r, p, maxmem});
}

function assertScryptParams(logN: number, r: number, p: number): void {
	if (logN < 10 || logN > 24) throw new Error(`scrypt logN out of range: ${logN}`);
	if (r < 1 || r > 32) throw new Error(`scrypt r out of range: ${r}`);
	if (p < 1 || p > 16) throw new Error(`scrypt p out of range: ${p}`);
}
