// Build a DER-encoded CRLv2 (RFC 5280 §5) signed by the CA. We don't depend on
// node-forge here — forge can't handle non-RSA CAs cleanly. Instead we encode
// TBSCertList ASN.1 manually and sign with node:crypto.

import crypto from 'crypto';
import type {Repos} from './repos.js';
import type {CaMaterial} from './contextLoader.js';

// ---- minimal DER encoder ----

function encLen(n: number): Buffer {
	if (n < 0x80) return Buffer.from([n]);
	const bytes: number[] = [];
	let x = n;
	while (x > 0) {
		bytes.unshift(x & 0xff);
		x >>>= 8;
	}
	return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function tag(t: number, body: Buffer): Buffer {
	return Buffer.concat([Buffer.from([t]), encLen(body.length), body]);
}
function seq(...children: Buffer[]): Buffer {
	return tag(0x30, Buffer.concat(children));
}
function oid(s: string): Buffer {
	const parts = s.split('.').map(Number);
	const out: number[] = [];
	out.push(parts[0]! * 40 + parts[1]!);
	for (let i = 2; i < parts.length; i++) {
		let v = parts[i]!;
		const stack: number[] = [];
		stack.unshift(v & 0x7f);
		v >>>= 7;
		while (v > 0) {
			stack.unshift((v & 0x7f) | 0x80);
			v >>>= 7;
		}
		for (const b of stack) out.push(b);
	}
	return tag(0x06, Buffer.from(out));
}
function integerFromHex(hex: string): Buffer {
	let h = hex;
	if (h.length % 2 !== 0) h = '0' + h;
	let bytes = Buffer.from(h, 'hex');
	if ((bytes[0]! & 0x80) !== 0) bytes = Buffer.concat([Buffer.from([0]), bytes]);
	return tag(0x02, bytes);
}
function integerSmall(n: number): Buffer {
	return tag(0x02, Buffer.from([n]));
}
function utcOrGeneralized(d: Date): Buffer {
	const y = d.getUTCFullYear();
	const pad = (n: number) => String(n).padStart(2, '0');
	const dt = `${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}Z`;
	if (y >= 1950 && y < 2050) {
		return tag(0x17, Buffer.from(`${pad(y % 100)}${dt}`, 'ascii'));
	}
	return tag(0x18, Buffer.from(`${y}${dt}`, 'ascii'));
}

// ---- CA helpers ----

function caKeyAlg(caKeyPem: string): {oid: string; hash: string | null; null: boolean} {
	const k = crypto.createPrivateKey(caKeyPem);
	switch (k.asymmetricKeyType) {
		case 'rsa':
		case 'rsa-pss':
			return {oid: '1.2.840.113549.1.1.11', hash: 'sha256', null: true};
		case 'ec': {
			const c = (k.asymmetricKeyDetails as any)?.namedCurve;
			if (c === 'P-384' || c === 'secp384r1')
				return {oid: '1.2.840.10045.4.3.3', hash: 'sha384', null: false};
			return {oid: '1.2.840.10045.4.3.2', hash: 'sha256', null: false};
		}
		case 'ed25519':
			return {oid: '1.3.101.112', hash: null, null: false};
		default:
			throw new Error(`Unsupported CA key type: ${k.asymmetricKeyType}`);
	}
}

function sigAlgIdDer(a: {oid: string; null: boolean}): Buffer {
	const oidB = oid(a.oid);
	if (a.null) {
		return seq(oidB, Buffer.from([0x05, 0x00]));
	}
	return seq(oidB);
}

/**
 * Extract the issuer Name DER bytes by reading the CA cert's TBSCertificate
 * (subject Name == issuer Name for a self-signed root; for intermediates we
 * want the *subject* of the signing CA itself).
 */
function caSubjectDer(caCertPem: string): Buffer {
	const body = caCertPem
		.replace(/-----BEGIN [^-]+-----/g, '')
		.replace(/-----END [^-]+-----/g, '')
		.replace(/\s+/g, '');
	const der = Buffer.from(body, 'base64');
	let p = 0;
	if (der[p++] !== 0x30) throw new Error('cert: SEQUENCE expected');
	const outerLen = readLen(der, p);
	p += outerLen.headerLen;
	if (der[p++] !== 0x30) throw new Error('cert: tbs SEQUENCE expected');
	const tbsLen = readLen(der, p);
	p += tbsLen.headerLen;
	// optional [0] version, then serial, then sigAlg, then issuer, then validity, then SUBJECT.
	// We need to walk to subject.
	// Read first child to detect [0] version.
	let first = p;
	if (der[first] === 0xa0) {
		const l = readLen(der, first + 1);
		first = first + 1 + l.headerLen + l.length;
	}
	// at first: serial INTEGER
	const serial = skip(der, first);
	// sigAlg SEQUENCE
	const sigAlg = skip(der, serial);
	// issuer Name SEQUENCE
	const issuer = skip(der, sigAlg);
	// validity SEQUENCE
	const validity = skip(der, issuer);
	// subject Name SEQUENCE — capture it
	const subjStart = validity;
	const subjLen = readLen(der, subjStart + 1);
	const subjEnd = subjStart + 1 + subjLen.headerLen + subjLen.length;
	return Buffer.from(der.subarray(subjStart, subjEnd));
}
function readLen(b: Buffer, off: number): {length: number; headerLen: number} {
	const first = b[off]!;
	if (first < 0x80) return {length: first, headerLen: 1};
	const n = first & 0x7f;
	let len = 0;
	for (let i = 1; i <= n; i++) len = (len << 8) | b[off + i]!;
	return {length: len, headerLen: 1 + n};
}
function skip(b: Buffer, off: number): number {
	const l = readLen(b, off + 1);
	return off + 1 + l.headerLen + l.length;
}

// ---- main builder ----

export type CrlOptions = {
	validityDays?: number;
};

export function buildCrl(repos: Repos, ca: CaMaterial, options: CrlOptions = {}): Buffer {
	const validityDays = options.validityDays ?? 7;
	const alg = caKeyAlg(ca.keyPem);
	const algDer = sigAlgIdDer(alg);
	const issuerDer = caSubjectDer(ca.certPem);

	const revoked = repos.db
		.prepare(
			`SELECT serial_hex, revoked_at, revocation_reason FROM certificates
			 WHERE revoked = 1 AND not_after > ?`,
		)
		.all(new Date(Date.now() - 86400 * 1000).toISOString()) as Array<{
		serial_hex: string;
		revoked_at: string | null;
		revocation_reason: number | null;
	}>;

	const now = new Date();
	const next = new Date(now.getTime() + validityDays * 86400 * 1000);

	const tbsChildren: Buffer[] = [
		integerSmall(1), // version v2
		algDer,
		issuerDer,
		utcOrGeneralized(now),
		utcOrGeneralized(next),
	];

	if (revoked.length) {
		const revokedSeq = revoked.map(r => {
			const ts = r.revoked_at ? new Date(r.revoked_at) : now;
			return seq(integerFromHex(r.serial_hex), utcOrGeneralized(ts));
		});
		tbsChildren.push(seq(...revokedSeq));
	}

	const tbs = seq(...tbsChildren);

	const signKey = crypto.createPrivateKey(ca.keyPem);
	const signature = alg.hash
		? crypto.sign(alg.hash, tbs, signKey)
		: crypto.sign(null as any, tbs, signKey); // Ed25519

	// BIT STRING with 0 unused bits.
	const sigBitString = tag(0x03, Buffer.concat([Buffer.from([0]), signature]));

	const crl = seq(tbs, algDer, sigBitString);
	return crl;
}

export function crlToPem(der: Buffer): string {
	const b64 = der.toString('base64').replace(/(.{64})/g, '$1\n').trim();
	return `-----BEGIN X509 CRL-----\n${b64}\n-----END X509 CRL-----\n`;
}
