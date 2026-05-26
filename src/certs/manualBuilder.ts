import crypto from 'crypto';
import forge from 'node-forge';
import {
	KeyAlgorithm,
	signatureAlgorithmOid,
	signingHashFor,
	detectPrivateKeyAlgorithm,
} from './keys.js';

/**
 * Build the AlgorithmIdentifier ASN.1 for a given signing algorithm:
 *  - RSA SHA-256: SEQUENCE { OID, NULL }
 *  - ECDSA-with-SHA*: SEQUENCE { OID }     (RFC 5480 — no parameters)
 *  - Ed25519: SEQUENCE { OID }             (RFC 8410 — no parameters)
 */
export function algorithmIdentifierAsn1(algorithm: KeyAlgorithm): forge.asn1.Asn1 {
	const ASN1 = forge.asn1;
	const oid = signatureAlgorithmOid(algorithm);
	const children: forge.asn1.Asn1[] = [
		ASN1.create(ASN1.Class.UNIVERSAL, ASN1.Type.OID, false, ASN1.oidToDer(oid).getBytes()),
	];
	if (algorithm.startsWith('rsa')) {
		children.push(ASN1.create(ASN1.Class.UNIVERSAL, ASN1.Type.NULL, false, ''));
	}
	return ASN1.create(ASN1.Class.UNIVERSAL, ASN1.Type.SEQUENCE, true, children);
}

/** Parse an SPKI-PEM public key into its raw ASN.1 (a SubjectPublicKeyInfo SEQUENCE). */
export function spkiAsn1FromPublicKeyPem(publicKeyPem: string): forge.asn1.Asn1 {
	const key = crypto.createPublicKey(publicKeyPem);
	const der = key.export({type: 'spki', format: 'der'}) as Buffer;
	return forge.asn1.fromDer(forge.util.createBuffer(der.toString('binary')));
}

/** Same but from a private key (extracts the public side). */
export function spkiAsn1FromPrivateKeyPem(privateKeyPem: string): forge.asn1.Asn1 {
	const key = crypto.createPrivateKey(privateKeyPem);
	const pub = crypto.createPublicKey(key);
	const der = pub.export({type: 'spki', format: 'der'}) as Buffer;
	return forge.asn1.fromDer(forge.util.createBuffer(der.toString('binary')));
}

let _dummyRsaSpkiAsn1: forge.asn1.Asn1 | null = null;
function dummyRsaSpkiAsn1(): forge.asn1.Asn1 {
	if (_dummyRsaSpkiAsn1) return _dummyRsaSpkiAsn1;
	// One-time 1024-bit dummy key just to give forge something parseable.
	// We never use it for crypto — only its SPKI bytes are read.
	const pair = crypto.generateKeyPairSync('rsa', {modulusLength: 1024});
	const pem = pair.publicKey.export({type: 'spki', format: 'pem'}) as string;
	_dummyRsaSpkiAsn1 = spkiAsn1FromPublicKeyPem(pem);
	return _dummyRsaSpkiAsn1;
}

/**
 * Parse an X.509 PEM into a forge Certificate object even if its public-key
 * algorithm is one that forge cannot decode (ECDSA, Ed25519). The trick is to
 * substitute the SubjectPublicKeyInfo block with a dummy RSA SPKI before
 * handing the ASN.1 to forge — every other field (subject, issuer, validity,
 * extensions) parses correctly. The returned `publicKeyOriginalPem` carries
 * the *real* SPKI extracted via node:crypto so callers can re-attach it later.
 */
export function parseCertCompat(pem: string): {
	cert: forge.pki.Certificate;
	publicKeyOriginalPem: string;
} {
	try {
		const cert = forge.pki.certificateFromPem(pem);
		const pubKeyPem = forge.pki.publicKeyToPem(cert.publicKey);
		return {cert, publicKeyOriginalPem: pubKeyPem};
	} catch {
		// fall through to manual swap
	}

	const origPubKey = crypto.createPublicKey(pem);
	const origPubPem = origPubKey.export({type: 'spki', format: 'pem'}) as string;

	// Strip PEM envelope, decode DER, locate SPKI inside TBS, swap.
	const der = pemToDer(pem);
	const ASN1 = forge.asn1;
	const certAsn1 = ASN1.fromDer(forge.util.createBuffer(der.toString('binary')));
	const tbs = (certAsn1 as any).value[0];
	const fields = tbs.value as forge.asn1.Asn1[];
	const hasVersion =
		fields[0].tagClass === ASN1.Class.CONTEXT_SPECIFIC && fields[0].type === 0;
	const spkiIdx = hasVersion ? 6 : 5;
	fields[spkiIdx] = dummyRsaSpkiAsn1();

	const cert = forge.pki.certificateFromAsn1(certAsn1);
	return {cert, publicKeyOriginalPem: origPubPem};
}

function pemToDer(pem: string): Buffer {
	const body = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
	return Buffer.from(body, 'base64');
}

/**
 * Compute the 160-bit Subject Key Identifier of an SPKI public-key PEM
 * (RFC 5280 §4.2.1.2 method 1): SHA-1 over the contents of the
 * SubjectPublicKey BIT STRING, *excluding* the leading "unused bits" byte.
 * Returns a 20-byte binary string (forge convention).
 *
 * Implemented with a minimal DER length parser so it's independent of how
 * forge happens to decode the BIT STRING (recursive vs raw) for the
 * particular key algorithm.
 */
export function ski160(publicKeyPem: string): string {
	const keyBits = spkiSubjectPublicKeyBits(publicKeyPem);
	return crypto.createHash('sha1').update(keyBits).digest('binary');
}

function spkiSubjectPublicKeyBits(publicKeyPem: string): Buffer {
	const pub = crypto.createPublicKey(publicKeyPem);
	const der = pub.export({type: 'spki', format: 'der'}) as Buffer;
	let p = 0;
	if (der[p++] !== 0x30) throw new Error('SPKI: expected outer SEQUENCE');
	const outer = readLen(der, p);
	p += outer.headerLen;
	// algorithm AlgorithmIdentifier — SEQUENCE
	if (der[p++] !== 0x30) throw new Error('SPKI: expected algorithm SEQUENCE');
	const alg = readLen(der, p);
	p += alg.headerLen + alg.length;
	// subjectPublicKey BIT STRING
	if (der[p++] !== 0x03) throw new Error('SPKI: expected BIT STRING');
	const bs = readLen(der, p);
	p += bs.headerLen;
	const unused = der[p];
	if (unused !== 0) throw new Error(`SPKI: ${unused} unused bits unsupported`);
	p += 1;
	return der.subarray(p, p + bs.length - 1);
}

function readLen(b: Buffer, off: number): {length: number; headerLen: number} {
	const first = b[off]!;
	if (first < 0x80) return {length: first, headerLen: 1};
	const n = first & 0x7f;
	let len = 0;
	for (let i = 1; i <= n; i++) len = (len << 8) | b[off + i]!;
	return {length: len, headerLen: 1 + n};
}

export type ManualCertOptions = {
	subjectAttrs: forge.pki.CertificateField[];
	issuerAttrs: forge.pki.CertificateField[];
	notBefore: Date;
	notAfter: Date;
	serialHex: string;
	subjectPublicKeyPem: string;
	/** Issuer's (CA's) plain private-key PEM, used to sign. */
	signerPrivateKeyPem: string;
	/**
	 * Signing algorithm — typically the CA key's algorithm. If omitted, it is
	 * detected automatically from the private key.
	 */
	signingAlgorithm?: KeyAlgorithm;
	/** node-forge–shaped extension descriptors (same as cert.setExtensions). */
	extensions: any[];
};

export type ManualCertResult = {
	certPem: string;
	certDer: Buffer;
	serial: string;
	notBefore: Date;
	notAfter: Date;
	fingerprint: string;
};

/**
 * Build a fully signed X.509 v3 certificate where the signing key may be RSA,
 * ECDSA P-256/P-384, or Ed25519. The subject's public key (in SPKI PEM) can
 * be any of those algorithms too — the signature algorithm is always
 * determined by the *issuer's* key.
 *
 * Strategy: use node-forge to populate a placeholder certificate (with a
 * throwaway RSA key) so we get correct Name / Validity / Extensions ASN.1
 * encoding, then swap the SubjectPublicKeyInfo and signature-algorithm
 * fields and sign the resulting TBS with node:crypto.
 */
export function buildCertManual(opts: ManualCertOptions): ManualCertResult {
	const algorithm: KeyAlgorithm =
		opts.signingAlgorithm ?? detectPrivateKeyAlgorithm(opts.signerPrivateKeyPem);

	// 1. Build a placeholder cert so forge does the Name/Validity/Extension
	//    encoding for us. The placeholder RSA key is discarded.
	const dummy = forge.pki.rsa.generateKeyPair(2048);
	const cert = forge.pki.createCertificate();
	cert.publicKey = dummy.publicKey;
	cert.serialNumber = opts.serialHex;
	cert.validity.notBefore = opts.notBefore;
	cert.validity.notAfter = opts.notAfter;
	cert.setSubject(opts.subjectAttrs);
	cert.setIssuer(opts.issuerAttrs);

	// CRITICAL: forge's setExtensions auto-computes subjectKeyIdentifier from
	// `cert.publicKey` — which is the dummy RSA key, not the real subject key.
	// Override the generator so it returns the SHA-1 of the *real* SPKI BIT
	// STRING (RFC 5280 §4.2.1.2 method 1).
	const realSki = ski160(opts.subjectPublicKeyPem);
	(cert as any).generateSubjectKeyIdentifier = () =>
		forge.util.createBuffer(realSki, 'raw');

	cert.setExtensions(opts.extensions);
	// Sign with dummy so forge populates siginfo (required by getTBSCertificate).
	cert.sign(dummy.privateKey, forge.md.sha256.create());

	const tbs = (forge.pki as any).getTBSCertificate(cert) as forge.asn1.Asn1;
	const fields = (tbs as any).value as forge.asn1.Asn1[];

	// TBSCertificate fields for v3:
	//   [0] EXPLICIT version  (CONTEXT_SPECIFIC tag)
	//   [1] serialNumber INTEGER
	//   [2] signature AlgorithmIdentifier  <- swap to our algorithm
	//   [3] issuer Name
	//   [4] validity
	//   [5] subject Name
	//   [6] subjectPublicKeyInfo  <- swap to subject's real key
	const ASN1 = forge.asn1;
	const hasVersion =
		fields[0].tagClass === ASN1.Class.CONTEXT_SPECIFIC && fields[0].type === 0;
	const sigAlgIndex = hasVersion ? 2 : 1;
	const spkiIndex = hasVersion ? 6 : 5;

	fields[sigAlgIndex] = algorithmIdentifierAsn1(algorithm);
	fields[spkiIndex] = spkiAsn1FromPublicKeyPem(opts.subjectPublicKeyPem);

	// 2. Sign the modified TBS with node:crypto using the real CA key.
	const tbsDerBin = ASN1.toDer(tbs).getBytes();
	const tbsBuf = Buffer.from(tbsDerBin, 'binary');
	const signKey = crypto.createPrivateKey(opts.signerPrivateKeyPem);
	const hash = signingHashFor(algorithm);
	const signature = crypto.sign(hash, tbsBuf, signKey);

	// 3. Assemble outer Certificate SEQUENCE.
	const outer = ASN1.create(ASN1.Class.UNIVERSAL, ASN1.Type.SEQUENCE, true, [
		tbs,
		algorithmIdentifierAsn1(algorithm),
		ASN1.create(
			ASN1.Class.UNIVERSAL,
			ASN1.Type.BITSTRING,
			false,
			'\x00' + signature.toString('binary'),
		),
	]);

	const der = Buffer.from(ASN1.toDer(outer).getBytes(), 'binary');
	const pem = forge.pem.encode({type: 'CERTIFICATE', body: der.toString('binary')});
	const fingerprint = crypto.createHash('sha256').update(der).digest('hex');

	return {
		certPem: pem,
		certDer: der,
		serial: opts.serialHex,
		notBefore: opts.notBefore,
		notAfter: opts.notAfter,
		fingerprint,
	};
}
