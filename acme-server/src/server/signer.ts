// CSR-based leaf certificate issuance.
//
// Heavy lifting (manual ASN.1 swap that lets us sign any subject SPKI with any
// CA key algorithm) is a slimmed port of certificate-manager/src/certs/*.ts.

import crypto from 'crypto';
import forge from 'node-forge';
import {AcmeError} from './errors.js';

export type CsrInfo = {
	commonName: string | null;
	sans: string[]; // dNSName + iPAddress values
	subjectPublicKeyPem: string; // SPKI PEM
	der: Buffer;
};

type KeyAlgorithm =
	| 'rsa-2048'
	| 'rsa-3072'
	| 'rsa-4096'
	| 'ecdsa-p256'
	| 'ecdsa-p384'
	| 'ed25519';

function detectAlgorithm(privateKeyPem: string): KeyAlgorithm {
	const k = crypto.createPrivateKey(privateKeyPem);
	const t = k.asymmetricKeyType;
	if (t === 'rsa' || t === 'rsa-pss') {
		const bits = (k.asymmetricKeyDetails as any)?.modulusLength ?? 2048;
		if (bits >= 4096) return 'rsa-4096';
		if (bits >= 3072) return 'rsa-3072';
		return 'rsa-2048';
	}
	if (t === 'ec') {
		const curve = (k.asymmetricKeyDetails as any)?.namedCurve;
		if (curve === 'P-384' || curve === 'secp384r1') return 'ecdsa-p384';
		return 'ecdsa-p256';
	}
	if (t === 'ed25519') return 'ed25519';
	throw new Error(`Unsupported CA key type: ${t}`);
}

function signatureAlgorithmOid(alg: KeyAlgorithm): string {
	switch (alg) {
		case 'rsa-2048':
		case 'rsa-3072':
		case 'rsa-4096':
			return '1.2.840.113549.1.1.11'; // sha256WithRSAEncryption
		case 'ecdsa-p256':
			return '1.2.840.10045.4.3.2'; // ecdsa-with-SHA256
		case 'ecdsa-p384':
			return '1.2.840.10045.4.3.3'; // ecdsa-with-SHA384
		case 'ed25519':
			return '1.3.101.112';
	}
}

function signingHashFor(alg: KeyAlgorithm): string | null {
	switch (alg) {
		case 'ecdsa-p384':
			return 'sha384';
		case 'ed25519':
			return null;
		default:
			return 'sha256';
	}
}

function readLen(b: Buffer, off: number): {length: number; headerLen: number} {
	const first = b[off]!;
	if (first < 0x80) return {length: first, headerLen: 1};
	const n = first & 0x7f;
	let len = 0;
	for (let i = 1; i <= n; i++) len = (len << 8) | b[off + i]!;
	return {length: len, headerLen: 1 + n};
}

function spkiSubjectPublicKeyBits(publicKeyPem: string): Buffer {
	const pub = crypto.createPublicKey(publicKeyPem);
	const der = pub.export({type: 'spki', format: 'der'}) as Buffer;
	let p = 0;
	if (der[p++] !== 0x30) throw new Error('SPKI: expected outer SEQUENCE');
	const outer = readLen(der, p);
	p += outer.headerLen;
	if (der[p++] !== 0x30) throw new Error('SPKI: expected algorithm SEQUENCE');
	const alg = readLen(der, p);
	p += alg.headerLen + alg.length;
	if (der[p++] !== 0x03) throw new Error('SPKI: expected BIT STRING');
	const bs = readLen(der, p);
	p += bs.headerLen;
	const unused = der[p];
	if (unused !== 0) throw new Error(`SPKI: ${unused} unused bits unsupported`);
	p += 1;
	return der.subarray(p, p + bs.length - 1);
}

function ski160(publicKeyPem: string): string {
	const bits = spkiSubjectPublicKeyBits(publicKeyPem);
	return crypto.createHash('sha1').update(bits).digest('binary');
}

function algorithmIdentifierAsn1(alg: KeyAlgorithm): forge.asn1.Asn1 {
	const A = forge.asn1;
	const children: forge.asn1.Asn1[] = [
		A.create(A.Class.UNIVERSAL, A.Type.OID, false, A.oidToDer(signatureAlgorithmOid(alg)).getBytes()),
	];
	if (alg.startsWith('rsa')) {
		children.push(A.create(A.Class.UNIVERSAL, A.Type.NULL, false, ''));
	}
	return A.create(A.Class.UNIVERSAL, A.Type.SEQUENCE, true, children);
}

function spkiAsn1FromPublicKeyPem(publicKeyPem: string): forge.asn1.Asn1 {
	const k = crypto.createPublicKey(publicKeyPem);
	const der = k.export({type: 'spki', format: 'der'}) as Buffer;
	return forge.asn1.fromDer(forge.util.createBuffer(der.toString('binary')));
}

/**
 * Parse a DER-encoded PKCS#10 CSR. Validates the self-signature, and extracts
 * subject CN, SANs, and public key SPKI. Works regardless of the CSR key
 * algorithm (RSA / ECDSA / Ed25519).
 *
 * Strategy: walk the outer ASN.1 manually (so we get the *exact* TBS bytes
 * and raw BIT STRING signature). Then build a SPKI-swapped copy and hand it
 * to forge purely for nice subject/extensionRequest decoding.
 */
export function parseCsr(der: Buffer): CsrInfo {
	const walk = walkCsr(der);

	let pubKeyObj: crypto.KeyObject;
	try {
		pubKeyObj = crypto.createPublicKey({key: walk.spkiDer, format: 'der', type: 'spki'});
	} catch (e: any) {
		throw new AcmeError('badCSR', `Cannot read CSR public key: ${e?.message ?? e}`);
	}
	const pubPem = pubKeyObj.export({type: 'spki', format: 'pem'}) as string;

	const hash = sigAlgOidToHash(walk.sigAlgOid);
	let ok = false;
	try {
		ok = crypto.verify(hash as any, walk.tbsDer, pubKeyObj, walk.sigBytes);
	} catch (e: any) {
		throw new AcmeError('badCSR', `Verify error: ${e?.message ?? e}`);
	}
	if (!ok) throw new AcmeError('badCSR', 'CSR signature invalid');

	// Decode subject + extensionRequest via forge by swapping a dummy RSA SPKI.
	let csrForge: any;
	try {
		const A = forge.asn1;
		const csrAsn1 = A.fromDer(forge.util.createBuffer(der.toString('binary')));
		const certInfo = (csrAsn1 as any).value[0];
		const dummyPub = crypto.generateKeyPairSync('rsa', {modulusLength: 1024}).publicKey;
		const dummyPem = dummyPub.export({type: 'spki', format: 'pem'}) as string;
		certInfo.value[2] = spkiAsn1FromPublicKeyPem(dummyPem);
		csrForge = (forge.pki as any).certificationRequestFromAsn1(csrAsn1);
	} catch (e: any) {
		throw new AcmeError('badCSR', `Cannot decode CSR subject/attrs: ${e?.message ?? e}`);
	}

	const commonName =
		(csrForge.subject.getField({name: 'commonName'}) as any)?.value ?? null;
	const sans: string[] = [];
	const extensionAttr = (csrForge.attributes || []).find(
		(a: any) => a.name === 'extensionRequest',
	) as any;
	if (extensionAttr?.extensions) {
		for (const ext of extensionAttr.extensions) {
			if (ext.name === 'subjectAltName' && Array.isArray(ext.altNames)) {
				for (const n of ext.altNames) {
					if (n.type === 2 /* dNSName */ && n.value) sans.push(n.value);
					else if (n.type === 7 /* iPAddress */ && n.ip) sans.push(n.ip);
				}
			}
		}
	}
	return {commonName, sans, subjectPublicKeyPem: pubPem, der};
}

/**
 * Manually walk the CSR DER:
 *   SEQUENCE
 *     SEQUENCE   <-- TBS (CertificationRequestInfo): version, subject, SPKI, [0]attrs
 *     SEQUENCE   <-- signatureAlgorithm
 *     BIT STRING <-- signature
 * Returns the exact TBS bytes (with header), the SPKI DER (with header), the
 * sig-alg OID, and the raw signature bytes (after stripping the BIT STRING's
 * "unused bits" leading byte).
 */
function walkCsr(der: Buffer): {tbsDer: Buffer; spkiDer: Buffer; sigAlgOid: string; sigBytes: Buffer} {
	let p = 0;
	if (der[p++] !== 0x30) throw new Error('CSR: expected outer SEQUENCE');
	const outerLen = readDerLen(der, p);
	p += outerLen.headerLen;
	const outerEnd = p + outerLen.length;

	// TBS SEQUENCE
	const tbsStart = p;
	if (der[p++] !== 0x30) throw new Error('CSR: expected TBS SEQUENCE');
	const tbsLen = readDerLen(der, p);
	p += tbsLen.headerLen;
	const tbsBodyEnd = p + tbsLen.length;
	const tbsDer = der.subarray(tbsStart, tbsBodyEnd);

	// Inside TBS: version INTEGER
	const skipv = readTagAndAdvance(der, p);
	p = skipv.next;
	// subject SEQUENCE
	const skipsubj = readTagAndAdvance(der, p);
	p = skipsubj.next;
	// SPKI SEQUENCE
	const spkiStart = p;
	if (der[p++] !== 0x30) throw new Error('CSR: expected SPKI SEQUENCE');
	const spkiLen = readDerLen(der, p);
	p += spkiLen.headerLen;
	const spkiEnd = p + spkiLen.length;
	const spkiDer = der.subarray(spkiStart, spkiEnd);
	p = spkiEnd;
	// (attrs [0] optional, ignored)

	// After TBS: signatureAlgorithm SEQUENCE
	p = tbsBodyEnd;
	if (der[p++] !== 0x30) throw new Error('CSR: expected sigAlg SEQUENCE');
	const sigAlgLen = readDerLen(der, p);
	p += sigAlgLen.headerLen;
	const sigAlgEnd = p + sigAlgLen.length;
	// First inside: OID
	if (der[p++] !== 0x06) throw new Error('CSR: expected sigAlg OID');
	const oidLen = readDerLen(der, p);
	p += oidLen.headerLen;
	const oidDer = der.subarray(p - oidLen.headerLen - 1, p + oidLen.length); // include tag+len+value
	const sigAlgOid = derToOid(der.subarray(p, p + oidLen.length));
	p = sigAlgEnd;
	void oidDer;

	// BIT STRING
	if (der[p++] !== 0x03) throw new Error('CSR: expected signature BIT STRING');
	const bsLen = readDerLen(der, p);
	p += bsLen.headerLen;
	const unused = der[p++]!;
	if (unused !== 0) throw new Error(`CSR: signature has ${unused} unused bits`);
	const sigBytes = Buffer.from(der.subarray(p, p + bsLen.length - 1));
	p += bsLen.length - 1;
	void outerEnd;

	return {tbsDer, spkiDer: Buffer.from(spkiDer), sigAlgOid, sigBytes};
}

function readDerLen(b: Buffer, off: number): {length: number; headerLen: number} {
	const first = b[off]!;
	if (first < 0x80) return {length: first, headerLen: 1};
	const n = first & 0x7f;
	let len = 0;
	for (let i = 1; i <= n; i++) len = (len << 8) | b[off + i]!;
	return {length: len, headerLen: 1 + n};
}
function readTagAndAdvance(b: Buffer, off: number): {next: number} {
	off++; // tag
	const l = readDerLen(b, off);
	return {next: off + l.headerLen + l.length};
}
function derToOid(b: Buffer): string {
	const parts: number[] = [];
	const first = b[0]!;
	parts.push(Math.floor(first / 40));
	parts.push(first % 40);
	let i = 1;
	while (i < b.length) {
		let v = 0;
		while (i < b.length) {
			const o = b[i++]!;
			v = (v << 7) | (o & 0x7f);
			if ((o & 0x80) === 0) break;
		}
		parts.push(v);
	}
	return parts.join('.');
}

function sigAlgOidToHash(oid: string): string {
	switch (oid) {
		case '1.2.840.113549.1.1.5': // sha1WithRSAEncryption
			return 'sha1';
		case '1.2.840.113549.1.1.11': // sha256WithRSAEncryption
			return 'sha256';
		case '1.2.840.113549.1.1.12':
			return 'sha384';
		case '1.2.840.113549.1.1.13':
			return 'sha512';
		case '1.2.840.10045.4.3.2': // ecdsa-with-SHA256
			return 'sha256';
		case '1.2.840.10045.4.3.3':
			return 'sha384';
		case '1.2.840.10045.4.3.4':
			return 'sha512';
		case '1.3.101.112':
			return null as any; // Ed25519
		default:
			throw new AcmeError('badCSR', `Unsupported CSR signature algorithm OID: ${oid}`);
	}
}

function genSerial(): string {
	const b = crypto.randomBytes(16);
	b[0] = (b[0] & 0x7f) | 0x01;
	return b.toString('hex');
}

function fingerprintOfPem(certPem: string): string {
	const body = certPem
		.replace(/-----BEGIN [^-]+-----/g, '')
		.replace(/-----END [^-]+-----/g, '')
		.replace(/\s+/g, '');
	const der = Buffer.from(body, 'base64');
	return crypto.createHash('sha256').update(der).digest('hex');
}

export type IssueLeafInput = {
	caCertPem: string;
	caKeyPem: string; // plain
	subjectPublicKeyPem: string;
	commonName: string;
	sans: string[];
	notBefore: Date;
	notAfter: Date;
};

export type IssueLeafResult = {
	certPem: string;
	certDer: Buffer;
	serialHex: string;
	notBefore: Date;
	notAfter: Date;
	fingerprint: string;
};

/**
 * Build a server-auth leaf cert. Uses node-forge to encode Name/Validity/
 * Extensions in a placeholder certificate, then swaps the SPKI and signature-
 * algorithm fields and signs the resulting TBS with node:crypto.
 */
export function issueLeaf(input: IssueLeafInput): IssueLeafResult {
	const caKeyAlg = detectAlgorithm(input.caKeyPem);
	const caCert = forge.pki.certificateFromPem(reEncodeCaCertForForge(input.caCertPem));

	// Subject attrs: CN only — minimum sufficient.
	const subjectAttrs: forge.pki.CertificateField[] = [
		{name: 'commonName', value: input.commonName},
	];
	const altNames = input.sans.map(v => {
		if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return {type: 7, ip: v};
		return {type: 2, value: v};
	});

	const exts: any[] = [
		{name: 'basicConstraints', cA: false},
		{name: 'keyUsage', digitalSignature: true, keyEncipherment: true},
		{name: 'extKeyUsage', serverAuth: true},
		{name: 'subjectKeyIdentifier'},
		{
			name: 'authorityKeyIdentifier',
			keyIdentifier: caKeyAlg.startsWith('rsa')
				? caCert.generateSubjectKeyIdentifier().getBytes()
				: ski160(crypto.createPublicKey(input.caCertPem).export({type: 'spki', format: 'pem'}) as string),
		},
	];
	if (altNames.length) exts.push({name: 'subjectAltName', altNames});

	// Placeholder cert built with a throwaway RSA key.
	const dummy = forge.pki.rsa.generateKeyPair(2048);
	const cert = forge.pki.createCertificate();
	cert.publicKey = dummy.publicKey;
	cert.serialNumber = genSerial();
	cert.validity.notBefore = input.notBefore;
	cert.validity.notAfter = input.notAfter;
	cert.setSubject(subjectAttrs);
	cert.setIssuer(caCert.subject.attributes);

	const realSki = ski160(input.subjectPublicKeyPem);
	(cert as any).generateSubjectKeyIdentifier = () =>
		forge.util.createBuffer(realSki, 'raw');
	cert.setExtensions(exts);
	cert.sign(dummy.privateKey, forge.md.sha256.create());

	const tbs = (forge.pki as any).getTBSCertificate(cert) as forge.asn1.Asn1;
	const fields = (tbs as any).value as forge.asn1.Asn1[];
	const A = forge.asn1;
	const hasVersion =
		fields[0].tagClass === A.Class.CONTEXT_SPECIFIC && fields[0].type === 0;
	const sigAlgIndex = hasVersion ? 2 : 1;
	const spkiIndex = hasVersion ? 6 : 5;
	fields[sigAlgIndex] = algorithmIdentifierAsn1(caKeyAlg);
	fields[spkiIndex] = spkiAsn1FromPublicKeyPem(input.subjectPublicKeyPem);

	const tbsDerBin = A.toDer(tbs).getBytes();
	const tbsBuf = Buffer.from(tbsDerBin, 'binary');
	const signKey = crypto.createPrivateKey(input.caKeyPem);
	const hash = signingHashFor(caKeyAlg);
	const signature = crypto.sign(hash, tbsBuf, signKey);

	const outer = A.create(A.Class.UNIVERSAL, A.Type.SEQUENCE, true, [
		tbs,
		algorithmIdentifierAsn1(caKeyAlg),
		A.create(A.Class.UNIVERSAL, A.Type.BITSTRING, false, '\x00' + signature.toString('binary')),
	]);

	const der = Buffer.from(A.toDer(outer).getBytes(), 'binary');
	const pem = forge.pem.encode({type: 'CERTIFICATE', body: der.toString('binary')});
	return {
		certPem: pem,
		certDer: der,
		serialHex: cert.serialNumber,
		notBefore: cert.validity.notBefore,
		notAfter: cert.validity.notAfter,
		fingerprint: fingerprintOfPem(pem),
	};
}

/**
 * forge can't parse certs whose subject key is non-RSA. For our purposes we
 * only need the CA cert's subject DN to wire as the issuer. Re-encode by
 * swapping in a dummy RSA SPKI before parsing.
 */
function reEncodeCaCertForForge(pem: string): string {
	try {
		forge.pki.certificateFromPem(pem); // works for RSA CAs
		return pem;
	} catch {
		// fall through
	}
	const A = forge.asn1;
	const body = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
	const der = Buffer.from(body, 'base64');
	const asn1 = A.fromDer(forge.util.createBuffer(der.toString('binary')));
	const tbs = (asn1 as any).value[0];
	const fields = tbs.value as forge.asn1.Asn1[];
	const hasVersion =
		fields[0].tagClass === A.Class.CONTEXT_SPECIFIC && fields[0].type === 0;
	const spkiIdx = hasVersion ? 6 : 5;
	const pair = crypto.generateKeyPairSync('rsa', {modulusLength: 1024});
	const dummyPem = pair.publicKey.export({type: 'spki', format: 'pem'}) as string;
	fields[spkiIdx] = spkiAsn1FromPublicKeyPem(dummyPem);
	const der2 = Buffer.from(A.toDer(asn1).getBytes(), 'binary');
	return forge.pem.encode({type: 'CERTIFICATE', body: der2.toString('binary')});
}
