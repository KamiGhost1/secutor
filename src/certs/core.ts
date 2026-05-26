import crypto from 'crypto';
import forge from 'node-forge';
import {
	KeyAlgorithm,
	generateKey,
	encryptPrivateKey,
	decryptPrivateKey,
	detectPrivateKeyAlgorithm,
	isEncryptedKey,
	isSigningAlgorithm,
} from './keys.js';
import {
	buildCertManual,
	parseCertCompat,
	spkiAsn1FromPublicKeyPem,
	ski160,
} from './manualBuilder.js';

export type Subject = {
	commonName: string;
	countryName?: string;
	stateOrProvinceName?: string;
	localityName?: string;
	organizationName?: string;
	organizationalUnitName?: string;
	emailAddress?: string;
};

export type LeafType = 'server' | 'client';

export type IssuerMaterial = {
	certPem: string;
	keyPem: string;
	/** If the CA key PEM is encrypted, supply its passphrase to decrypt. */
	keyPassword?: string | null;
};

export type BuiltCert = {
	certPem: string;
	keyPem: string;
	serial: string;
	notBefore: Date;
	notAfter: Date;
	fingerprint: string;
	algorithm: KeyAlgorithm;
};

export type ResignedCert = {
	certPem: string;
	serial: string;
	notBefore: Date;
	notAfter: Date;
	fingerprint: string;
};

export const DEFAULT_ALGORITHM: KeyAlgorithm = 'rsa-2048';

export function buildSubjectAttrs(s: Subject): forge.pki.CertificateField[] {
	const attrs: forge.pki.CertificateField[] = [
		{name: 'commonName', value: s.commonName},
	];
	if (s.countryName) attrs.push({name: 'countryName', value: s.countryName});
	if (s.stateOrProvinceName)
		attrs.push({name: 'stateOrProvinceName', value: s.stateOrProvinceName});
	if (s.localityName) attrs.push({name: 'localityName', value: s.localityName});
	if (s.organizationName)
		attrs.push({name: 'organizationName', value: s.organizationName});
	if (s.organizationalUnitName)
		attrs.push({shortName: 'OU', value: s.organizationalUnitName});
	if (s.emailAddress) attrs.push({name: 'emailAddress', value: s.emailAddress});
	return attrs;
}

// RFC 5280 §4.1.2.2: serial MUST be a positive integer. Force the high bit off
// and the leading byte non-zero so DER encodes a 16-byte unsigned integer
// without an extra leading 0x00.
export function genSerial(): string {
	const b = crypto.randomBytes(16);
	b[0] = (b[0] & 0x7f) | 0x01;
	return b.toString('hex');
}

export function fingerprintOfPem(certPem: string): string {
	// Compute the fingerprint over the raw DER of the original PEM. Going
	// through forge would round-trip the cert and corrupt non-RSA certs
	// (forge can't preserve ECDSA / Ed25519 SubjectPublicKeyInfo).
	const body = certPem
		.replace(/-----BEGIN [^-]+-----/g, '')
		.replace(/-----END [^-]+-----/g, '')
		.replace(/\s+/g, '');
	const der = Buffer.from(body, 'base64');
	return crypto.createHash('sha256').update(der).digest('hex');
}

type AltName = {type: number; value?: string; ip?: string};
export function sanList(sans: string[] | undefined): AltName[] | undefined {
	if (!sans || !sans.length) return undefined;
	return sans.map<AltName>(v => {
		if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return {type: 7, ip: v};
		return {type: 2, value: v};
	});
}

function defaultValidity(validityDays: number): {notBefore: Date; notAfter: Date} {
	const now = new Date();
	return {
		notBefore: now,
		notAfter: new Date(now.getTime() + validityDays * 24 * 3600 * 1000),
	};
}

/**
 * AuthorityKeyIdentifier with *only* the keyIdentifier field. Including
 * authorityCertIssuer/SerialNumber via node-forge populates them from the
 * CA's subject DN which is wrong (RFC 5280 §4.2.1.1 wants the CA's *issuer*
 * DN + serial) and breaks `openssl verify` on chains with an intermediate CA.
 */
function akiKeyIdentifierExt(caCert: forge.pki.Certificate) {
	return {
		name: 'authorityKeyIdentifier',
		keyIdentifier: caCert.generateSubjectKeyIdentifier().getBytes(),
	};
}

/**
 * Derive the AKI key identifier from a raw SPKI PEM (used when the CA's key
 * is non-RSA and node-forge cannot synthesise the keyIdentifier from its
 * Certificate object). The identifier is the SHA-1 of the BIT STRING value
 * inside SubjectPublicKeyInfo (RFC 5280 §4.2.1.2 method 1).
 */
function akiFromCaPublicKeyPem(caPublicKeyPem: string): {
	name: string;
	keyIdentifier: string;
} {
	return {name: 'authorityKeyIdentifier', keyIdentifier: ski160(caPublicKeyPem)};
}

function caPublicKeyPemFromCert(certPem: string): string {
	const key = crypto.createPublicKey(certPem);
	return key.export({type: 'spki', format: 'pem'}) as string;
}

function loadCaKey(issuer: IssuerMaterial): string {
	if (!issuer.keyPem) {
		throw new Error('CA has no private key in the store — cannot sign');
	}
	if (isEncryptedKey(issuer.keyPem)) {
		if (!issuer.keyPassword) {
			throw new Error('CA private key is password-protected — pass keyPassword');
		}
		return decryptPrivateKey(issuer.keyPem, issuer.keyPassword);
	}
	return issuer.keyPem;
}

function maybeEncryptKey(privateKeyPem: string, keyPassword?: string | null): string {
	if (!keyPassword) return privateKeyPem;
	return encryptPrivateKey(privateKeyPem, keyPassword);
}

// ---------- Root CA ----------

export type BuildRootInput = {
	subject: Subject;
	validityDays: number;
	algorithm?: KeyAlgorithm;
	/** If set, the returned `keyPem` is encrypted (PKCS#8 / AES-256-CBC). */
	keyPassword?: string | null;
};

export function buildRootCa(input: BuildRootInput): BuiltCert {
	const algorithm = input.algorithm ?? DEFAULT_ALGORITHM;
	if (!isSigningAlgorithm(algorithm)) {
		throw new Error(`Algorithm ${algorithm} cannot sign X.509 certificates`);
	}

	if (algorithm.startsWith('rsa')) {
		return buildRootCaRsa(input, algorithm);
	}
	return buildRootCaManual(input, algorithm);
}

function buildRootCaRsa(input: BuildRootInput, algorithm: KeyAlgorithm): BuiltCert {
	const bits = parseInt(algorithm.split('-')[1]!, 10);
	const keys = forge.pki.rsa.generateKeyPair(bits);
	const cert = forge.pki.createCertificate();
	cert.publicKey = keys.publicKey;
	cert.serialNumber = genSerial();
	const v = defaultValidity(input.validityDays);
	cert.validity.notBefore = v.notBefore;
	cert.validity.notAfter = v.notAfter;
	const attrs = buildSubjectAttrs(input.subject);
	cert.setSubject(attrs);
	cert.setIssuer(attrs);
	cert.setExtensions([
		{name: 'basicConstraints', cA: true},
		{name: 'keyUsage', keyCertSign: true, digitalSignature: true, cRLSign: true},
		{name: 'subjectKeyIdentifier'},
	]);
	cert.sign(keys.privateKey, forge.md.sha256.create());

	const certPem = forge.pki.certificateToPem(cert);
	const plainKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
	const keyPem = maybeEncryptKey(plainKeyPem, input.keyPassword);
	return {
		certPem,
		keyPem,
		serial: cert.serialNumber,
		notBefore: cert.validity.notBefore,
		notAfter: cert.validity.notAfter,
		fingerprint: fingerprintOfPem(certPem),
		algorithm,
	};
}

function buildRootCaManual(input: BuildRootInput, algorithm: KeyAlgorithm): BuiltCert {
	const k = generateKey(algorithm);
	const attrs = buildSubjectAttrs(input.subject);
	const v = defaultValidity(input.validityDays);
	const serial = genSerial();

	// Self-signed: subject = issuer, signing key = our new key.
	const built = buildCertManual({
		subjectAttrs: attrs,
		issuerAttrs: attrs,
		notBefore: v.notBefore,
		notAfter: v.notAfter,
		serialHex: serial,
		subjectPublicKeyPem: k.publicKeyPem,
		signerPrivateKeyPem: k.privateKeyPem,
		signingAlgorithm: algorithm,
		extensions: [
			{name: 'basicConstraints', cA: true},
			{name: 'keyUsage', keyCertSign: true, digitalSignature: true, cRLSign: true},
			{name: 'subjectKeyIdentifier'},
		],
	});

	const keyPem = maybeEncryptKey(k.privateKeyPem, input.keyPassword);
	return {
		certPem: built.certPem,
		keyPem,
		serial: built.serial,
		notBefore: built.notBefore,
		notAfter: built.notAfter,
		fingerprint: built.fingerprint,
		algorithm,
	};
}

// ---------- Intermediate CA ----------

export type BuildIntermediateInput = {
	subject: Subject;
	validityDays: number;
	ca: IssuerMaterial;
	pathLenConstraint?: number;
	algorithm?: KeyAlgorithm;
	keyPassword?: string | null;
};

export function buildIntermediateCa(input: BuildIntermediateInput): BuiltCert {
	const subjectAlgorithm = input.algorithm ?? DEFAULT_ALGORITHM;
	if (!isSigningAlgorithm(subjectAlgorithm)) {
		throw new Error(`Algorithm ${subjectAlgorithm} cannot sign X.509 certificates`);
	}
	const caKeyPem = loadCaKey(input.ca);
	const caAlgorithm = detectPrivateKeyAlgorithm(caKeyPem);
	const caCert = parseCertCompat(input.ca.certPem).cert;

	const v = defaultValidity(input.validityDays);
	const serial = genSerial();
	const attrs = buildSubjectAttrs(input.subject);

	const bc: any = {name: 'basicConstraints', cA: true};
	if (typeof input.pathLenConstraint === 'number' && input.pathLenConstraint >= 0) {
		bc.pathLenConstraint = input.pathLenConstraint;
	}
	const useForgeAki = caAlgorithm.startsWith('rsa');
	const aki = useForgeAki
		? akiKeyIdentifierExt(caCert)
		: akiFromCaPublicKeyPem(caPublicKeyPemFromCert(input.ca.certPem));

	const extensions = [
		bc,
		{name: 'keyUsage', keyCertSign: true, digitalSignature: true, cRLSign: true},
		{name: 'subjectKeyIdentifier'},
		aki,
	];

	if (caAlgorithm.startsWith('rsa') && subjectAlgorithm.startsWith('rsa')) {
		return buildIntermediateRsa({
			input,
			caKeyPem,
			caCert,
			attrs,
			validity: v,
			serial,
			extensions,
			subjectAlgorithm,
		});
	}

	const subjectKey = generateKey(subjectAlgorithm);
	const built = buildCertManual({
		subjectAttrs: attrs,
		issuerAttrs: caCert.subject.attributes,
		notBefore: v.notBefore,
		notAfter: v.notAfter,
		serialHex: serial,
		subjectPublicKeyPem: subjectKey.publicKeyPem,
		signerPrivateKeyPem: caKeyPem,
		signingAlgorithm: caAlgorithm,
		extensions,
	});

	const keyPem = maybeEncryptKey(subjectKey.privateKeyPem, input.keyPassword);
	return {
		certPem: built.certPem,
		keyPem,
		serial: built.serial,
		notBefore: built.notBefore,
		notAfter: built.notAfter,
		fingerprint: built.fingerprint,
		algorithm: subjectAlgorithm,
	};
}

function buildIntermediateRsa(args: {
	input: BuildIntermediateInput;
	caKeyPem: string;
	caCert: forge.pki.Certificate;
	attrs: forge.pki.CertificateField[];
	validity: {notBefore: Date; notAfter: Date};
	serial: string;
	extensions: any[];
	subjectAlgorithm: KeyAlgorithm;
}): BuiltCert {
	const bits = parseInt(args.subjectAlgorithm.split('-')[1]!, 10);
	const keys = forge.pki.rsa.generateKeyPair(bits);
	const cert = forge.pki.createCertificate();
	cert.publicKey = keys.publicKey;
	cert.serialNumber = args.serial;
	cert.validity.notBefore = args.validity.notBefore;
	cert.validity.notAfter = args.validity.notAfter;
	cert.setSubject(args.attrs);
	cert.setIssuer(args.caCert.subject.attributes);
	cert.setExtensions(args.extensions);
	const caKey = forge.pki.privateKeyFromPem(args.caKeyPem) as forge.pki.rsa.PrivateKey;
	cert.sign(caKey, forge.md.sha256.create());

	const certPem = forge.pki.certificateToPem(cert);
	const plainKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
	return {
		certPem,
		keyPem: maybeEncryptKey(plainKeyPem, args.input.keyPassword),
		serial: cert.serialNumber,
		notBefore: cert.validity.notBefore,
		notAfter: cert.validity.notAfter,
		fingerprint: fingerprintOfPem(certPem),
		algorithm: args.subjectAlgorithm,
	};
}

// ---------- Leaf ----------

export type BuildLeafInput = {
	type: LeafType;
	subject: Subject;
	validityDays: number;
	sans?: string[];
	ca: IssuerMaterial;
	algorithm?: KeyAlgorithm;
	keyPassword?: string | null;
};

export type BuiltLeaf = BuiltCert & {sans: string[]};

export function buildLeafCert(input: BuildLeafInput): BuiltLeaf {
	const subjectAlgorithm = input.algorithm ?? DEFAULT_ALGORITHM;
	if (!isSigningAlgorithm(subjectAlgorithm)) {
		throw new Error(`Algorithm ${subjectAlgorithm} cannot be used for a TLS leaf`);
	}
	const caKeyPem = loadCaKey(input.ca);
	const caAlgorithm = detectPrivateKeyAlgorithm(caKeyPem);
	const caCert = parseCertCompat(input.ca.certPem).cert;

	const sansFinal = input.sans ? [...input.sans] : [];
	if (input.type === 'server' && !sansFinal.includes(input.subject.commonName)) {
		sansFinal.unshift(input.subject.commonName);
	}
	const altNames = sanList(sansFinal);

	const aki = caAlgorithm.startsWith('rsa')
		? akiKeyIdentifierExt(caCert)
		: akiFromCaPublicKeyPem(caPublicKeyPemFromCert(input.ca.certPem));

	const exts: any[] = [
		{name: 'basicConstraints', cA: false},
		{
			name: 'keyUsage',
			digitalSignature: true,
			keyEncipherment: true,
			nonRepudiation: true,
		},
		{
			name: 'extKeyUsage',
			serverAuth: input.type === 'server',
			clientAuth: input.type === 'client',
		},
		{name: 'subjectKeyIdentifier'},
		aki,
	];
	if (altNames) exts.push({name: 'subjectAltName', altNames});

	const v = defaultValidity(input.validityDays);
	const serial = genSerial();
	const attrs = buildSubjectAttrs(input.subject);

	if (caAlgorithm.startsWith('rsa') && subjectAlgorithm.startsWith('rsa')) {
		const bits = parseInt(subjectAlgorithm.split('-')[1]!, 10);
		const keys = forge.pki.rsa.generateKeyPair(bits);
		const cert = forge.pki.createCertificate();
		cert.publicKey = keys.publicKey;
		cert.serialNumber = serial;
		cert.validity.notBefore = v.notBefore;
		cert.validity.notAfter = v.notAfter;
		cert.setSubject(attrs);
		cert.setIssuer(caCert.subject.attributes);
		cert.setExtensions(exts);
		const caKey = forge.pki.privateKeyFromPem(caKeyPem) as forge.pki.rsa.PrivateKey;
		cert.sign(caKey, forge.md.sha256.create());
		const certPem = forge.pki.certificateToPem(cert);
		const plainKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
		return {
			certPem,
			keyPem: maybeEncryptKey(plainKeyPem, input.keyPassword),
			serial: cert.serialNumber,
			notBefore: cert.validity.notBefore,
			notAfter: cert.validity.notAfter,
			fingerprint: fingerprintOfPem(certPem),
			sans: sansFinal,
			algorithm: subjectAlgorithm,
		};
	}

	const subjectKey = generateKey(subjectAlgorithm);
	const built = buildCertManual({
		subjectAttrs: attrs,
		issuerAttrs: caCert.subject.attributes,
		notBefore: v.notBefore,
		notAfter: v.notAfter,
		serialHex: serial,
		subjectPublicKeyPem: subjectKey.publicKeyPem,
		signerPrivateKeyPem: caKeyPem,
		signingAlgorithm: caAlgorithm,
		extensions: exts,
	});

	return {
		certPem: built.certPem,
		keyPem: maybeEncryptKey(subjectKey.privateKeyPem, input.keyPassword),
		serial: built.serial,
		notBefore: built.notBefore,
		notAfter: built.notAfter,
		fingerprint: built.fingerprint,
		sans: sansFinal,
		algorithm: subjectAlgorithm,
	};
}

// ---------- Re-sign ----------

export type ResignInput = {
	oldCertPem: string;
	ca: IssuerMaterial;
	validityDays?: number;
};

/**
 * Re-sign an existing certificate with a different CA.
 * Preserves the leaf's public key, subject, validity, SANs and extensions
 * (basicConstraints / keyUsage / extKeyUsage). Updates issuer DN, AKI, serial
 * and signature.
 */
export function resignCertificateCore(input: ResignInput): ResignedCert {
	const caKeyPem = loadCaKey(input.ca);
	const caAlgorithm = detectPrivateKeyAlgorithm(caKeyPem);

	const oldCert = parseCertCompat(input.oldCertPem).cert;
	const caCert = parseCertCompat(input.ca.certPem).cert;

	// If both CA and leaf public key are RSA, keep the well-trodden forge path.
	const oldKeyObj = crypto.createPublicKey(input.oldCertPem);
	const subjectIsRsa =
		oldKeyObj.asymmetricKeyType === 'rsa' || oldKeyObj.asymmetricKeyType === 'rsa-pss';
	const caIsRsa = caAlgorithm.startsWith('rsa');

	const now = new Date();
	const notBefore = input.validityDays && input.validityDays > 0 ? now : oldCert.validity.notBefore;
	const notAfter =
		input.validityDays && input.validityDays > 0
			? new Date(now.getTime() + input.validityDays * 24 * 3600 * 1000)
			: oldCert.validity.notAfter;
	const serial = genSerial();

	if (caIsRsa && subjectIsRsa) {
		const caKey = forge.pki.privateKeyFromPem(caKeyPem) as forge.pki.rsa.PrivateKey;
		const cert = forge.pki.createCertificate();
		cert.publicKey = oldCert.publicKey;
		cert.serialNumber = serial;
		cert.validity.notBefore = notBefore;
		cert.validity.notAfter = notAfter;
		cert.setSubject(oldCert.subject.attributes);
		cert.setIssuer(caCert.subject.attributes);

		const exts: any[] = [];
		for (const name of [
			'basicConstraints',
			'keyUsage',
			'extKeyUsage',
			'subjectAltName',
			'subjectKeyIdentifier',
		]) {
			const ext = oldCert.getExtension(name) as any;
			if (ext) {
				const {value: _value, ...rest} = ext;
				exts.push(rest);
			}
		}
		exts.push(akiKeyIdentifierExt(caCert));
		cert.setExtensions(exts);
		cert.sign(caKey, forge.md.sha256.create());

		const certPem = forge.pki.certificateToPem(cert);
		return {
			certPem,
			serial: cert.serialNumber,
			notBefore: cert.validity.notBefore,
			notAfter: cert.validity.notAfter,
			fingerprint: fingerprintOfPem(certPem),
		};
	}

	// Mixed (non-RSA CA, or non-RSA leaf key). Manual builder path.
	const subjectPublicKeyPem = oldKeyObj.export({type: 'spki', format: 'pem'}) as string;

	const exts: any[] = [];
	for (const name of [
		'basicConstraints',
		'keyUsage',
		'extKeyUsage',
		'subjectAltName',
		'subjectKeyIdentifier',
	]) {
		const ext = oldCert.getExtension(name) as any;
		if (ext) {
			const {value: _value, ...rest} = ext;
			exts.push(rest);
		}
	}
	exts.push(
		caIsRsa
			? akiKeyIdentifierExt(caCert)
			: akiFromCaPublicKeyPem(caPublicKeyPemFromCert(input.ca.certPem)),
	);

	const built = buildCertManual({
		subjectAttrs: oldCert.subject.attributes,
		issuerAttrs: caCert.subject.attributes,
		notBefore,
		notAfter,
		serialHex: serial,
		subjectPublicKeyPem,
		signerPrivateKeyPem: caKeyPem,
		signingAlgorithm: caAlgorithm,
		extensions: exts,
	});

	return {
		certPem: built.certPem,
		serial: built.serial,
		notBefore: built.notBefore,
		notAfter: built.notAfter,
		fingerprint: built.fingerprint,
	};
}
