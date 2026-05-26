import crypto from 'crypto';
import forge from 'node-forge';
import {certRepo, CertRow} from '../storage/repos.js';
import {
	buildRootCa,
	buildIntermediateCa,
	buildLeafCert,
	resignCertificateCore,
	Subject,
	LeafType,
} from './core.js';
import {KeyAlgorithm, decryptPrivateKey, isEncryptedKey} from './keys.js';
import {parseCertCompat} from './manualBuilder.js';
import {buildP12 as buildP12Pkijs} from './p12.js';

export type {Subject} from './core.js';
export type {KeyAlgorithm} from './keys.js';

export type CreateCAInput = Subject & {
	name: string;
	validityDays: number;
	/** Key algorithm — defaults to RSA-2048 for backwards compatibility. */
	algorithm?: KeyAlgorithm;
	/** If set, the CA's stored private key is encrypted with this passphrase. */
	keyPassword?: string | null;
};

export type IssueCertInput = Subject & {
	name: string;
	caId: number;
	validityDays: number;
	sans?: string[];
	algorithm?: KeyAlgorithm;
	keyPassword?: string | null;
	/** Required if the issuing CA's key is password-protected. */
	caKeyPassword?: string | null;
};

export type IssueIntermediateCAInput = Subject & {
	name: string;
	caId: number;
	validityDays: number;
	pathLenConstraint?: number;
	algorithm?: KeyAlgorithm;
	keyPassword?: string | null;
	caKeyPassword?: string | null;
};

function pickSubject(input: Subject): Subject {
	return {
		commonName: input.commonName,
		countryName: input.countryName,
		stateOrProvinceName: input.stateOrProvinceName,
		localityName: input.localityName,
		organizationName: input.organizationName,
		organizationalUnitName: input.organizationalUnitName,
		emailAddress: input.emailAddress,
	};
}

export function createCA(input: CreateCAInput): number {
	const built = buildRootCa({
		subject: pickSubject(input),
		validityDays: input.validityDays,
		algorithm: input.algorithm,
		keyPassword: input.keyPassword,
	});
	return certRepo.insert({
		name: input.name,
		type: 'ca',
		common_name: input.commonName,
		organization: input.organizationName ?? null,
		issuer_id: null,
		serial: built.serial,
		not_before: built.notBefore.toISOString(),
		not_after: built.notAfter.toISOString(),
		san: null,
		cert_pem: built.certPem,
		key_pem: built.keyPem,
		fingerprint: built.fingerprint,
	});
}

export function issueIntermediateCA(input: IssueIntermediateCAInput): number {
	const ca = certRepo.findById(input.caId);
	if (!ca) throw new Error('CA not found');
	if (ca.type !== 'ca') throw new Error('Selected issuer is not a CA');
	if (!ca.key_pem)
		throw new Error('У выбранного CA нет приватного ключа в БД — выпускать невозможно');

	const built = buildIntermediateCa({
		subject: pickSubject(input),
		validityDays: input.validityDays,
		pathLenConstraint: input.pathLenConstraint,
		algorithm: input.algorithm,
		keyPassword: input.keyPassword,
		ca: {
			certPem: ca.cert_pem,
			keyPem: ca.key_pem,
			keyPassword: input.caKeyPassword ?? null,
		},
	});

	return certRepo.insert({
		name: input.name,
		type: 'ca',
		common_name: input.commonName,
		organization: input.organizationName ?? null,
		issuer_id: ca.id,
		serial: built.serial,
		not_before: built.notBefore.toISOString(),
		not_after: built.notAfter.toISOString(),
		san: null,
		cert_pem: built.certPem,
		key_pem: built.keyPem,
		fingerprint: built.fingerprint,
	});
}

export function issueCert(type: LeafType, input: IssueCertInput): number {
	const ca = certRepo.findById(input.caId);
	if (!ca) throw new Error('CA not found');
	if (ca.type !== 'ca') throw new Error('Selected issuer is not a CA');
	if (!ca.key_pem)
		throw new Error('У выбранного CA нет приватного ключа в БД — выпускать невозможно');

	const built = buildLeafCert({
		type,
		subject: pickSubject(input),
		validityDays: input.validityDays,
		sans: input.sans,
		algorithm: input.algorithm,
		keyPassword: input.keyPassword,
		ca: {
			certPem: ca.cert_pem,
			keyPem: ca.key_pem,
			keyPassword: input.caKeyPassword ?? null,
		},
	});

	return certRepo.insert({
		name: input.name,
		type,
		common_name: input.commonName,
		organization: input.organizationName ?? null,
		issuer_id: ca.id,
		serial: built.serial,
		not_before: built.notBefore.toISOString(),
		not_after: built.notAfter.toISOString(),
		san: built.sans.length ? JSON.stringify(built.sans) : null,
		cert_pem: built.certPem,
		key_pem: built.keyPem,
		fingerprint: built.fingerprint,
	});
}

export type ResignResult = {
	certPem: string;
	serial: string;
	notBefore: Date;
	notAfter: Date;
	fingerprint: string;
};

export function resignCertificate(
	leafId: number,
	newCaId: number,
	options?: {validityDays?: number; caKeyPassword?: string | null},
): ResignResult {
	if (leafId === newCaId)
		throw new Error('Cannot re-sign a certificate with itself');
	const leaf = certRepo.findById(leafId);
	if (!leaf) throw new Error('Certificate not found');
	const ca = certRepo.findById(newCaId);
	if (!ca) throw new Error('CA not found');
	if (ca.type !== 'ca') throw new Error('Selected issuer is not a CA');
	if (!ca.key_pem) throw new Error('CA has no private key — cannot re-sign');

	return resignCertificateCore({
		oldCertPem: leaf.cert_pem,
		ca: {
			certPem: ca.cert_pem,
			keyPem: ca.key_pem,
			keyPassword: options?.caKeyPassword ?? null,
		},
		validityDays: options?.validityDays,
	});
}

export type RenewResult = ResignResult & {newIssuerId: number | null};

/**
 * Re-issue a certificate (typically expired) with a fresh validity window,
 * keeping the public key, subject, SANs and extensions. The signing CA is
 * picked automatically: self for a self-signed root, or the cert's current
 * issuer otherwise. Caller is responsible for writing the result back via
 * certRepo.replaceCert.
 */
export function renewCertificate(
	leafId: number,
	options: {validityDays: number; caKeyPassword?: string | null},
): RenewResult {
	if (!options.validityDays || options.validityDays <= 0) {
		throw new Error('validityDays must be positive');
	}
	const leaf = certRepo.findById(leafId);
	if (!leaf) throw new Error('Certificate not found');

	const leafCert = parseCertCompat(leaf.cert_pem).cert;
	const subjectDer = forge.asn1
		.toDer(forge.pki.distinguishedNameToAsn1(leafCert.subject as any))
		.getBytes();
	const issuerDer = forge.asn1
		.toDer(forge.pki.distinguishedNameToAsn1(leafCert.issuer as any))
		.getBytes();
	const selfSigned = subjectDer === issuerDer;

	let caCertPem: string;
	let caKeyPem: string;
	let newIssuerId: number | null;

	if (selfSigned && leaf.type === 'ca') {
		if (!leaf.key_pem) {
			throw new Error('Self-signed CA has no private key — cannot renew');
		}
		caCertPem = leaf.cert_pem;
		caKeyPem = leaf.key_pem;
		newIssuerId = null;
	} else {
		if (leaf.issuer_id === null) {
			throw new Error('Certificate has no linked issuer — cannot renew');
		}
		const parent = certRepo.findById(leaf.issuer_id);
		if (!parent) throw new Error('Linked issuer is missing in the DB');
		if (parent.type !== 'ca') throw new Error('Linked issuer is not a CA');
		if (!parent.key_pem)
			throw new Error('Linked CA has no private key — cannot renew');
		caCertPem = parent.cert_pem;
		caKeyPem = parent.key_pem;
		newIssuerId = parent.id;
	}

	const result = resignCertificateCore({
		oldCertPem: leaf.cert_pem,
		ca: {
			certPem: caCertPem,
			keyPem: caKeyPem,
			keyPassword: options.caKeyPassword ?? null,
		},
		validityDays: options.validityDays,
	});
	return {...result, newIssuerId};
}

function dateToTime(d: Date): forge.asn1.Asn1 {
	const year = d.getUTCFullYear();
	if (year >= 1950 && year < 2050) {
		return forge.asn1.create(
			forge.asn1.Class.UNIVERSAL,
			forge.asn1.Type.UTCTIME,
			false,
			forge.asn1.dateToUtcTime(d) as any,
		);
	}
	return forge.asn1.create(
		forge.asn1.Class.UNIVERSAL,
		forge.asn1.Type.GENERALIZEDTIME,
		false,
		forge.asn1.dateToGeneralizedTime(d) as any,
	);
}

function serialBytes(serialHex: string): string {
	let h = serialHex;
	if (h.length % 2 !== 0) h = '0' + h;
	let bytes = forge.util.hexToBytes(h);
	if (bytes.charCodeAt(0) & 0x80) bytes = '\x00' + bytes;
	return bytes;
}

function getCertSubjectAsn1(caCert: forge.pki.Certificate): forge.asn1.Asn1 {
	const certAsn1 = forge.pki.certificateToAsn1(caCert) as any;
	const tbs = certAsn1.value[0];
	const fields = tbs.value as any[];
	const hasVersion =
		fields[0].tagClass === forge.asn1.Class.CONTEXT_SPECIFIC &&
		(fields[0].type === 0);
	const offset = hasVersion ? 1 : 0;
	return fields[offset + 4];
}

export function buildCRL(
	caId: number,
	options?: {validityDays?: number; caKeyPassword?: string | null},
): Buffer {
	const ca = certRepo.findById(caId);
	if (!ca) throw new Error('CA not found');
	if (ca.type !== 'ca') throw new Error('Selected certificate is not a CA');
	if (!ca.key_pem) throw new Error('CA has no private key — cannot sign CRL');

	// Use parseCertCompat so non-RSA CAs work too.
	const caCert = parseCertCompat(ca.cert_pem).cert;
	const plainKeyPem = decryptPrivateKey(ca.key_pem, options?.caKeyPassword ?? null);
	const issuerAsn1 = getCertSubjectAsn1(caCert);

	const revokedRows = certRepo.listRevokedBy(caId);

	// Determine the signature algorithm OID from the CA's actual key type.
	const cryptoKey = crypto.createPrivateKey(plainKeyPem);
	const {sigOid, hash, includeNullParams} = crlSigAlg(cryptoKey);

	const ASN1 = forge.asn1;
	const sigAlgChildren = [
		ASN1.create(
			ASN1.Class.UNIVERSAL,
			ASN1.Type.OID,
			false,
			ASN1.oidToDer(sigOid).getBytes(),
		),
	];
	if (includeNullParams) {
		sigAlgChildren.push(ASN1.create(ASN1.Class.UNIVERSAL, ASN1.Type.NULL, false, ''));
	}
	const sigAlg = ASN1.create(ASN1.Class.UNIVERSAL, ASN1.Type.SEQUENCE, true, sigAlgChildren);

	const now = new Date();
	const next = new Date(
		now.getTime() + (options?.validityDays ?? 30) * 24 * 3600 * 1000,
	);

	const revokedSeqEntries: forge.asn1.Asn1[] = revokedRows.map(r => {
		const revDate = r.revoked_at ? new Date(r.revoked_at) : now;
		return ASN1.create(ASN1.Class.UNIVERSAL, ASN1.Type.SEQUENCE, true, [
			ASN1.create(
				ASN1.Class.UNIVERSAL,
				ASN1.Type.INTEGER,
				false,
				serialBytes(r.serial),
			),
			dateToTime(revDate),
		]);
	});

	const tbsChildren: forge.asn1.Asn1[] = [
		ASN1.create(
			ASN1.Class.UNIVERSAL,
			ASN1.Type.INTEGER,
			false,
			ASN1.integerToDer(1).getBytes(),
		),
		sigAlg,
		issuerAsn1,
		dateToTime(now),
		dateToTime(next),
	];
	if (revokedSeqEntries.length) {
		tbsChildren.push(
			ASN1.create(ASN1.Class.UNIVERSAL, ASN1.Type.SEQUENCE, true, revokedSeqEntries),
		);
	}

	const tbs = ASN1.create(ASN1.Class.UNIVERSAL, ASN1.Type.SEQUENCE, true, tbsChildren);
	const tbsDer = ASN1.toDer(tbs).getBytes();

	// Sign with node:crypto so RSA / ECDSA / Ed25519 are all supported.
	const signature = crypto.sign(hash, Buffer.from(tbsDer, 'binary'), cryptoKey);

	const crl = ASN1.create(ASN1.Class.UNIVERSAL, ASN1.Type.SEQUENCE, true, [
		tbs,
		sigAlg,
		ASN1.create(
			ASN1.Class.UNIVERSAL,
			ASN1.Type.BITSTRING,
			false,
			'\x00' + signature.toString('binary'),
		),
	]);

	const der = ASN1.toDer(crl).getBytes();
	const pem = forge.pem.encode({type: 'X509 CRL', body: der});
	return Buffer.from(pem, 'utf8');
}

function crlSigAlg(key: any): {sigOid: string; hash: string | null; includeNullParams: boolean} {
	const t = key.asymmetricKeyType;
	if (t === 'rsa' || t === 'rsa-pss') {
		return {sigOid: '1.2.840.113549.1.1.11', hash: 'sha256', includeNullParams: true};
	}
	if (t === 'ec') {
		const curve = key.asymmetricKeyDetails?.namedCurve;
		if (curve === 'P-384' || curve === 'secp384r1') {
			return {sigOid: '1.2.840.10045.4.3.3', hash: 'sha384', includeNullParams: false};
		}
		return {sigOid: '1.2.840.10045.4.3.2', hash: 'sha256', includeNullParams: false};
	}
	if (t === 'ed25519') {
		return {sigOid: '1.3.101.112', hash: null, includeNullParams: false};
	}
	throw new Error(`Unsupported CA key type for CRL signing: ${t}`);
}

export function collectSubtreePems(rootId: number): string[] {
	const out: string[] = [];
	const seen = new Set<number>();
	const walk = (id: number) => {
		if (seen.has(id)) return;
		seen.add(id);
		const row = certRepo.findById(id);
		if (!row) return;
		out.push(row.cert_pem);
		for (const child of certRepo.listIssuedBy(id)) {
			walk(child.id);
		}
	};
	walk(rootId);
	return out;
}

/**
 * Build a PKCS#12 (.p12 / .pfx) blob for a leaf certificate + its CA chain.
 * Backed by `pkijs` so all key algorithms (RSA, ECDSA P-256/P-384, Ed25519)
 * are supported. Returns a binary DER buffer.
 *
 * If `cert.key_pem` is encrypted, pass `options.keyPassword` to decrypt it
 * before re-wrapping; the on-disk P12's own password is the `password`
 * argument.
 */
export async function buildP12(
	cert: CertRow,
	chain: CertRow[],
	password: string,
	friendlyName?: string,
	options?: {keyPassword?: string | null},
): Promise<Buffer> {
	if (!cert.key_pem) {
		throw new Error('Certificate has no private key — cannot build PKCS#12');
	}
	const plainKeyPem = isEncryptedKey(cert.key_pem)
		? decryptPrivateKey(cert.key_pem, options?.keyPassword ?? null)
		: cert.key_pem;
	return buildP12Pkijs({
		leafCertPem: cert.cert_pem,
		leafPrivateKeyPem: plainKeyPem,
		chainCertPems: chain.map(c => c.cert_pem),
		password,
		friendlyName: friendlyName || cert.name,
	});
}
