import crypto from 'crypto';
import forge from 'node-forge';
import {CertRow, CertType} from '../storage/repos.js';
import {parseCertCompat} from './manualBuilder.js';
import {isEncryptedKey} from './keys.js';

export type FindingKind =
	| 'parse-error'
	| 'key-mismatch'
	| 'meta-drift'
	| 'issuer-not-set'
	| 'issuer-missing'
	| 'issuer-dn-mismatch'
	| 'signature-invalid'
	| 'expired'
	| 'not-yet-valid';

export type Severity = 'error' | 'warn' | 'info';

export type DerivedMeta = {
	common_name: string;
	organization: string | null;
	serial: string;
	not_before: string;
	not_after: string;
	san: string | null;
	fingerprint: string;
};

export type Fix =
	| {kind: 'refresh-meta'; metadata: DerivedMeta}
	| {kind: 'relink-issuer'; newIssuerId: number | null; newIssuerName?: string};

export type Finding = {
	certId: number;
	certName: string;
	certType: CertType;
	kind: FindingKind;
	severity: Severity;
	message: string;
	detail?: string;
	fix?: Fix;
};

export type AuditReport = {
	findings: Finding[];
	scanned: number;
	byCert: Map<number, Finding[]>;
};

function derive(certPem: string): DerivedMeta | null {
	let cert: forge.pki.Certificate;
	try {
		cert = parseCertCompat(certPem).cert;
	} catch {
		return null;
	}
	const cn = cert.subject.attributes.find(a => a.name === 'commonName');
	const org = cert.subject.attributes.find(a => a.name === 'organizationName');
	const sansExt = cert.getExtension('subjectAltName') as
		| {altNames?: Array<{type: number; value?: string; ip?: string}>}
		| undefined;
	const sans: string[] = [];
	if (sansExt?.altNames) {
		for (const n of sansExt.altNames) {
			if (n.type === 2 && n.value) sans.push(n.value);
			else if (n.type === 7 && n.ip) sans.push(n.ip);
		}
	}
	// Fingerprint over the original DER (not the dummy-key version forge sees
	// after compat-parsing), so non-RSA certs hash correctly.
	const originalDer = pemToDer(certPem);
	const fp = crypto.createHash('sha256').update(originalDer).digest('hex');
	return {
		common_name: cn ? String(cn.value) : '',
		organization: org ? String(org.value) : null,
		serial: cert.serialNumber,
		not_before: cert.validity.notBefore.toISOString(),
		not_after: cert.validity.notAfter.toISOString(),
		san: sans.length ? JSON.stringify(sans) : null,
		fingerprint: fp,
	};
}

function pemToDer(pem: string): Buffer {
	const body = pem
		.replace(/-----BEGIN [^-]+-----/g, '')
		.replace(/-----END [^-]+-----/g, '')
		.replace(/\s+/g, '');
	return Buffer.from(body, 'base64');
}

function dnDer(name: {attributes: forge.pki.CertificateField[]}): string | null {
	try {
		return forge.asn1
			.toDer(forge.pki.distinguishedNameToAsn1(name as any))
			.getBytes();
	} catch {
		return null;
	}
}

function caSignsLeaf(caCertPem: string, leafCertPem: string): boolean {
	// Use node:crypto X509 verification — works for RSA, ECDSA and Ed25519.
	try {
		const ca = new crypto.X509Certificate(caCertPem);
		const leaf = new crypto.X509Certificate(leafCertPem);
		return leaf.verify(ca.publicKey);
	} catch {
		return false;
	}
}

function keyMatchesCert(keyPem: string, certPem: string): boolean {
	if (!keyPem) return true;
	// Encrypted private key in the DB can't be matched without its passphrase;
	// treat as a non-finding (we can't say it's wrong, and we can't prove it's
	// right). The dedicated unlock flow validates on use.
	if (isEncryptedKey(keyPem)) return true;
	try {
		const priv = crypto.createPrivateKey(keyPem);
		const certPub = new crypto.X509Certificate(certPem).publicKey;
		const privPub = crypto.createPublicKey(priv);
		const a = privPub.export({type: 'spki', format: 'der'}) as Buffer;
		const b = certPub.export({type: 'spki', format: 'der'}) as Buffer;
		return a.equals(b);
	} catch {
		return false;
	}
}

function sameInstantSec(a: string, b: string): boolean {
	const ta = Math.floor(Date.parse(a) / 1000);
	const tb = Math.floor(Date.parse(b) / 1000);
	if (Number.isNaN(ta) || Number.isNaN(tb)) return a === b;
	return ta === tb;
}

function metaDriftDetail(row: CertRow, derived: DerivedMeta): string | null {
	const diffs: string[] = [];
	const cmp: Array<[keyof DerivedMeta, string | null]> = [
		['common_name', row.common_name ?? ''],
		['organization', row.organization],
		['serial', row.serial],
		['san', row.san],
		['fingerprint', row.fingerprint],
	];
	for (const [field, dbVal] of cmp) {
		const newVal = derived[field] as string | null;
		if ((dbVal ?? '') !== (newVal ?? '')) {
			diffs.push(`${field}: "${dbVal ?? ''}" → "${newVal ?? ''}"`);
		}
	}
	// X.509 UTCTime has only second precision; tolerate sub-second drift on
	// validity timestamps to avoid false positives from PEM round-trips.
	if (!sameInstantSec(row.not_before, derived.not_before)) {
		diffs.push(`not_before: "${row.not_before}" → "${derived.not_before}"`);
	}
	if (!sameInstantSec(row.not_after, derived.not_after)) {
		diffs.push(`not_after: "${row.not_after}" → "${derived.not_after}"`);
	}
	return diffs.length ? diffs.join('; ') : null;
}

function findCandidateIssuer(
	leafPem: string,
	cas: CertRow[],
	excludeId?: number,
): CertRow | null {
	let leaf: forge.pki.Certificate;
	try {
		leaf = parseCertCompat(leafPem).cert;
	} catch {
		return null;
	}
	const leafIssuerDer = dnDer(leaf.issuer);
	if (leafIssuerDer === null) return null;
	for (const ca of cas) {
		if (excludeId !== undefined && ca.id === excludeId) continue;
		try {
			const caCert = parseCertCompat(ca.cert_pem).cert;
			const caSubjDer = dnDer(caCert.subject);
			if (caSubjDer === null || caSubjDer !== leafIssuerDer) continue;
			if (caSignsLeaf(ca.cert_pem, leafPem)) return ca;
		} catch {
			continue;
		}
	}
	return null;
}

function isSelfSigned(certPem: string): boolean {
	try {
		const c = parseCertCompat(certPem).cert;
		const a = dnDer(c.subject);
		const b = dnDer(c.issuer);
		return a !== null && b !== null && a === b;
	} catch {
		return false;
	}
}

export function auditCertificates(rows: CertRow[]): AuditReport {
	const findings: Finding[] = [];
	const byId = new Map<number, CertRow>();
	for (const r of rows) byId.set(r.id, r);
	const cas = rows.filter(r => r.type === 'ca');
	const now = Date.now();

	const push = (f: Finding) => findings.push(f);

	for (const row of rows) {
		const derived = derive(row.cert_pem);

		if (!derived) {
			push({
				certId: row.id,
				certName: row.name,
				certType: row.type,
				kind: 'parse-error',
				severity: 'error',
				message: `PEM is not parseable as X.509`,
			});
			continue;
		}

		if (!keyMatchesCert(row.key_pem || '', row.cert_pem)) {
			push({
				certId: row.id,
				certName: row.name,
				certType: row.type,
				kind: 'key-mismatch',
				severity: 'error',
				message: `Stored private key does not match the certificate`,
			});
		}

		const drift = metaDriftDetail(row, derived);
		if (drift) {
			push({
				certId: row.id,
				certName: row.name,
				certType: row.type,
				kind: 'meta-drift',
				severity: 'warn',
				message: 'DB metadata diverged from the PEM',
				detail: drift,
				fix: {kind: 'refresh-meta', metadata: derived},
			});
		}

		const selfSigned = isSelfSigned(row.cert_pem);
		const expectsParent = !(row.type === 'ca' && selfSigned);

		if (expectsParent && row.issuer_id === null) {
			const candidate = findCandidateIssuer(row.cert_pem, cas, row.id);
			push({
				certId: row.id,
				certName: row.name,
				certType: row.type,
				kind: 'issuer-not-set',
				severity: 'error',
				message: 'No issuer linked in the DB but the cert is not self-signed',
				fix: candidate
					? {
							kind: 'relink-issuer',
							newIssuerId: candidate.id,
							newIssuerName: candidate.name,
					  }
					: undefined,
			});
		} else if (row.issuer_id !== null) {
			const parent = byId.get(row.issuer_id);
			if (!parent) {
				const candidate = findCandidateIssuer(row.cert_pem, cas, row.id);
				push({
					certId: row.id,
					certName: row.name,
					certType: row.type,
					kind: 'issuer-missing',
					severity: 'error',
					message: `Issuer link points to a missing row (id=${row.issuer_id})`,
					fix: candidate
						? {
								kind: 'relink-issuer',
								newIssuerId: candidate.id,
								newIssuerName: candidate.name,
						  }
						: {kind: 'relink-issuer', newIssuerId: null},
				});
			} else {
				let parentCert: forge.pki.Certificate | null = null;
				try {
					parentCert = parseCertCompat(parent.cert_pem).cert;
				} catch {}

				let leafCert: forge.pki.Certificate | null = null;
				try {
					leafCert = parseCertCompat(row.cert_pem).cert;
				} catch {}

				const parentSubj = parentCert ? dnDer(parentCert.subject) : null;
				const leafIss = leafCert ? dnDer(leafCert.issuer) : null;
				const dnMatch =
					parentSubj !== null && leafIss !== null && parentSubj === leafIss;

				if (!dnMatch) {
					const candidate = findCandidateIssuer(row.cert_pem, cas, row.id);
					push({
						certId: row.id,
						certName: row.name,
						certType: row.type,
						kind: 'issuer-dn-mismatch',
						severity: 'error',
						message: `Linked CA "${parent.name}" subject does not match this cert's issuer`,
						fix: candidate
							? {
									kind: 'relink-issuer',
									newIssuerId: candidate.id,
									newIssuerName: candidate.name,
							  }
							: undefined,
					});
				} else if (!caSignsLeaf(parent.cert_pem, row.cert_pem)) {
					const candidate = findCandidateIssuer(row.cert_pem, cas, row.id);
					push({
						certId: row.id,
						certName: row.name,
						certType: row.type,
						kind: 'signature-invalid',
						severity: 'error',
						message: `Linked CA "${parent.name}" does not actually sign this cert`,
						fix:
							candidate && candidate.id !== parent.id
								? {
										kind: 'relink-issuer',
										newIssuerId: candidate.id,
										newIssuerName: candidate.name,
								  }
								: undefined,
					});
				}
			}
		}

		const notAfter = Date.parse(derived.not_after);
		const notBefore = Date.parse(derived.not_before);
		if (Number.isFinite(notAfter) && notAfter < now) {
			push({
				certId: row.id,
				certName: row.name,
				certType: row.type,
				kind: 'expired',
				severity: 'warn',
				message: `Expired on ${derived.not_after.slice(0, 10)}`,
			});
		} else if (Number.isFinite(notBefore) && notBefore > now) {
			push({
				certId: row.id,
				certName: row.name,
				certType: row.type,
				kind: 'not-yet-valid',
				severity: 'info',
				message: `Not yet valid (starts ${derived.not_before.slice(0, 10)})`,
			});
		}
	}

	const byCert = new Map<number, Finding[]>();
	for (const f of findings) {
		const list = byCert.get(f.certId) || [];
		list.push(f);
		byCert.set(f.certId, list);
	}

	return {findings, scanned: rows.length, byCert};
}

export function severityWeight(s: Severity): number {
	if (s === 'error') return 0;
	if (s === 'warn') return 1;
	return 2;
}

export function sortFindings(findings: Finding[]): Finding[] {
	return [...findings].sort((a, b) => {
		const sw = severityWeight(a.severity) - severityWeight(b.severity);
		if (sw !== 0) return sw;
		if (a.certName !== b.certName) return a.certName.localeCompare(b.certName);
		return a.kind.localeCompare(b.kind);
	});
}
