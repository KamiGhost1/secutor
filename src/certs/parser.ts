import forge from 'node-forge';
import {parseCertCompat} from './manualBuilder.js';

export type ParsedCert = {
	subject: Record<string, string>;
	issuer: Record<string, string>;
	serial: string;
	notBefore: Date;
	notAfter: Date;
	sans: string[];
	isCA: boolean;
	keyUsage: string[];
	extKeyUsage: string[];
	signatureAlgorithm: string;
};

function attrsToObj(
	attrs: forge.pki.CertificateField[],
): Record<string, string> {
	const out: Record<string, string> = {};
	for (const a of attrs) {
		const k = a.name || a.shortName || '';
		if (k) out[k] = String(a.value);
	}
	return out;
}

export function parseCertPem(pem: string): ParsedCert {
	// `parseCertCompat` falls back to a SPKI swap so ECDSA / Ed25519 certs
	// (which forge can't natively parse) yield a usable forge Certificate
	// object — every field except `publicKey` is correct.
	const {cert} = parseCertCompat(pem);
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
	const bc = cert.getExtension('basicConstraints') as
		| {cA?: boolean}
		| undefined;
	const ku = cert.getExtension('keyUsage') as
		| Record<string, boolean>
		| undefined;
	const eku = cert.getExtension('extKeyUsage') as
		| Record<string, boolean>
		| undefined;

	const keyUsage: string[] = [];
	if (ku) {
		for (const [k, v] of Object.entries(ku)) {
			if (v === true && k !== 'name' && k !== 'id') keyUsage.push(k);
		}
	}
	const extKeyUsage: string[] = [];
	if (eku) {
		for (const [k, v] of Object.entries(eku)) {
			if (v === true && k !== 'name' && k !== 'id') extKeyUsage.push(k);
		}
	}

	return {
		subject: attrsToObj(cert.subject.attributes),
		issuer: attrsToObj(cert.issuer.attributes),
		serial: cert.serialNumber,
		notBefore: cert.validity.notBefore,
		notAfter: cert.validity.notAfter,
		sans,
		isCA: !!bc?.cA,
		keyUsage,
		extKeyUsage,
		signatureAlgorithm: cert.siginfo?.algorithmOid || '',
	};
}
