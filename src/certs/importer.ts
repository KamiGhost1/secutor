import fs from 'fs';
import crypto from 'crypto';
import forge from 'node-forge';
import {parseCertPem, ParsedCert} from './parser.js';
import {parseP12} from './p12.js';
import {certRepo, profileRepo, CertType, CertRow} from '../storage/repos.js';

export type ImportedCert = {
	pem: string;
	parsed: ParsedCert;
	fingerprint: string;
	suggestedType: CertType;
};

export type ImportedKey = {
	pem: string;
};

export type ImportSource = 'pem' | 'pkcs12';

export type ImportResult = {
	source: ImportSource;
	certs: ImportedCert[]; // [leaf, ...intermediates, root?]
	key: ImportedKey | null;
};

export function detectFormat(buf: Buffer): ImportSource {
	// PEM files may have metadata (Bag Attributes, subject=, issuer=, comments)
	// before the first -----BEGIN marker, so check a generous prefix, not just 64 bytes.
	// PKCS12/DER is binary and starts with ASN.1 SEQUENCE (0x30).
	const sampleSize = Math.min(buf.length, 16384);
	const sample = buf.subarray(0, sampleSize).toString('utf8');
	if (sample.includes('-----BEGIN ')) return 'pem';
	return 'pkcs12';
}

function fingerprintOfPem(pem: string): string {
	// Hash the original DER — going through forge breaks non-RSA certs.
	const body = pem
		.replace(/-----BEGIN [^-]+-----/g, '')
		.replace(/-----END [^-]+-----/g, '')
		.replace(/\s+/g, '');
	const der = Buffer.from(body, 'base64');
	return crypto.createHash('sha256').update(der).digest('hex');
}

function classify(parsed: ParsedCert): CertType {
	if (parsed.isCA) return 'ca';
	if (parsed.extKeyUsage.includes('serverAuth')) return 'server';
	if (parsed.extKeyUsage.includes('clientAuth')) return 'client';
	return 'server';
}

export function parsePem(text: string): ImportResult {
	const certBlocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
	const keyMatch =
		text.match(/-----BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (RSA |EC |ENCRYPTED )?PRIVATE KEY-----/);

	if (certBlocks.length === 0 && !keyMatch) {
		throw new Error('PEM не содержит ни сертификата, ни ключа');
	}

	const certs: ImportedCert[] = certBlocks.map(pem => {
		const parsed = parseCertPem(pem);
		return {
			pem,
			parsed,
			fingerprint: fingerprintOfPem(pem),
			suggestedType: classify(parsed),
		};
	});

	let key: ImportedKey | null = null;
	if (keyMatch) key = {pem: keyMatch[0]};

	return {source: 'pem', certs: orderChain(certs), key};
}

/**
 * Parse a PKCS#12 (.p12 / .pfx) blob. Algorithm-agnostic via `pkijs` —
 * accepts files produced by openssl, forge, browsers, or this app, with any
 * key algorithm (RSA / ECDSA / Ed25519).
 *
 * Returns a structurally identical `ImportResult` to `parsePem` so callers
 * upstream don't need to branch.
 */
export async function parsePkcs12(buf: Buffer, password: string): Promise<ImportResult> {
	let parsed;
	try {
		parsed = await parseP12(buf, password);
	} catch (err: any) {
		// Forge has wider tolerance for some old/quirky P12s (RC2-40, very old
		// MAC algorithms). If pkijs refuses, try forge as a fallback for
		// RSA-only inputs.
		try {
			return parsePkcs12Forge(buf, password);
		} catch {
			throw new Error(err?.message ?? String(err));
		}
	}

	const certs: ImportedCert[] = parsed.certPems.map(pem => {
		const p = parseCertPem(pem);
		return {
			pem,
			parsed: p,
			fingerprint: fingerprintOfPem(pem),
			suggestedType: classify(p),
		};
	});

	const key: ImportedKey | null = parsed.privateKeyPem ? {pem: parsed.privateKeyPem} : null;

	if (certs.length === 0 && !key) {
		throw new Error('PKCS#12 не содержит ни сертификата, ни ключа');
	}

	return {source: 'pkcs12', certs: orderChain(certs), key};
}

/** Legacy forge-backed P12 reader; used only as a fallback for RSA-only inputs that pkijs can't parse. */
function parsePkcs12Forge(buf: Buffer, password: string): ImportResult {
	const der = forge.util.createBuffer(buf.toString('binary'));
	const asn1 = forge.asn1.fromDer(der);
	const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, false, password);

	const certBags = p12.getBags({bagType: forge.pki.oids.certBag})[forge.pki.oids.certBag] || [];
	const keyBags = [
		...((p12.getBags({bagType: forge.pki.oids.pkcs8ShroudedKeyBag})[forge.pki.oids.pkcs8ShroudedKeyBag]) || []),
		...((p12.getBags({bagType: forge.pki.oids.keyBag})[forge.pki.oids.keyBag]) || []),
	];

	const certs: ImportedCert[] = certBags
		.filter(b => b.cert)
		.map(b => {
			const pem = forge.pki.certificateToPem(b.cert!);
			const parsed = parseCertPem(pem);
			return {
				pem,
				parsed,
				fingerprint: fingerprintOfPem(pem),
				suggestedType: classify(parsed),
			};
		});

	let key: ImportedKey | null = null;
	if (keyBags.length && keyBags[0].key) {
		key = {pem: forge.pki.privateKeyToPem(keyBags[0].key)};
	}

	if (certs.length === 0 && !key) {
		throw new Error('PKCS#12 не содержит ни сертификата, ни ключа');
	}

	return {source: 'pkcs12', certs: orderChain(certs), key};
}

function orderChain(certs: ImportedCert[]): ImportedCert[] {
	if (certs.length <= 1) return certs;
	const bySubject = new Map<string, ImportedCert>();
	const byIssuer = new Map<string, ImportedCert[]>();
	for (const c of certs) {
		const subj = JSON.stringify(c.parsed.subject);
		const iss = JSON.stringify(c.parsed.issuer);
		bySubject.set(subj, c);
		const list = byIssuer.get(iss) || [];
		list.push(c);
		byIssuer.set(iss, list);
	}
	// Find leaf: cert whose subject is no one's issuer
	const leaf =
		certs.find(c => {
			const subj = JSON.stringify(c.parsed.subject);
			return !certs.some(o => o !== c && JSON.stringify(o.parsed.issuer) === subj);
		}) ?? certs[0];

	const ordered: ImportedCert[] = [leaf];
	let cur: ImportedCert | undefined = leaf;
	const seen = new Set([leaf.fingerprint]);
	while (cur) {
		const issStr = JSON.stringify(cur.parsed.issuer);
		const issuer = bySubject.get(issStr);
		if (!issuer || seen.has(issuer.fingerprint) || issuer === cur) break;
		ordered.push(issuer);
		seen.add(issuer.fingerprint);
		cur = issuer;
	}
	for (const c of certs) {
		if (!seen.has(c.fingerprint)) ordered.push(c);
	}
	return ordered;
}

export async function readImport(filePath: string, password?: string): Promise<ImportResult> {
	const buf = fs.readFileSync(filePath);
	const fmt = detectFormat(buf);
	if (fmt === 'pem') return parsePem(buf.toString('utf8'));
	if (!password) throw new Error('Для PKCS#12 требуется пароль');
	return parsePkcs12(buf, password);
}

export function findCertByFingerprint(fingerprint: string): CertRow | null {
	const all = certRepo.list();
	return all.find(r => r.fingerprint === fingerprint) || null;
}

export type SaveImportOptions = {
	leafName: string;
	leafType: CertType;
	leafKeyPem: string | null;
	chainAsCAs: boolean;
	issuerCertId: number | null;
};

export function saveImport(
	result: ImportResult,
	opts: SaveImportOptions,
): {leafId: number; chainIds: number[]} {
	if (!result.certs.length) throw new Error('Нет сертификатов для сохранения');

	const chainIds: number[] = [];
	let parentId: number | null = opts.issuerCertId;

	if (opts.chainAsCAs && result.certs.length > 1) {
		const intermediates = result.certs.slice(1);
		// import from root downwards, so each child gets the right issuer_id
		for (const c of [...intermediates].reverse()) {
			const exists = findCertByFingerprint(c.fingerprint);
			if (exists) {
				chainIds.unshift(exists.id);
				parentId = exists.id;
				continue;
			}
			const id = certRepo.insert({
				name: makeUniqueName(c.parsed.subject.commonName || 'imported-ca'),
				type: 'ca',
				common_name: c.parsed.subject.commonName || '',
				organization: c.parsed.subject.organizationName || null,
				issuer_id: parentId,
				serial: c.parsed.serial,
				not_before: c.parsed.notBefore.toISOString(),
				not_after: c.parsed.notAfter.toISOString(),
				san: c.parsed.sans.length ? JSON.stringify(c.parsed.sans) : null,
				cert_pem: c.pem,
				key_pem: '',
				fingerprint: c.fingerprint,
			});
			chainIds.unshift(id);
			parentId = id;
		}
	}

	const leaf = result.certs[0];
	const existingLeaf = findCertByFingerprint(leaf.fingerprint);
	if (existingLeaf) {
		throw new Error(`Сертификат уже импортирован: "${existingLeaf.name}"`);
	}
	const leafId = certRepo.insert({
		name: opts.leafName,
		type: opts.leafType,
		common_name: leaf.parsed.subject.commonName || '',
		organization: leaf.parsed.subject.organizationName || null,
		issuer_id: parentId,
		serial: leaf.parsed.serial,
		not_before: leaf.parsed.notBefore.toISOString(),
		not_after: leaf.parsed.notAfter.toISOString(),
		san: leaf.parsed.sans.length ? JSON.stringify(leaf.parsed.sans) : null,
		cert_pem: leaf.pem,
		key_pem: opts.leafKeyPem || result.key?.pem || '',
		fingerprint: leaf.fingerprint,
	});

	return {leafId, chainIds};
}

function makeUniqueName(base: string): string {
	const safe = base.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 40) || 'imported';
	if (!certRepo.findByName(safe)) return safe;
	for (let i = 2; i < 1000; i++) {
		const n = `${safe}-${i}`;
		if (!certRepo.findByName(n)) return n;
	}
	return `${safe}-${Date.now()}`;
}

export function saveProfileFromFile(opts: {
	name: string;
	friendlyName: string | null;
	filePath: string;
	certId: number;
}): number {
	const data = fs.readFileSync(opts.filePath);
	return profileRepo.insert({
		name: opts.name,
		cert_id: opts.certId,
		format: 'p12',
		friendly_name: opts.friendlyName,
		data,
	});
}
