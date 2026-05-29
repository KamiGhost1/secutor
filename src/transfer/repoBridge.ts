// repoBridge — converts secutor storage rows ↔ key bundles.
//
// Public surface:
//   exportCert(certId, opts)          → BuiltBundle for a single cert (+ optional parents)
//   exportCertSubtree(caCertId)       → BuiltBundle covering a CA and every descendant
//   exportSshKey(id)                  → BuiltBundle for an SSH key
//   exportProfile(id)                 → BuiltBundle for a P12 profile (DER in payload)
//   importBundle(parsed, opts)        → ImportSummary, mutates the currently open context
//
// Conventions:
//   * Cert fingerprint = SHA-256 of the PEM body's base64-decoded DER.
//     Computed locally so this module does not have to depend on importer.ts'
//     internals — same algorithm though, so two contexts always agree on
//     "is this the same cert?".
//   * `name` collisions are resolved by appending -2, -3, ... .  Same
//     fingerprint never inserts a duplicate; the existing row's metadata is
//     refreshed instead, and an empty key_pem is filled in if the bundle
//     carries one.
//   * Issuer relink happens after every cert row is written, by looking up
//     `meta.issuerFingerprint` against the freshly populated table.

import crypto from 'crypto';
import {
	BundleManifest,
	BundleItem,
	newManifest,
	textToData,
	dataToText,
	bytesToData,
	dataToBytes,
	ParsedBundle,
} from './keyBundle.js';
import {parseCertPem} from '../certs/parser.js';
import {
	certRepo,
	sshKeyRepo,
	profileRepo,
	CertRow,
	CertType,
} from '../storage/repos.js';
import {getDb} from '../storage/db.js';
import Database from 'better-sqlite3';

export type BuiltBundle = {
	manifest: BundleManifest;
	payload: Buffer;
};

/* ────────────────────────── helpers ────────────────────────── */

export function fingerprintOfPem(pem: string): string {
	const body = pem
		.replace(/-----BEGIN [^-]+-----/g, '')
		.replace(/-----END [^-]+-----/g, '')
		.replace(/\s+/g, '');
	const der = Buffer.from(body, 'base64');
	return crypto.createHash('sha256').update(der).digest('hex');
}

function certMeta(row: CertRow): NonNullable<BundleItem['meta']> {
	return {
		name: row.name,
		commonName: row.common_name,
		organization: row.organization,
		type: row.type,
		fingerprint: row.fingerprint,
		san: row.san ? safeParseSan(row.san) : null,
		notBefore: row.not_before,
		notAfter: row.not_after,
		serial: row.serial,
	};
}

function safeParseSan(raw: string): string[] | null {
	try {
		const v = JSON.parse(raw);
		return Array.isArray(v) ? v : null;
	} catch {
		return null;
	}
}

function findByFingerprint(fingerprint: string): CertRow | null {
	const db = getDb();
	return (
		(db.prepare('SELECT * FROM certificates WHERE fingerprint = ?').get(fingerprint) as
			| CertRow
			| undefined) ?? null
	);
}

function uniqueName(suggested: string): string {
	if (!certRepo.findByName(suggested)) return suggested;
	for (let i = 2; i < 10000; i++) {
		const n = `${suggested}-${i}`;
		if (!certRepo.findByName(n)) return n;
	}
	throw new Error(`could not find a free cert name based on "${suggested}"`);
}

function uniqueSshName(suggested: string): string {
	if (!sshKeyRepo.findByName(suggested)) return suggested;
	for (let i = 2; i < 10000; i++) {
		const n = `${suggested}-${i}`;
		if (!sshKeyRepo.findByName(n)) return n;
	}
	throw new Error(`could not find a free ssh name based on "${suggested}"`);
}

function uniqueProfileName(suggested: string): string {
	const db = getDb();
	const row = db.prepare('SELECT id FROM profiles WHERE name = ?').get(suggested);
	if (!row) return suggested;
	for (let i = 2; i < 10000; i++) {
		const n = `${suggested}-${i}`;
		const r = db.prepare('SELECT id FROM profiles WHERE name = ?').get(n);
		if (!r) return n;
	}
	throw new Error(`could not find a free profile name based on "${suggested}"`);
}

function parentsOf(row: CertRow): CertRow[] {
	const chain: CertRow[] = [];
	let cur = row;
	const seen = new Set<number>([cur.id]);
	while (cur.issuer_id != null) {
		const parent = certRepo.findById(cur.issuer_id);
		if (!parent || seen.has(parent.id)) break;
		chain.push(parent);
		seen.add(parent.id);
		cur = parent;
	}
	return chain;
}

function descendantsOf(rootId: number): CertRow[] {
	const out: CertRow[] = [];
	const stack: number[] = [rootId];
	const seen = new Set<number>([rootId]);
	while (stack.length) {
		const cur = stack.pop()!;
		const kids = certRepo.listIssuedBy(cur);
		for (const k of kids) {
			if (seen.has(k.id)) continue;
			seen.add(k.id);
			out.push(k);
			stack.push(k.id);
		}
	}
	return out;
}

/* ────────────────────────── export ────────────────────────── */

export type ExportCertOptions = {
	includeParents?: boolean;
	contextName: string;
};

export function exportCert(certId: number, opts: ExportCertOptions): BuiltBundle {
	const row = certRepo.findById(certId);
	if (!row) throw new Error(`cert id ${certId} not found`);
	const items: BundleItem[] = [];

	items.push({
		role: 'cert',
		encoding: 'pem',
		data: textToData(row.cert_pem),
		meta: certMeta(row),
	});

	if (row.key_pem) {
		const encrypted = /-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(row.key_pem);
		items.push({
			role: 'key',
			encoding: 'pem',
			encrypted,
			data: textToData(row.key_pem),
		});
	}

	let issuerFp: string | null = null;
	if (opts.includeParents) {
		const parents = parentsOf(row);
		for (const p of parents) {
			items.push({
				role: 'parent',
				encoding: 'pem',
				data: textToData(p.cert_pem),
				meta: certMeta(p),
			});
		}
		issuerFp = parents[0]?.fingerprint ?? null;
	} else {
		// Even without bundling parents, hint at the issuer fp so the receiver
		// can relink if they already have the issuer locally.
		if (row.issuer_id != null) {
			const parent = certRepo.findById(row.issuer_id);
			issuerFp = parent?.fingerprint ?? null;
		}
	}

	const kind = row.type === 'ca' ? 'ca' : 'leaf';
	const manifest = newManifest(kind, row.name, opts.contextName, items, {
		fingerprint: row.fingerprint,
		links: {issuerFingerprint: issuerFp},
	});
	return {manifest, payload: Buffer.alloc(0)};
}

export function exportCertSubtree(caCertId: number, opts: {contextName: string}): BuiltBundle {
	const root = certRepo.findById(caCertId);
	if (!root) throw new Error(`cert id ${caCertId} not found`);
	if (root.type !== 'ca') throw new Error(`cert "${root.name}" is not a CA — subtree export N/A`);

	const items: BundleItem[] = [];
	const fps: string[] = [];

	// Root is the first child-list entry, fingerprint-list anchor item.
	items.push({
		role: 'cert',
		encoding: 'pem',
		data: textToData(root.cert_pem),
		meta: {
			...certMeta(root),
			issuerFingerprint: null,
		},
	});
	if (root.key_pem) {
		items.push({
			role: 'key',
			encoding: 'pem',
			encrypted: /-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(root.key_pem),
			data: textToData(root.key_pem),
			meta: {fingerprint: root.fingerprint},
		});
	}
	fps.push(root.fingerprint);

	for (const child of descendantsOf(root.id)) {
		const issuerRow = child.issuer_id != null ? certRepo.findById(child.issuer_id) : null;
		items.push({
			role: 'child',
			encoding: 'pem',
			data: textToData(child.cert_pem),
			meta: {
				...certMeta(child),
				issuerFingerprint: issuerRow?.fingerprint ?? null,
			},
		});
		if (child.key_pem) {
			items.push({
				role: 'key',
				encoding: 'pem',
				encrypted: /-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(child.key_pem),
				data: textToData(child.key_pem),
				meta: {fingerprint: child.fingerprint},
			});
		}
		fps.push(child.fingerprint);
	}

	const manifest = newManifest('subtree', root.name, opts.contextName, items, {
		fingerprint: root.fingerprint,
		links: {subtreeFingerprints: fps},
	});
	return {manifest, payload: Buffer.alloc(0)};
}

export function exportSshKey(id: number, opts: {contextName: string}): BuiltBundle {
	const row = sshKeyRepo.findById(id);
	if (!row) throw new Error(`ssh key id ${id} not found`);
	const items: BundleItem[] = [
		{
			role: 'ssh-pub',
			encoding: 'openssh-v1',
			data: textToData(row.public_key),
			meta: {
				name: row.name,
				algorithm: row.algorithm,
				comment: row.comment,
				fingerprint: row.fingerprint,
			},
		},
		{
			role: 'ssh-priv',
			encoding: 'openssh-v1',
			encrypted: row.encrypted === 1,
			data: textToData(row.private_key),
		},
	];
	const manifest = newManifest('ssh', row.name, opts.contextName, items, {
		fingerprint: row.fingerprint,
	});
	return {manifest, payload: Buffer.alloc(0)};
}

export function exportProfile(id: number, opts: {contextName: string}): BuiltBundle {
	const row = profileRepo.findById(id);
	if (!row) throw new Error(`profile id ${id} not found`);
	const certRow = certRepo.findById(row.cert_id);
	const items: BundleItem[] = [
		{
			role: 'p12',
			encoding: 'pkcs12',
			data: '', // actual bytes ride in payload to keep manifest small
			meta: {
				name: row.name,
				friendlyName: row.friendly_name,
				fingerprint: certRow?.fingerprint,
				commonName: certRow?.common_name,
			},
		},
	];
	const manifest = newManifest('profile', row.name, opts.contextName, items, {
		fingerprint: certRow?.fingerprint,
	});
	return {manifest, payload: Buffer.from(row.data)};
}

/* ────────────────────────── import ────────────────────────── */

export type ImportConflict = {
	kind: 'cert' | 'ssh' | 'profile';
	suggestedName: string;
	reason: string;
};

export type ImportRecord = {
	kind: 'cert' | 'ssh' | 'profile';
	name: string;
	role?: BundleItem['role'];
	fingerprint?: string;
	id?: number;
	outcome: 'inserted' | 'updated' | 'duplicate-skipped';
};

export type ImportSummary = {
	inserted: ImportRecord[];
	updated: ImportRecord[];
	duplicates: ImportRecord[];
	conflicts: ImportConflict[];
	issuerRelinks: number;
};

export type ImportOptions = {
	/** Rename the primary entity. If absent, uses manifest.name. */
	rename?: string;
	/** When true, overwrite an existing key_pem even if non-empty. Default: only fill in if empty. */
	overwriteKey?: boolean;
};

export function importBundle(
	parsed: ParsedBundle,
	opts: ImportOptions = {},
): ImportSummary {
	const summary: ImportSummary = {
		inserted: [],
		updated: [],
		duplicates: [],
		conflicts: [],
		issuerRelinks: 0,
	};

	const db = getDb();
	const tx = db.transaction(() => {
		switch (parsed.manifest.kind) {
			case 'leaf':
			case 'ca':
				importLeafOrCa(parsed.manifest, opts, summary);
				break;
			case 'subtree':
				importSubtree(parsed.manifest, opts, summary);
				break;
			case 'ssh':
				importSsh(parsed.manifest, opts, summary);
				break;
			case 'profile':
				importProfile(parsed.manifest, parsed.payload, opts, summary);
				break;
			default:
				throw new Error(`unknown bundle kind: ${(parsed.manifest as any).kind}`);
		}
	});
	tx();

	return summary;
}

function importLeafOrCa(
	manifest: BundleManifest,
	opts: ImportOptions,
	summary: ImportSummary,
): void {
	const certItem = manifest.items.find(i => i.role === 'cert');
	if (!certItem) throw new Error('bundle missing required "cert" item');
	const keyItem = manifest.items.find(i => i.role === 'key');
	const parentItems = manifest.items.filter(i => i.role === 'parent');

	// Insert parents first so the leaf can relink against them.
	for (const p of parentItems) {
		insertCertItem(p, /* fallbackName */ p.meta?.name ?? 'imported-ca', 'ca', summary);
	}

	const suggestedName = opts.rename ?? manifest.name;
	const targetType = (manifest.kind === 'ca' ? 'ca' : certItem.meta?.type ?? 'server') as CertType;
	const insertedId = insertCertItem(
		certItem,
		suggestedName,
		targetType,
		summary,
		keyItem,
		opts.overwriteKey,
	);

	// Relink issuer for the primary cert.
	const issuerFp =
		certItem.meta?.issuerFingerprint ?? manifest.links?.issuerFingerprint ?? null;
	if (issuerFp && insertedId != null) {
		const issuer = findByFingerprint(issuerFp);
		if (issuer) {
			certRepo.relinkIssuer(insertedId, issuer.id);
			summary.issuerRelinks++;
		}
	}
	// And for any imported parents — chain them up.
	for (const p of parentItems) {
		const fp = p.meta?.fingerprint;
		const issuerFp2 = p.meta?.issuerFingerprint ?? null;
		if (!fp || !issuerFp2) continue;
		const row = findByFingerprint(fp);
		if (!row) continue;
		const issuer = findByFingerprint(issuerFp2);
		if (issuer) {
			certRepo.relinkIssuer(row.id, issuer.id);
			summary.issuerRelinks++;
		}
	}
}

function importSubtree(
	manifest: BundleManifest,
	opts: ImportOptions,
	summary: ImportSummary,
): void {
	// Items come root-first. We insert in two passes:
	//   1. Cert items (cert | child) — placeholders for the chain.
	//   2. Key items — attached to their owning cert by fingerprint.
	// Then we run relinking against meta.issuerFingerprint.
	const certItems = manifest.items.filter(i => i.role === 'cert' || i.role === 'child');
	const keyItems = manifest.items.filter(i => i.role === 'key');

	// Build a fingerprint→key map so we can attach keys without relying on order.
	const keysByFp = new Map<string, BundleItem>();
	for (const k of keyItems) {
		const fp = k.meta?.fingerprint;
		if (fp) keysByFp.set(fp, k);
	}

	for (const ci of certItems) {
		const fp = ci.meta?.fingerprint;
		const matchingKey = fp ? keysByFp.get(fp) : undefined;
		insertCertItem(
			ci,
			ci.meta?.name ?? 'imported',
			(ci.meta?.type ?? 'server') as CertType,
			summary,
			matchingKey,
			opts.overwriteKey,
		);
	}

	// Pass 2: relink issuer relationships for every cert we just touched.
	for (const ci of certItems) {
		const fp = ci.meta?.fingerprint;
		const issuerFp = ci.meta?.issuerFingerprint ?? null;
		if (!fp || !issuerFp) continue;
		const child = findByFingerprint(fp);
		const parent = findByFingerprint(issuerFp);
		if (child && parent && child.issuer_id !== parent.id) {
			certRepo.relinkIssuer(child.id, parent.id);
			summary.issuerRelinks++;
		}
	}
}

function importSsh(
	manifest: BundleManifest,
	opts: ImportOptions,
	summary: ImportSummary,
): void {
	const pub = manifest.items.find(i => i.role === 'ssh-pub');
	const priv = manifest.items.find(i => i.role === 'ssh-priv');
	if (!pub || !priv) throw new Error('SSH bundle missing pub/priv item');

	const fingerprint = pub.meta?.fingerprint ?? '';
	if (fingerprint) {
		const existing = sshKeyRepo
			.list()
			.find(r => r.fingerprint === fingerprint);
		if (existing) {
			summary.duplicates.push({
				kind: 'ssh',
				name: existing.name,
				fingerprint,
				id: existing.id,
				outcome: 'duplicate-skipped',
			});
			return;
		}
	}

	const suggestedName = opts.rename ?? manifest.name;
	const finalName = uniqueSshName(suggestedName);
	if (finalName !== suggestedName) {
		summary.conflicts.push({
			kind: 'ssh',
			suggestedName,
			reason: `name in use; imported as "${finalName}"`,
		});
	}
	const id = sshKeyRepo.insert({
		name: finalName,
		algorithm: pub.meta?.algorithm ?? 'unknown',
		comment: pub.meta?.comment ?? null,
		public_key: dataToText(pub.data),
		private_key: dataToText(priv.data),
		encrypted: priv.encrypted ? 1 : 0,
		fingerprint,
	});
	summary.inserted.push({
		kind: 'ssh',
		name: finalName,
		fingerprint,
		id,
		outcome: 'inserted',
	});
}

function importProfile(
	manifest: BundleManifest,
	payload: Buffer,
	opts: ImportOptions,
	summary: ImportSummary,
): void {
	const item = manifest.items.find(i => i.role === 'p12');
	if (!item) throw new Error('profile bundle missing p12 item');
	if (!payload || payload.length === 0) {
		throw new Error('profile bundle has no payload bytes');
	}

	const suggestedName = opts.rename ?? manifest.name;
	const finalName = uniqueProfileName(suggestedName);
	if (finalName !== suggestedName) {
		summary.conflicts.push({
			kind: 'profile',
			suggestedName,
			reason: `name in use; imported as "${finalName}"`,
		});
	}

	// Profiles need a cert row to attach to. If the bundle hints at a cert
	// fingerprint and we have it locally, link there; otherwise we can't store
	// the profile in a meaningful way (CASCADE FK).
	const fp = item.meta?.fingerprint;
	const certRow = fp ? findByFingerprint(fp) : null;
	if (!certRow) {
		throw new Error(
			'profile bundle references a certificate (fingerprint ' +
				(fp ?? '?') +
				') not present in target context — import the cert first',
		);
	}

	const id = profileRepo.insert({
		name: finalName,
		cert_id: certRow.id,
		format: 'p12',
		friendly_name: item.meta?.friendlyName ?? null,
		data: payload,
	});
	summary.inserted.push({
		kind: 'profile',
		name: finalName,
		fingerprint: fp,
		id,
		outcome: 'inserted',
	});
}

/**
 * Insert (or merge) a single cert PEM item, optionally with a matching key.
 * Returns the row id, or null on duplicate-skip.
 */
function insertCertItem(
	certItem: BundleItem,
	suggestedName: string,
	defaultType: CertType,
	summary: ImportSummary,
	keyItem?: BundleItem,
	overwriteKey?: boolean,
): number | null {
	const pem = dataToText(certItem.data);
	const fingerprint = fingerprintOfPem(pem);
	const metaFp = certItem.meta?.fingerprint;
	if (metaFp && metaFp !== fingerprint) {
		throw new Error(
			`bundle integrity check failed for "${suggestedName}": meta fingerprint ${metaFp} ≠ computed ${fingerprint}`,
		);
	}

	const existing = findByFingerprint(fingerprint);
	if (existing) {
		// Same cert already present. Optionally fill in a missing key.
		if (keyItem && (!existing.key_pem || overwriteKey)) {
			updateKeyPem(existing.id, dataToText(keyItem.data));
			summary.updated.push({
				kind: 'cert',
				name: existing.name,
				fingerprint,
				id: existing.id,
				outcome: 'updated',
			});
		} else {
			summary.duplicates.push({
				kind: 'cert',
				name: existing.name,
				fingerprint,
				id: existing.id,
				outcome: 'duplicate-skipped',
			});
		}
		return existing.id;
	}

	const parsed = parseCertPem(pem);
	const finalName = uniqueName(suggestedName);
	if (finalName !== suggestedName) {
		summary.conflicts.push({
			kind: 'cert',
			suggestedName,
			reason: `name in use; imported as "${finalName}"`,
		});
	}
	const id = certRepo.insert({
		name: finalName,
		type: defaultType,
		common_name: parsed.subject['commonName'] || '',
		organization: parsed.subject['organizationName'] ?? null,
		issuer_id: null,
		serial: parsed.serial,
		not_before: parsed.notBefore.toISOString(),
		not_after: parsed.notAfter.toISOString(),
		san: parsed.sans.length ? JSON.stringify(parsed.sans) : null,
		cert_pem: pem,
		key_pem: keyItem ? dataToText(keyItem.data) : '',
		fingerprint,
	});
	summary.inserted.push({
		kind: 'cert',
		name: finalName,
		role: certItem.role,
		fingerprint,
		id,
		outcome: 'inserted',
	});
	return id;
}

function updateKeyPem(id: number, keyPem: string): void {
	const db = getDb();
	db.prepare('UPDATE certificates SET key_pem = ? WHERE id = ?').run(keyPem, id);
}

/* ────────────────────────── for tests / external callers ────────────────────────── */

/** Convenience: count how many active leaves exist for a CA (used by subtree previews). */
export function subtreeCount(caId: number): number {
	return descendantsOf(caId).length + 1;
}

/** Convenience: get the open DB. Lets unit tests assert on raw rows. */
export function debugDb(): Database.Database {
	return getDb();
}
