import crypto from 'crypto';
import forge from 'node-forge';
import {certRepo, CertRow} from '../storage/repos.js';
import {parseCertCompat} from './manualBuilder.js';

export type VerifyResult = {
	ok: boolean;
	reason?: string;
	chain: string[];
	notBefore: Date;
	notAfter: Date;
	expired: boolean;
	notYetValid: boolean;
	revoked: boolean;
	revokedAt?: string;
	revocationReason?: string;
	revokedAncestor?: string;
	sni?: {requested: string; matched: boolean};
};

export function verifyCertById(id: number, sni?: string): VerifyResult {
	const row = certRepo.findById(id);
	if (!row) {
		return {
			ok: false,
			reason: 'Certificate not found',
			chain: [],
			notBefore: new Date(),
			notAfter: new Date(),
			expired: false,
			notYetValid: false,
			revoked: false,
		};
	}
	return verifyCert(row, sni);
}

/**
 * Cryptographically verify a single cert chain link with `node:crypto`.
 * Works for RSA, ECDSA P-256/P-384 and Ed25519 — unlike forge, which only
 * supports RSA.
 */
function caSignsLeaf(parentPem: string, leafPem: string): {ok: boolean; reason?: string} {
	try {
		const parent = new crypto.X509Certificate(parentPem);
		const leaf = new crypto.X509Certificate(leafPem);
		// X509Certificate.verify(key) checks that `leaf` was signed by `key`.
		const ok = leaf.verify(parent.publicKey);
		return ok ? {ok: true} : {ok: false, reason: `signature does not verify against "${parent.subject}"`};
	} catch (err: any) {
		return {ok: false, reason: err?.message ?? 'chain verification failed'};
	}
}

export function verifyCert(row: CertRow, sni?: string): VerifyResult {
	// Use parseCertCompat so ECDSA / Ed25519 leaf certs (which forge can't
	// natively parse) still yield a usable forge Certificate for metadata.
	const cert = parseCertCompat(row.cert_pem).cert;
	const now = new Date();
	const expired = now > cert.validity.notAfter;
	const notYetValid = now < cert.validity.notBefore;

	const chainNames: string[] = [row.common_name];
	const chainRows: CertRow[] = [row];
	let cur: CertRow | null = row;
	const safety = new Set<number>();
	let revokedAncestor: string | undefined;

	while (cur && cur.issuer_id && !safety.has(cur.issuer_id)) {
		safety.add(cur.issuer_id);
		const parent = certRepo.findById(cur.issuer_id);
		if (!parent) {
			return {
				ok: false,
				reason: `Missing issuer (id=${cur.issuer_id})`,
				chain: chainNames,
				notBefore: cert.validity.notBefore,
				notAfter: cert.validity.notAfter,
				expired,
				notYetValid,
				revoked: !!row.revoked_at,
				revokedAt: row.revoked_at ?? undefined,
				revocationReason: row.revocation_reason ?? undefined,
			};
		}
		chainNames.push(parent.common_name);
		chainRows.push(parent);
		if (parent.revoked_at && !revokedAncestor) {
			revokedAncestor = parent.common_name;
		}
		cur = parent.type === 'ca' && !parent.issuer_id ? null : parent;
	}

	// Cryptographically verify each link — child against its parent — using
	// node:crypto.X509Certificate.verify(). Self-signed roots verify against
	// themselves (already in the chain).
	if (row.type !== 'ca' || row.issuer_id !== null) {
		for (let i = 0; i < chainRows.length - 1; i++) {
			const child = chainRows[i]!;
			const parent = chainRows[i + 1]!;
			const r = caSignsLeaf(parent.cert_pem, child.cert_pem);
			if (!r.ok) {
				return {
					ok: false,
					reason: r.reason ?? 'Chain verification failed',
					chain: chainNames,
					notBefore: cert.validity.notBefore,
					notAfter: cert.validity.notAfter,
					expired,
					notYetValid,
					revoked: !!row.revoked_at,
					revokedAt: row.revoked_at ?? undefined,
					revocationReason: row.revocation_reason ?? undefined,
					revokedAncestor,
				};
			}
		}
		// Confirm the chain terminates in a self-signed root, otherwise the
		// trust anchor is unknown.
		const top = chainRows[chainRows.length - 1]!;
		if (top.issuer_id !== null) {
			return {
				ok: false,
				reason: `Chain does not terminate in a self-signed CA (top: "${top.common_name}")`,
				chain: chainNames,
				notBefore: cert.validity.notBefore,
				notAfter: cert.validity.notAfter,
				expired,
				notYetValid,
				revoked: !!row.revoked_at,
				revokedAt: row.revoked_at ?? undefined,
				revocationReason: row.revocation_reason ?? undefined,
				revokedAncestor,
			};
		}
	}

	let sniInfo: VerifyResult['sni'] | undefined;
	if (sni) {
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
		const cnAttr = cert.subject.attributes.find(a => a.name === 'commonName');
		const matched =
			(cnAttr && matchHost(String(cnAttr.value), sni)) ||
			sans.some(s => matchHost(s, sni));
		sniInfo = {requested: sni, matched: !!matched};
	}

	const revoked = !!row.revoked_at;
	const baseRevocation = {
		revoked,
		revokedAt: row.revoked_at ?? undefined,
		revocationReason: row.revocation_reason ?? undefined,
		revokedAncestor,
	};

	if (revoked) {
		return {
			ok: false,
			reason: row.revocation_reason
				? `Certificate revoked: ${row.revocation_reason}`
				: 'Certificate revoked',
			chain: chainNames,
			notBefore: cert.validity.notBefore,
			notAfter: cert.validity.notAfter,
			expired,
			notYetValid,
			...baseRevocation,
			sni: sniInfo,
		};
	}

	if (revokedAncestor) {
		return {
			ok: false,
			reason: `Issuer "${revokedAncestor}" is revoked`,
			chain: chainNames,
			notBefore: cert.validity.notBefore,
			notAfter: cert.validity.notAfter,
			expired,
			notYetValid,
			...baseRevocation,
			sni: sniInfo,
		};
	}

	if (expired || notYetValid) {
		return {
			ok: false,
			reason: expired ? 'Certificate expired' : 'Certificate not yet valid',
			chain: chainNames,
			notBefore: cert.validity.notBefore,
			notAfter: cert.validity.notAfter,
			expired,
			notYetValid,
			...baseRevocation,
			sni: sniInfo,
		};
	}

	if (sniInfo && !sniInfo.matched) {
		return {
			ok: false,
			reason: `SNI "${sni}" does not match cert`,
			chain: chainNames,
			notBefore: cert.validity.notBefore,
			notAfter: cert.validity.notAfter,
			expired,
			notYetValid,
			...baseRevocation,
			sni: sniInfo,
		};
	}

	return {
		ok: true,
		chain: chainNames,
		notBefore: cert.validity.notBefore,
		notAfter: cert.validity.notAfter,
		expired,
		notYetValid,
		...baseRevocation,
		sni: sniInfo,
	};
}

function matchHost(pattern: string, host: string): boolean {
	if (!pattern || !host) return false;
	const p = pattern.toLowerCase();
	const h = host.toLowerCase();
	if (p === h) return true;
	if (p.startsWith('*.')) {
		const suffix = p.slice(1);
		const idx = h.indexOf('.');
		if (idx > 0 && h.slice(idx) === suffix) return true;
	}
	return false;
}
