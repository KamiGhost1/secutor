// mTLS-only admin auth. Two trust paths run in parallel and the higher-privileged
// role wins (owner > operator > viewer):
//
//   1. fingerprint allow-list — SHA-256 of the presented client cert's DER must
//      match one entry. Best for ops with a small, hand-picked set of admins.
//   2. CA trust — present cert must verify against one of the trusted CA files
//      AND satisfy subjectMatch ("contains" check, case-insensitive). Best for
//      large/automated client sets where minting individual fingerprints is
//      operationally painful.
//
// Implementation notes:
//   * fastify is started with requestCert:true, rejectUnauthorized:false so the
//     TLS handshake accepts ANY client cert; the actual decision happens here.
//   * Chain verification uses crypto.X509Certificate#verify(publicKey) walking
//     issuer→issuer. Node's X509 API doesn't expose a one-shot "verify against
//     this CA pool" call, so we hand-roll it. The chain in `peerCertificate
//     .raw` includes intermediates the client sent.

import crypto from 'crypto';
import fs from 'fs';
import type {TLSSocket} from 'tls';

export type AdminRole = 'viewer' | 'operator' | 'owner';

const ROLE_RANK: Record<AdminRole, number> = {viewer: 1, operator: 2, owner: 3};

export type FingerprintRule = {
	sha256: string; // hex, no colons
	role: AdminRole;
	label?: string;
};

export type CaRule = {
	caFile: string;
	role: AdminRole;
	subjectMatch?: string; // case-insensitive substring on subject DN
	label?: string;
};

export type AdminTrustConfig = {
	fingerprints?: FingerprintRule[];
	cas?: CaRule[];
	/** When true, /admin/v1/auth-policy is exposed (without mTLS). Defaults to false. */
	publishPolicy?: boolean;
};

export type AdminAuthResult = {
	role: AdminRole;
	clientFingerprint: string; // hex SHA-256 of the leaf cert's DER
	subject: string;
	matchedRules: string[]; // labels of all matching rules, for audit
};

export class AdminAuth {
	private trustedCas: Array<{rule: CaRule; cert: crypto.X509Certificate}> = [];

	constructor(private trust: AdminTrustConfig) {
		for (const c of trust.cas ?? []) {
			const pem = fs.readFileSync(c.caFile, 'utf8');
			// A single CA file may carry multiple certs (bundle); load all.
			const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
			if (!blocks.length) {
				throw new Error(`admin.trust.cas: no certificates in ${c.caFile}`);
			}
			for (const b of blocks) {
				this.trustedCas.push({rule: c, cert: new crypto.X509Certificate(b)});
			}
		}
	}

	/**
	 * Try to authenticate the TLS peer. Returns null on no-match (= 401).
	 * The caller's responsibility is to forbid plain HTTP altogether.
	 */
	verifyPeer(socket: TLSSocket): AdminAuthResult | null {
		const peer = socket.getPeerCertificate(true);
		if (!peer || !peer.raw || peer.raw.length === 0) return null;
		const leaf = new crypto.X509Certificate(peer.raw);
		const fp = crypto.createHash('sha256').update(peer.raw).digest('hex');
		const subject = String(leaf.subject ?? '');

		let bestRole: AdminRole | null = null;
		const matched: string[] = [];

		for (const r of this.trust.fingerprints ?? []) {
			if (r.sha256.toLowerCase() === fp) {
				matched.push(`fp:${r.label ?? r.sha256.slice(0, 12)}`);
				if (!bestRole || ROLE_RANK[r.role] > ROLE_RANK[bestRole]) bestRole = r.role;
			}
		}

		if (this.trustedCas.length) {
			// Walk the client-sent chain (peer + intermediates) and try to chain
			// up to any of our trusted roots/intermediates.
			const chain = collectChain(peer);
			for (const {rule, cert} of this.trustedCas) {
				if (chainsTo(chain, cert)) {
					if (rule.subjectMatch && !subject.toLowerCase().includes(rule.subjectMatch.toLowerCase())) {
						continue;
					}
					matched.push(`ca:${rule.label ?? rule.caFile}`);
					if (!bestRole || ROLE_RANK[rule.role] > ROLE_RANK[bestRole]) bestRole = rule.role;
				}
			}
		}

		if (!bestRole) return null;
		return {role: bestRole, clientFingerprint: fp, subject, matchedRules: matched};
	}

	publishPolicyEnabled(): boolean {
		return !!this.trust.publishPolicy;
	}

	policyDocument(): {
		fingerprints: Array<{sha256: string; label?: string; role: AdminRole}>;
		cas: Array<{caFingerprint: string; label?: string; role: AdminRole; subjectPattern?: string}>;
	} {
		return {
			fingerprints: (this.trust.fingerprints ?? []).map(f => ({
				sha256: f.sha256.toLowerCase(),
				label: f.label,
				role: f.role,
			})),
			cas: this.trustedCas.map(({rule, cert}) => ({
				caFingerprint: crypto.createHash('sha256').update(cert.raw).digest('hex'),
				label: rule.label ?? rule.caFile,
				role: rule.role,
				subjectPattern: rule.subjectMatch,
			})),
		};
	}
}

function collectChain(peer: import('tls').PeerCertificate): crypto.X509Certificate[] {
	const out: crypto.X509Certificate[] = [];
	let cur: import('tls').PeerCertificate | undefined = peer;
	const seen = new Set<string>();
	while (cur && cur.raw && cur.raw.length) {
		const fp = crypto.createHash('sha256').update(cur.raw).digest('hex');
		if (seen.has(fp)) break;
		seen.add(fp);
		out.push(new crypto.X509Certificate(cur.raw));
		// Node sets issuerCertificate=self for the root.
		const next: any = (cur as any).issuerCertificate;
		if (!next || next === cur) break;
		cur = next as import('tls').PeerCertificate;
	}
	return out;
}

/**
 * Returns true if any cert in `chain` chains up to (or equals) `trustAnchor`,
 * verified by signature using each parent's public key as we walk.
 */
function chainsTo(chain: crypto.X509Certificate[], trustAnchor: crypto.X509Certificate): boolean {
	if (!chain.length) return false;
	// Quick win: an anchor that's in the chain directly.
	for (const c of chain) {
		if (Buffer.from(c.raw).equals(Buffer.from(trustAnchor.raw))) return true;
	}
	// Otherwise: walk pairs from leaf upward, verifying each link, until we
	// find a cert whose issuer matches the anchor and whose signature verifies
	// against the anchor's public key.
	for (let i = 0; i < chain.length; i++) {
		const cur = chain[i]!;
		// Each next cert in the chain MUST verify cur.
		const next = chain[i + 1];
		if (next) {
			try {
				if (!cur.verify(next.publicKey)) return false;
			} catch {
				return false;
			}
		}
		// Check whether cur (or the upcoming next) is signed by the anchor.
		const candidate = next ?? cur;
		if (candidate.issuer === trustAnchor.subject) {
			try {
				if (candidate.verify(trustAnchor.publicKey)) return true;
			} catch {
				// fall through
			}
		}
	}
	return false;
}

export function roleAtLeast(have: AdminRole, need: AdminRole): boolean {
	return ROLE_RANK[have] >= ROLE_RANK[need];
}
