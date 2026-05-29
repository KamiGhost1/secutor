// Typed wrappers over hubClient for the admin/v1 endpoints the TUI talks to.
// Pure HTTP helpers; no React, no storage. Caller owns the HubClientHandle
// lifecycle.

import crypto from 'crypto';
import type {HubClientHandle} from './hubClient.js';

export type CaInfo = {
	name: string;
	subject: string;
	issuer: string;
	serial_hex: string;
	not_before: string;
	not_after: string;
	cert_fingerprint: string;
	spki_fingerprint: string;
	key_algorithm: string;
	chain_depth: number;
};

export type AdminInfo = {
	role: 'viewer' | 'operator' | 'owner';
	ca: {name: string; cn: string; serial: string; notAfter: string; chainDepth: number};
	counts: {accounts: number; certificates: number; revoked: number; orders: number};
};

export type VerifyResponse = {
	alg: string;
	hash: string;
	signature: string; // base64
	cert_pem: string;
};

export type AdminCertRow = {
	id: string;
	order_id: string;
	account_id: string;
	serial_hex: string;
	not_before: string;
	not_after: string;
	revoked: number;
	revoked_at: string | null;
	revocation_reason: number | null;
	revoked_by?: string | null;
	issued_at: string;
	/** DNS identifiers from the order's authz rows (wildcards include the `*.` prefix). */
	identifiers: string[];
	pem_omitted?: true;
};

export type AdminCertDetails = AdminCertRow & {pem: string; chain_pem: string; identifiers: string[]};

export type AdminAccountRow = {
	id: string;
	jwk_thumbprint: string;
	status: string;
	contact_json: string | null;
	allow_list_json: string | null;
	created_at: string;
	deactivated_at?: string | null;
};

export type BanResponse = {
	account_id: string;
	previous_status: string;
	banned_at: string;
	revoked_certificates: number;
	cancelled_orders: number;
	reason: number;
	mode: 'cascade' | 'soft';
	ban_event_id: string;
};

export class AdminApi {
	constructor(private hub: HubClientHandle) {}

	async info(): Promise<AdminInfo> {
		const r = await this.hub.request<AdminInfo>({method: 'GET', path: '/admin/v1/info'});
		if (r.status !== 200) throw new Error(`/info HTTP ${r.status}`);
		return r.body;
	}

	async ca(): Promise<CaInfo> {
		const r = await this.hub.request<CaInfo>({method: 'GET', path: '/admin/v1/ca'});
		if (r.status !== 200) throw new Error(`/ca HTTP ${r.status}`);
		return r.body;
	}

	async listCertificates(filter?: {
		accountId?: string;
		revoked?: boolean;
		identifier?: string;
		limit?: number;
	}): Promise<AdminCertRow[]> {
		const q: string[] = [];
		if (filter?.accountId) q.push(`account_id=${encodeURIComponent(filter.accountId)}`);
		if (filter?.revoked !== undefined) q.push(`revoked=${filter.revoked}`);
		if (filter?.identifier) q.push(`identifier=${encodeURIComponent(filter.identifier)}`);
		if (filter?.limit) q.push(`limit=${filter.limit}`);
		const path = '/admin/v1/certificates' + (q.length ? `?${q.join('&')}` : '');
		const r = await this.hub.request<{items: AdminCertRow[]}>({method: 'GET', path});
		if (r.status !== 200) throw new Error(`/certificates HTTP ${r.status}`);
		return r.body.items;
	}

	async getCertificate(id: string): Promise<AdminCertDetails> {
		const r = await this.hub.request<AdminCertDetails>({
			method: 'GET',
			path: `/admin/v1/certificates/${encodeURIComponent(id)}`,
		});
		if (r.status !== 200) throw new Error(`/certificates/:id HTTP ${r.status}`);
		return r.body;
	}

	async revokeCertificate(id: string, reason: number): Promise<void> {
		const r = await this.hub.request({
			method: 'POST',
			path: `/admin/v1/certificates/${encodeURIComponent(id)}/revoke`,
			body: {reason},
		});
		if (r.status !== 200) throw new Error(`revoke HTTP ${r.status}: ${JSON.stringify(r.body)}`);
	}

	async stageCa(opts: {certPem: string; keyPem: string; chainPem: string}): Promise<{
		staged: boolean;
		fingerprint: string;
		key_algorithm: string;
		not_after: string;
		common_name: string;
		staged_at: string;
	}> {
		const r = await this.hub.request({
			method: 'POST', path: '/admin/v1/ca/stage',
			body: {cert_pem: opts.certPem, key_pem: opts.keyPem, chain_pem: opts.chainPem},
		});
		if (r.status !== 200) throw new Error(`stage HTTP ${r.status}: ${JSON.stringify(r.body)}`);
		return r.body;
	}

	async discardStagedCa(): Promise<void> {
		const r = await this.hub.request({method: 'DELETE', path: '/admin/v1/ca/staged'});
		if (r.status !== 200) throw new Error(`discard HTTP ${r.status}`);
	}

	async getStagedCa(): Promise<{staged: boolean; fingerprint?: string; key_algorithm?: string; not_after?: string; common_name?: string; staged_at?: string}> {
		const r = await this.hub.request({method: 'GET', path: '/admin/v1/ca/staged'});
		if (r.status !== 200) throw new Error(`staged HTTP ${r.status}`);
		return r.body as any;
	}

	async promoteCa(): Promise<{promoted: boolean; previous_fingerprint: string; new_fingerprint: string; rollback_available: boolean}> {
		const r = await this.hub.request({method: 'POST', path: '/admin/v1/ca/promote'});
		if (r.status !== 200) throw new Error(`promote HTTP ${r.status}: ${JSON.stringify(r.body)}`);
		return r.body;
	}

	async rollbackCa(): Promise<{rolled_back: boolean; restored_fingerprint: string}> {
		const r = await this.hub.request({method: 'POST', path: '/admin/v1/ca/rollback'});
		if (r.status !== 200) throw new Error(`rollback HTTP ${r.status}: ${JSON.stringify(r.body)}`);
		return r.body;
	}

	async startReissueJob(opts: {scope: 'all-active' | 'by-account' | 'by-identifier-pattern'; ratePerSec?: number; accountIds?: string[]; identifierPattern?: string}): Promise<{id: string; total: number; status: string}> {
		const r = await this.hub.request({method: 'POST', path: '/admin/v1/jobs/reissue', body: opts});
		if (r.status !== 200) throw new Error(`reissue HTTP ${r.status}: ${JSON.stringify(r.body)}`);
		return r.body as any;
	}

	async getJob(id: string): Promise<{id: string; status: string; total: number; done: number; failed: number; started_at: string; finished_at: string | null}> {
		const r = await this.hub.request({method: 'GET', path: `/admin/v1/jobs/${encodeURIComponent(id)}`});
		if (r.status !== 200) throw new Error(`job HTTP ${r.status}`);
		return r.body as any;
	}

	async cancelJob(id: string): Promise<void> {
		const r = await this.hub.request({method: 'POST', path: `/admin/v1/jobs/${encodeURIComponent(id)}/cancel`});
		if (r.status !== 200) throw new Error(`cancel HTTP ${r.status}: ${JSON.stringify(r.body)}`);
	}

	async listAudit(opts?: {action?: string; limit?: number; since?: string}): Promise<Array<{
		id: string;
		ts: string;
		actor_type: string;
		actor_id: string | null;
		action: string;
		target: string | null;
		ip: string | null;
		details_json: string | null;
	}>> {
		const q: string[] = [];
		if (opts?.action) q.push(`action=${encodeURIComponent(opts.action)}`);
		if (opts?.limit) q.push(`limit=${opts.limit}`);
		if (opts?.since) q.push(`since=${encodeURIComponent(opts.since)}`);
		const path = '/admin/v1/audit' + (q.length ? `?${q.join('&')}` : '');
		const r = await this.hub.request<{items: any[]}>({method: 'GET', path});
		if (r.status !== 200) throw new Error(`/audit HTTP ${r.status}`);
		return r.body.items;
	}

	async getOrderStats(): Promise<{
		window: {since: string; until: string};
		total: number;
		by_status: Record<string, number>;
		success_rate: number;
		buckets: Array<{ts: string; total: number; valid: number; invalid: number; expired: number}>;
	}> {
		const r = await this.hub.request({method: 'GET', path: '/admin/v1/stats/orders'});
		if (r.status !== 200) throw new Error(`stats/orders HTTP ${r.status}`);
		return r.body;
	}

	async getFailureStats(): Promise<{
		window: {since: string; until: string};
		total_invalid_orders: number;
		by_problem_type: Array<{type: string; count: number}>;
		by_challenge_type: Record<string, number>;
		top_failing_identifiers: Array<{value: string; count: number}>;
	}> {
		const r = await this.hub.request({method: 'GET', path: '/admin/v1/stats/failures'});
		if (r.status !== 200) throw new Error(`stats/failures HTTP ${r.status}`);
		return r.body;
	}

	async listAccounts(): Promise<AdminAccountRow[]> {
		const r = await this.hub.request<{items: AdminAccountRow[]}>({
			method: 'GET',
			path: '/admin/v1/accounts',
		});
		if (r.status !== 200) throw new Error(`/accounts HTTP ${r.status}`);
		return r.body.items;
	}

	async banAccount(id: string, opts: {reason?: number; comment?: string}): Promise<BanResponse> {
		const r = await this.hub.request<BanResponse>({
			method: 'POST',
			path: `/admin/v1/accounts/${encodeURIComponent(id)}/ban`,
			body: opts,
		});
		if (r.status !== 200) throw new Error(`ban HTTP ${r.status}: ${JSON.stringify(r.body)}`);
		return r.body;
	}

	async unbanAccount(id: string): Promise<void> {
		const r = await this.hub.request({
			method: 'POST',
			path: `/admin/v1/accounts/${encodeURIComponent(id)}/unban`,
		});
		if (r.status !== 200) throw new Error(`unban HTTP ${r.status}: ${JSON.stringify(r.body)}`);
	}

	async caChain(): Promise<string> {
		const r = await this.hub.request<string>({method: 'GET', path: '/admin/v1/ca/chain'});
		if (r.status !== 200) throw new Error(`/ca/chain HTTP ${r.status}`);
		return String(r.body);
	}

	/**
	 * Drives the proof-of-possession protocol end-to-end: generates a random
	 * nonce, asks the hub to sign it, and verifies the signature locally
	 * against `expectedPublicKeyPem`. Returns true iff the key the hub is
	 * actually using matches the one the caller supplied.
	 */
	async verifyCa(expectedPublicKeyPem: string): Promise<{
		ok: boolean;
		alg: string;
		hubCertFingerprint: string;
	}> {
		const nonce = crypto.randomBytes(32);
		const r = await this.hub.request<VerifyResponse>({
			method: 'POST',
			path: '/admin/v1/ca/verify',
			body: {nonce: nonce.toString('base64url')},
		});
		if (r.status !== 200) throw new Error(`/ca/verify HTTP ${r.status}: ${JSON.stringify(r.body)}`);
		const ok = verifyProofOfPossession({
			expectedPublicKeyPem,
			nonce,
			signature: Buffer.from(r.body.signature, 'base64'),
			alg: r.body.alg,
		});
		const hubCertFp = crypto
			.createHash('sha256')
			.update(new crypto.X509Certificate(r.body.cert_pem).raw)
			.digest('hex');
		return {ok, alg: r.body.alg, hubCertFingerprint: hubCertFp};
	}
}

// Mirror of acme-server/src/server/admin/ca.ts::verifyProofOfPossession.
// Re-implemented here so the TUI doesn't need to depend on the server package.
const VERIFY_PREFIX = Buffer.from('secutor-ca-verify-v1', 'utf8');

function signHashFor(alg: string): string | null {
	if (alg === 'ed25519') return null;
	if (alg === 'ecdsa-p384') return 'sha384';
	return 'sha256';
}

export function verifyProofOfPossession(opts: {
	expectedPublicKeyPem: string;
	nonce: Buffer;
	signature: Buffer;
	alg: string;
}): boolean {
	const message = crypto
		.createHash('sha256')
		.update(Buffer.concat([VERIFY_PREFIX, opts.nonce]))
		.digest();
	const pub = crypto.createPublicKey(opts.expectedPublicKeyPem);
	const hash = signHashFor(opts.alg);
	try {
		if (opts.alg.startsWith('rsa')) {
			return crypto.verify(hash, message, {
				key: pub,
				padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
				saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
			} as any, opts.signature);
		}
		return crypto.verify(hash, message, pub, opts.signature);
	} catch {
		return false;
	}
}
