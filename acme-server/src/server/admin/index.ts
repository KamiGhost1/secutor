// Admin API — separate fastify listener with mTLS only. Exposes:
//   /admin/v1/info
//   /admin/v1/health
//   /admin/v1/certificates(?...)            GET (viewer)
//   /admin/v1/certificates/:id              GET (viewer)
//   /admin/v1/certificates/:id/revoke       POST (operator)
//   /admin/v1/accounts(?...)                GET (viewer)
//   /admin/v1/accounts/:id                  PATCH (owner)
//   /admin/v1/accounts/:id/ban              POST (owner)
//   /admin/v1/accounts/:id/unban            POST (owner)
//   /admin/v1/orders(?...)                  GET (viewer)
//   /admin/v1/audit(?...)                   GET (viewer)
//   /admin/v1/stats/orders                  GET (viewer)
//   /admin/v1/stats/failures                GET (viewer)
//   /admin/v1/stats/issuance                GET (viewer)
//   /admin/v1/metrics                       GET (viewer, Prometheus text)
//   /admin/v1/auth-policy                   GET (no mTLS, opt-in)
//
// All mTLS-gated routes set req.auth from the AdminAuth verifier (null → 401).

import crypto from 'crypto';
import fs from 'fs';
import Fastify, {FastifyInstance, FastifyReply, FastifyRequest} from 'fastify';
import type {TLSSocket} from 'tls';
import type {Repos, OrderRow, OrderStatus, CertRow} from '../repos.js';
import type {CaMaterial} from '../contextLoader.js';
import {AdminAuth, AdminRole, roleAtLeast} from './auth.js';
import {parseCsr, issueLeaf} from '../signer.js';
import {b64uDecode} from '../util.js';
import {registerCaRoutes} from './ca.js';

export type AdminConfig = {
	listen: string; // "0.0.0.0:8444"
	serverTls: {
		certFile: string;
		keyFile: string;
	};
	trust: {
		fingerprints?: Array<{sha256: string; role: AdminRole; label?: string}>;
		cas?: Array<{caFile: string; role: AdminRole; subjectMatch?: string; label?: string}>;
		publishPolicy?: boolean;
	};
	/** 'cascade' (default) revokes all valid certs on ban; 'soft' only deactivates. */
	banMode?: 'cascade' | 'soft';
};

export type AdminCtx = {
	repos: Repos;
	ca: CaMaterial;
	config: AdminConfig;
	auth: AdminAuth;
	/** Optional — only present if the operator wants stage/promote/rollback. */
	caStore?: import('../caStore.js').CaStore;
	/** Optional — drives background re-signing of leaves after CA rotation. */
	reissueWorker?: import('../reissueWorker.js').ReissueWorker;
};

function parseListen(s: string): {host: string; port: number} {
	const m = /^(.+):(\d+)$/.exec(s);
	if (!m) throw new Error(`Bad admin.listen address: ${s}`);
	return {host: m[1]!, port: parseInt(m[2]!, 10)};
}

declare module 'fastify' {
	interface FastifyRequest {
		auth?: ReturnType<AdminAuth['verifyPeer']>;
	}
}

export async function startAdminServer(ctx: AdminCtx): Promise<FastifyInstance> {
	const tls = {
		cert: fs.readFileSync(ctx.config.serverTls.certFile),
		key: fs.readFileSync(ctx.config.serverTls.keyFile),
		requestCert: true,
		rejectUnauthorized: false,
	};

	const app = Fastify({
		logger: {level: process.env.LOG_LEVEL ?? 'info'},
		bodyLimit: 1 * 1024 * 1024,
		https: tls,
	}) as unknown as FastifyInstance;

	// Per-request mTLS gate. /auth-policy is the only exception — it MAY be
	// served without an mTLS handshake when publishPolicy is on.
	app.addHook('onRequest', async (req, reply) => {
		if (req.url.startsWith('/admin/v1/auth-policy') && ctx.auth.publishPolicyEnabled()) {
			return; // allow anonymous
		}
		const sock = req.socket as TLSSocket;
		const res = ctx.auth.verifyPeer(sock);
		if (!res) {
			reply.code(401).send({error: 'mtls-required', detail: 'No accepted client certificate'});
			return reply;
		}
		req.auth = res;
	});

	registerAdminRoutes(app, ctx);
	registerCaRoutes(app, ctx);

	const {host, port} = parseListen(ctx.config.listen);
	await app.listen({host, port});
	app.log.info({host, port}, `admin API listening (mTLS)`);
	return app;
}

function requireRole(req: FastifyRequest, reply: FastifyReply, need: AdminRole): boolean {
	const r = req.auth?.role;
	if (!r || !roleAtLeast(r, need)) {
		reply.code(403).send({error: 'forbidden', detail: `requires role ${need}`});
		return false;
	}
	return true;
}

function audit(
	ctx: AdminCtx,
	req: FastifyRequest,
	action: string,
	target?: string | null,
	details?: object,
): string {
	return ctx.repos.audit({
		actorType: 'admin',
		actorId: req.auth?.clientFingerprint ?? null,
		action,
		target,
		ip: req.ip,
		details,
	});
}

function registerAdminRoutes(app: FastifyInstance, ctx: AdminCtx): void {
	/* ───── auth-policy (no-mTLS-when-enabled) ───── */
	app.get('/admin/v1/auth-policy', async (_req, reply) => {
		if (!ctx.auth.publishPolicyEnabled()) {
			reply.code(404).send({error: 'not-published'});
			return;
		}
		return ctx.auth.policyDocument();
	});

	/* ───── info / health ───── */
	app.get('/admin/v1/info', async req => {
		if (!req.auth) return;
		const ca = ctx.ca;
		const counts = ctx.repos.db
			.prepare(
				`SELECT
					(SELECT COUNT(*) FROM accounts) AS accounts,
					(SELECT COUNT(*) FROM certificates) AS certificates,
					(SELECT COUNT(*) FROM certificates WHERE revoked=1) AS revoked,
					(SELECT COUNT(*) FROM orders) AS orders`,
			)
			.get() as {accounts: number; certificates: number; revoked: number; orders: number};
		return {
			role: req.auth.role,
			ca: {
				name: ca.name,
				cn: ca.commonName,
				serial: ca.serial,
				notAfter: ca.notAfter.toISOString(),
				chainDepth: ca.chainDepth,
			},
			counts,
		};
	});

	app.get('/admin/v1/health', async () => ({ok: true}));

	/* ───── certificates ───── */
	app.get('/admin/v1/certificates', async (req, reply) => {
		if (!requireRole(req, reply, 'viewer')) return reply;
		const q = req.query as Record<string, string>;
		const rows = ctx.repos.listCertificates({
			limit: q.limit ? parseInt(q.limit, 10) : undefined,
			offset: q.offset ? parseInt(q.offset, 10) : undefined,
			accountId: q.account_id || undefined,
			identifier: q.identifier || undefined,
			revoked: q.revoked === 'true' ? true : q.revoked === 'false' ? false : undefined,
			issuedAfter: q.issued_after || undefined,
			issuedBefore: q.issued_before || undefined,
			expiresBefore: q.expires_before || undefined,
		});
		return {items: rows.map(stripCertPemFromList)};
	});

	app.get('/admin/v1/certificates/:id', async (req, reply) => {
		if (!requireRole(req, reply, 'viewer')) return reply;
		const id = (req.params as any).id as string;
		const row = ctx.repos.getCertWithIdentifiers(id);
		if (!row) {
			reply.code(404).send({error: 'not-found'});
			return reply;
		}
		// identifiers_json is the raw column; we expose only the parsed array.
		const {identifiers_json: _omit, ...rest} = row;
		return rest;
	});

	app.post('/admin/v1/certificates/:id/revoke', async (req, reply) => {
		if (!requireRole(req, reply, 'operator')) return reply;
		const id = (req.params as any).id as string;
		const body = (req.body as any) ?? {};
		const reason = typeof body.reason === 'number' ? body.reason : 0;
		const row = ctx.repos.getCert(id);
		if (!row) {
			reply.code(404).send({error: 'not-found'});
			return reply;
		}
		if (row.revoked) {
			reply.code(409).send({error: 'already-revoked'});
			return reply;
		}
		ctx.repos.revokeCert(id, reason, `admin:${req.auth!.clientFingerprint}`);
		audit(ctx, req, 'cert.revoke', id, {serial: row.serial_hex, reason});
		return {ok: true, id, reason};
	});

	/* ───── accounts ───── */
	app.get('/admin/v1/accounts', async (req, reply) => {
		if (!requireRole(req, reply, 'viewer')) return reply;
		const q = req.query as Record<string, string>;
		const rows = ctx.repos.listAccounts({
			limit: q.limit ? parseInt(q.limit, 10) : undefined,
			offset: q.offset ? parseInt(q.offset, 10) : undefined,
		});
		return {items: rows};
	});

	app.patch('/admin/v1/accounts/:id', async (req, reply) => {
		if (!requireRole(req, reply, 'owner')) return reply;
		const id = (req.params as any).id as string;
		const body = (req.body as any) ?? {};
		const acct = ctx.repos.getAccount(id);
		if (!acct) {
			reply.code(404).send({error: 'not-found'});
			return reply;
		}
		const patch: {status?: string; allowList?: string[] | null; contact?: string[] | null} = {};
		if (typeof body.status === 'string' && ['valid', 'deactivated'].includes(body.status)) {
			patch.status = body.status;
		}
		if (Array.isArray(body.allow_list) || body.allow_list === null) {
			patch.allowList = body.allow_list;
		}
		if (Array.isArray(body.contact) || body.contact === null) {
			patch.contact = body.contact;
		}
		ctx.repos.updateAccount(id, patch);
		audit(ctx, req, 'account.update', id, patch);
		return ctx.repos.getAccount(id);
	});

	app.post('/admin/v1/accounts/:id/ban', async (req, reply) => {
		if (!requireRole(req, reply, 'owner')) return reply;
		const id = (req.params as any).id as string;
		const body = (req.body as any) ?? {};
		const reason = typeof body.reason === 'number' ? body.reason : 9; // privilegeWithdrawn
		const acct = ctx.repos.getAccount(id);
		if (!acct) {
			reply.code(404).send({error: 'not-found'});
			return reply;
		}
		if (acct.status === 'banned') {
			reply.code(409).send({error: 'already-banned'});
			return reply;
		}
		const mode = ctx.config.banMode ?? 'cascade';
		const fp = req.auth!.clientFingerprint;

		// Audit-entry id is written first so cascade rows can reference it.
		const eventId = audit(ctx, req, 'account.ban', id, {
			previous_status: acct.status,
			mode,
			reason,
			comment: typeof body.comment === 'string' ? body.comment : null,
		});

		let revoked = 0;
		let cancelled = 0;
		ctx.repos.db.transaction(() => {
			ctx.repos.updateAccount(id, {status: 'banned'});
			// Cancel open orders regardless of mode.
			for (const o of ctx.repos.listOpenOrdersForAccount(id)) {
				ctx.repos.setOrderStatus(o.id, 'invalid', {
					type: 'secutor:accountBanned',
					detail: `Account banned (event ${eventId})`,
				});
				cancelled++;
			}
			if (mode === 'cascade') {
				for (const c of ctx.repos.listActiveCertsForAccount(id)) {
					ctx.repos.revokeCert(c.id, reason, `admin:${fp}:ban`, eventId);
					ctx.repos.audit({
						actorType: 'admin',
						actorId: fp,
						action: 'cert.revoke.cascade',
						target: c.id,
						ip: req.ip,
						details: {account_id: id, ban_event_id: eventId, serial: c.serial_hex, reason},
					});
					revoked++;
				}
			}
		})();
		return {
			account_id: id,
			previous_status: acct.status,
			banned_at: new Date().toISOString(),
			revoked_certificates: revoked,
			cancelled_orders: cancelled,
			reason,
			mode,
			ban_event_id: eventId,
		};
	});

	app.post('/admin/v1/accounts/:id/unban', async (req, reply) => {
		if (!requireRole(req, reply, 'owner')) return reply;
		const id = (req.params as any).id as string;
		const acct = ctx.repos.getAccount(id);
		if (!acct) {
			reply.code(404).send({error: 'not-found'});
			return reply;
		}
		if (acct.status !== 'banned') {
			reply.code(409).send({error: 'not-banned'});
			return reply;
		}
		ctx.repos.updateAccount(id, {status: 'valid'});
		audit(ctx, req, 'account.unban', id);
		return {account_id: id, status: 'valid'};
	});

	/* ───── orders ───── */
	app.get('/admin/v1/orders', async (req, reply) => {
		if (!requireRole(req, reply, 'viewer')) return reply;
		const q = req.query as Record<string, string>;
		const rows = ctx.repos.listOrders({
			limit: q.limit ? parseInt(q.limit, 10) : undefined,
			offset: q.offset ? parseInt(q.offset, 10) : undefined,
			status: q.status as OrderStatus | undefined,
			accountId: q.account_id || undefined,
			since: q.since || undefined,
			until: q.until || undefined,
		});
		return {items: rows};
	});

	/* ───── audit ───── */
	app.get('/admin/v1/audit', async (req, reply) => {
		if (!requireRole(req, reply, 'viewer')) return reply;
		const q = req.query as Record<string, string>;
		const rows = ctx.repos.listAuditLog({
			limit: q.limit ? parseInt(q.limit, 10) : undefined,
			offset: q.offset ? parseInt(q.offset, 10) : undefined,
			action: q.action || undefined,
			actorId: q.actor_id || undefined,
			target: q.target || undefined,
			since: q.since || undefined,
		});
		return {items: rows};
	});

	/* ───── stats ───── */
	app.get('/admin/v1/stats/orders', async (req, reply) => {
		if (!requireRole(req, reply, 'viewer')) return reply;
		const q = req.query as Record<string, string>;
		const window = defaultWindow(q.since, q.until);
		const counts = ctx.repos.countOrdersByStatus(window);
		const successRate = counts.total
			? Math.round((counts.valid / counts.total) * 1000) / 1000
			: 0;
		const buckets = ctx.repos.bucketOrders({
			...window,
			bucket: (q.bucket as 'day' | 'hour') || 'day',
		});
		return {
			window: {since: window.since, until: window.until},
			total: counts.total,
			by_status: {
				valid: counts.valid,
				invalid: counts.invalid,
				expired: counts.expired,
				pending: counts.pending,
				processing: counts.processing,
				ready: counts.ready,
			},
			success_rate: successRate,
			buckets,
		};
	});

	app.get('/admin/v1/stats/failures', async (req, reply) => {
		if (!requireRole(req, reply, 'viewer')) return reply;
		const q = req.query as Record<string, string>;
		const window = defaultWindow(q.since, q.until);
		const b = ctx.repos.failureBreakdown(window);
		return {
			window: {since: window.since, until: window.until},
			total_invalid_orders: b.totalInvalid,
			by_problem_type: b.byProblemType,
			by_challenge_type: b.byChallengeType,
			top_failing_identifiers: b.topFailingIdentifiers,
		};
	});

	app.get('/admin/v1/stats/issuance', async (req, reply) => {
		if (!requireRole(req, reply, 'viewer')) return reply;
		const q = req.query as Record<string, string>;
		const window = defaultWindow(q.since, q.until);
		const series = ctx.repos.issuanceSeries({
			...window,
			bucket: (q.bucket as 'day' | 'hour') || 'day',
		});
		return {window: {since: window.since, until: window.until}, series};
	});

	/* ───── admin-issue (out-of-band leaf issuance) ─────
	 * Skips ACME challenges entirely. Authorization is the mTLS handshake +
	 * `operator` role. Audited as 'cert.issue.admin'. Two modes:
	 *   - With CSR (recommended): client supplies a CSR; server only signs,
	 *     never sees a private key. SANs in the CSR must match identifiers.
	 *   - Without CSR: server generates a key pair and a leaf cert. The
	 *     response then includes both PEMs. Caller is responsible for getting
	 *     them off this machine safely (TUI streams into a local context via
	 *     the key-bundle path).
	 */
	app.post('/admin/v1/certificates/issue', async (req, reply) => {
		if (!requireRole(req, reply, 'operator')) return reply;
		const body = (req.body as any) ?? {};
		const identifiers = Array.isArray(body.identifiers) ? body.identifiers : [];
		if (!identifiers.length) {
			reply.code(400).send({error: 'missing-identifiers'});
			return reply;
		}
		for (const i of identifiers) {
			if (i?.type !== 'dns' || typeof i.value !== 'string') {
				reply.code(400).send({error: 'unsupported-identifier', detail: 'only dns identifiers'});
				return reply;
			}
		}
		const notAfterDays = typeof body.notAfterDays === 'number' ? body.notAfterDays : 90;
		if (notAfterDays < 1 || notAfterDays > 825) {
			reply.code(400).send({error: 'bad-validity', detail: '1–825 days'});
			return reply;
		}
		const adminFp = req.auth!.clientFingerprint;
		// Find or synthesise the admin-account that owns admin-issued certs so
		// orders/certs FK stays satisfied.
		const adminAccountId = ensureAdminAccount(ctx, adminFp);

		const wantSans = identifiers.map((i: any) => String(i.value).toLowerCase());
		const commonName = body.subject?.commonName ?? wantSans[0]!;
		let subjectPublicKeyPem: string;
		let generatedKeyPem: string | null = null;
		let csrDer: Buffer | null = null;

		if (typeof body.csr === 'string' && body.csr.length) {
			try {
				csrDer = b64uDecode(body.csr);
			} catch (e: any) {
				reply.code(400).send({error: 'bad-csr', detail: e?.message ?? 'base64 decode'});
				return reply;
			}
			const csr = parseCsr(csrDer);
			const got = new Set([...(csr.sans ?? []), ...(csr.commonName ? [csr.commonName] : [])].map(s => s.toLowerCase()));
			for (const w of wantSans) {
				if (!got.has(w)) {
					reply.code(400).send({error: 'bad-csr', detail: `CSR missing SAN ${w}`});
					return reply;
				}
			}
			subjectPublicKeyPem = csr.subjectPublicKeyPem;
		} else {
			// Server-side keypair generation. Default ECDSA P-256 — small, fast.
			const alg = String(body.keyAlgorithm ?? 'ecdsa-p256').toLowerCase();
			const pair = generateKeyPair(alg);
			subjectPublicKeyPem = pair.publicKey;
			generatedKeyPem = pair.privateKey;
		}

		const notBefore = new Date();
		const notAfter = new Date(notBefore.getTime() + notAfterDays * 86400_000);
		let result;
		try {
			result = issueLeaf({
				caCertPem: ctx.ca.certPem,
				caKeyPem: ctx.ca.keyPem,
				subjectPublicKeyPem,
				commonName,
				sans: wantSans,
				notBefore,
				notAfter,
			});
		} catch (e: any) {
			reply.code(500).send({error: 'sign-failed', detail: e?.message ?? String(e)});
			return reply;
		}

		// Synthesize a placeholder order that owns the cert (admin issues bypass
		// ACME order/authz but the certificates table FKs to orders).
		const order = ctx.repos.insertOrder({
			accountId: adminAccountId,
			identifiers,
			notBefore: notBefore.toISOString(),
			notAfter: notAfter.toISOString(),
			ttlSec: 1,
		});
		ctx.repos.setOrderStatus(order.id, 'valid');
		const certRow = ctx.repos.insertCert({
			orderId: order.id,
			accountId: adminAccountId,
			serialHex: result.serialHex,
			pem: result.certPem,
			chainPem: ctx.ca.chainPem,
			notBefore: result.notBefore.toISOString(),
			notAfter: result.notAfter.toISOString(),
			identifiers: wantSans,
		});
		ctx.repos.attachCertToOrder(order.id, certRow.id, csrDer ?? Buffer.alloc(0));
		audit(ctx, req, 'cert.issue.admin', certRow.id, {
			serial: result.serialHex,
			identifiers,
			generated_key: !!generatedKeyPem,
		});

		return {
			id: certRow.id,
			serial: result.serialHex,
			cert_pem: result.certPem,
			chain_pem: ctx.ca.chainPem,
			not_before: result.notBefore.toISOString(),
			not_after: result.notAfter.toISOString(),
			fingerprint: result.fingerprint,
			...(generatedKeyPem ? {generated_key_pem: generatedKeyPem} : {}),
		};
	});

	app.get('/admin/v1/metrics', async (req, reply) => {
		if (!requireRole(req, reply, 'viewer')) return reply;
		const counts = ctx.repos.countOrdersByStatus({});
		const certs = ctx.repos.db
			.prepare(
				`SELECT
					COUNT(*) AS total,
					SUM(CASE WHEN revoked=1 THEN 1 ELSE 0 END) AS revoked,
					SUM(CASE WHEN not_after < datetime('now', '+30 days') AND not_after >= datetime('now') THEN 1 ELSE 0 END) AS expiring_soon,
					SUM(CASE WHEN not_after < datetime('now') THEN 1 ELSE 0 END) AS expired
				FROM certificates`,
			)
			.get() as any;
		reply.header('Content-Type', 'text/plain; version=0.0.4');
		const lines = [
			'# HELP secutor_acme_orders_total Total ACME orders by status',
			'# TYPE secutor_acme_orders_total counter',
			...Object.entries(counts)
				.filter(([k]) => k !== 'total')
				.map(([k, v]) => `secutor_acme_orders_total{status="${k}"} ${v}`),
			'# HELP secutor_acme_certificates_total Issued certificates',
			'# TYPE secutor_acme_certificates_total gauge',
			`secutor_acme_certificates_total ${certs.total ?? 0}`,
			`secutor_acme_certificates_revoked ${certs.revoked ?? 0}`,
			`secutor_acme_certificates_expiring_soon_30d ${certs.expiring_soon ?? 0}`,
			`secutor_acme_certificates_expired ${certs.expired ?? 0}`,
			'',
		];
		return lines.join('\n');
	});
}

function defaultWindow(sinceQ?: string, untilQ?: string): {since: string; until: string} {
	// `until` is end-exclusive (`created_at < ?`). Default to one minute into
	// the future so rows inserted within the same millisecond as the request
	// are still counted; callers can pin a tighter `until` explicitly.
	const until = untilQ ?? new Date(Date.now() + 60_000).toISOString();
	const since = sinceQ ?? new Date(Date.now() - 30 * 86400_000).toISOString();
	return {since, until};
}

function stripCertPemFromList(
	c: CertRow & {identifiers?: string[]},
): Omit<CertRow, 'pem' | 'chain_pem' | 'identifiers_json'> & {
	pem_omitted: true;
	identifiers: string[];
} {
	const {pem: _, chain_pem: __, identifiers_json: ___, identifiers, ...rest} = c;
	return {...rest, identifiers: identifiers ?? [], pem_omitted: true};
}

/**
 * Find (or lazily insert) the dedicated admin-account used as owner for
 * admin-issued certs. Keyed by a synthetic thumbprint embedding the admin's
 * client-cert fingerprint, so different admins get separate ownership rows
 * (handy for filtering admin-issued certs in the audit log).
 */
function ensureAdminAccount(ctx: AdminCtx, adminClientFp: string): string {
	const tp = `admin-issuer:${adminClientFp}`;
	const existing = ctx.repos.findAccountByThumbprint(tp);
	if (existing) return existing.id;
	const row = ctx.repos.insertAccount(
		JSON.stringify({kty: 'admin-pseudo', fp: adminClientFp}),
		tp,
		null,
	);
	return row.id;
}

function generateKeyPair(alg: string): {privateKey: string; publicKey: string} {
	switch (alg) {
		case 'rsa-2048':
		case 'rsa-3072':
		case 'rsa-4096': {
			const bits = parseInt(alg.split('-')[1]!, 10);
			return crypto.generateKeyPairSync('rsa', {
				modulusLength: bits,
				publicKeyEncoding: {type: 'spki', format: 'pem'},
				privateKeyEncoding: {type: 'pkcs8', format: 'pem'},
			});
		}
		case 'ecdsa-p256':
		case 'ecdsa-p384': {
			const curve = alg === 'ecdsa-p384' ? 'P-384' : 'P-256';
			return crypto.generateKeyPairSync('ec', {
				namedCurve: curve,
				publicKeyEncoding: {type: 'spki', format: 'pem'},
				privateKeyEncoding: {type: 'pkcs8', format: 'pem'},
			});
		}
		case 'ed25519':
			return crypto.generateKeyPairSync('ed25519', {
				publicKeyEncoding: {type: 'spki', format: 'pem'},
				privateKeyEncoding: {type: 'pkcs8', format: 'pem'},
			});
		default:
			throw new Error(`unsupported keyAlgorithm "${alg}"`);
	}
}
