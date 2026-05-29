// ACME endpoints (RFC 8555). Wired onto a fastify instance by index.ts.

import type {FastifyInstance, FastifyReply, FastifyRequest} from 'fastify';
import {AcmeError, problemContentType} from './errors.js';
import {verifyJws, type JwsRequestBody} from './jws.js';
import type {Repos} from './repos.js';
import type {NonceManager} from './nonce.js';
import type {Urls} from './urls.js';
import type {Config} from './config.js';
import type {CaMaterial} from './contextLoader.js';
import crypto from 'crypto';
import {parseCsr, issueLeaf} from './signer.js';
import {buildCrl, crlToPem} from './crl.js';
import {jwkThumbprint, b64uDecode, randomToken, nowIso} from './util.js';

export type ServerCtx = {
	repos: Repos;
	nonces: NonceManager;
	urls: Urls;
	config: Config;
	ca: CaMaterial;
	/** Optional — present only if `config.dnsProviders` is configured. */
	dnsRegistry?: import('./dnsProviders.js').DnsProviderRegistry;
};

function applyAcmeHeaders(reply: FastifyReply, ctx: ServerCtx, link?: string): void {
	reply.header('Replay-Nonce', ctx.nonces.issue());
	if (link) reply.header('Link', link);
}

function directoryLink(ctx: ServerCtx): string {
	return `<${ctx.urls.directory()}>;rel="index"`;
}

function sendProblem(reply: FastifyReply, ctx: ServerCtx, err: AcmeError): void {
	reply
		.code(err.status)
		.header('Content-Type', problemContentType())
		.header('Replay-Nonce', ctx.nonces.issue())
		.send(err.toProblem());
}

async function readJws(
	req: FastifyRequest,
	reply: FastifyReply,
	ctx: ServerCtx,
	expectedUrl: string,
) {
	const body = req.body as JwsRequestBody;
	if (!body) {
		throw new AcmeError('malformed', 'Missing JWS body', 400);
	}
	const parsed = await verifyJws(body, expectedUrl, kid => {
		const id = ctx.urls.parseAccountId(kid);
		if (!id) return null;
		const acct = ctx.repos.getAccount(id);
		if (!acct) return null;
		return JSON.parse(acct.jwk_json);
	});
	if (!ctx.nonces.consume(parsed.protectedHeader.nonce)) {
		throw new AcmeError('badNonce', 'Stale or unknown nonce', 400);
	}
	return parsed;
}

function expectedSans(identifiers: Array<{type: string; value: string}>): Set<string> {
	const s = new Set<string>();
	for (const i of identifiers) {
		if (i.type === 'dns') s.add(i.value.toLowerCase());
	}
	return s;
}

function compareSans(want: Set<string>, got: Iterable<string>): {ok: true} | {ok: false; reason: string} {
	const have = new Set<string>();
	for (const g of got) have.add(g.toLowerCase());
	if (have.size !== want.size) {
		return {ok: false, reason: `CSR SANs differ in count (want=${want.size}, got=${have.size})`};
	}
	for (const w of want) {
		if (!have.has(w)) return {ok: false, reason: `CSR missing SAN ${w}`};
	}
	return {ok: true};
}

function passesAllowList(name: string, cfg: Config): boolean {
	if (!cfg.allowList || !cfg.allowList.dnsPatterns.length) return true;
	const n = name.toLowerCase();
	for (const pat of cfg.allowList.dnsPatterns) {
		const p = pat.toLowerCase();
		if (p === n) return true;
		if (p.startsWith('*.')) {
			const suf = p.slice(2);
			if (n === suf || n.endsWith('.' + suf)) return true;
		}
	}
	return false;
}

export function registerRoutes(app: FastifyInstance, ctx: ServerCtx): void {
	app.setErrorHandler((err, _req, reply) => {
		if (err instanceof AcmeError) {
			sendProblem(reply, ctx, err);
			return;
		}
		app.log.error({err}, 'unhandled error');
		sendProblem(reply, ctx, new AcmeError('serverInternal', err.message ?? 'internal error', 500));
	});

	// ARI (draft-ietf-acme-ari) renewal-info hint. Public, unauthenticated.
	// Per the draft, the path is /renewalInfo/<base64url-encoded(AKI || serial)>;
	// our simpler form takes the cert id we already use elsewhere. This is an
	// extension; standard clients ignore it harmlessly.
	app.get('/renewalInfo/:id', async (req, reply) => {
		const id = (req.params as any).id as string;
		const cert = ctx.repos.getCert(id);
		if (!cert) {
			reply.code(404).send({error: 'not-found'});
			return reply;
		}
		// If the cert was re-signed recently (issued_at is the original issuance
		// but pem now reflects the new signature), we want clients to renew now.
		// Approximation: when the issuing CA's certificate fingerprint differs
		// from what the leaf chains to in `chain_pem`, the leaf has been
		// resigned — recommend "renew now". Otherwise recommend the usual
		// pre-expiry window.
		const now = Date.now();
		const expiresAt = new Date(cert.not_after).getTime();
		const ttl = expiresAt - now;
		// Default: recommend renewal in the last third of the validity window.
		const recommendStart = now + Math.max(0, Math.floor(ttl * 2 / 3));
		const recommendEnd = now + Math.max(0, ttl - 6 * 3600_000); // 6h before expiry
		reply.header('Retry-After', '86400');
		return {
			suggestedWindow: {
				start: new Date(recommendStart).toISOString(),
				end: new Date(recommendEnd).toISOString(),
			},
		};
	});

	// CRL — public, unauthenticated. Two formats:
	//   GET /crl       → application/pkix-crl (DER)
	//   GET /crl.pem   → application/x-pem-file
	app.get('/crl', async (_req, reply) => {
		const der = buildCrl(ctx.repos, ctx.ca);
		reply.header('Content-Type', 'application/pkix-crl');
		reply.header('Cache-Control', 'public, max-age=3600');
		return reply.send(der);
	});
	app.get('/crl.pem', async (_req, reply) => {
		const der = buildCrl(ctx.repos, ctx.ca);
		reply.header('Content-Type', 'application/x-pem-file');
		reply.header('Cache-Control', 'public, max-age=3600');
		return crlToPem(der);
	});

	// Root CA cert — for trust distribution. Always the self-signed anchor at
	// the top of the chain, regardless of whether the signing CA is itself the
	// root or an intermediate.
	app.get('/ca.pem', async (_req, reply) => {
		reply.header('Content-Type', 'application/x-pem-file');
		return ctx.ca.rootCertPem;
	});
	// The full issuer chain (signing CA + intermediates, root excluded). Useful
	// if a client wants to bundle a chain without re-fetching every leaf.
	app.get('/chain.pem', async (_req, reply) => {
		reply.header('Content-Type', 'application/x-pem-file');
		return ctx.ca.chainPem || ctx.ca.rootCertPem;
	});

	// directory
	app.get('/directory', async (_req, reply) => {
		applyAcmeHeaders(reply, ctx);
		return {
			newNonce: ctx.urls.newNonce(),
			newAccount: ctx.urls.newAccount(),
			newOrder: ctx.urls.newOrder(),
			revokeCert: ctx.urls.revokeCert(),
			keyChange: ctx.urls.keyChange(),
			meta: {
				termsOfService: ctx.config.baseUrl + 'tos',
			},
		};
	});

	// newNonce
	app.route({
		method: ['HEAD', 'GET'],
		url: '/new-nonce',
		handler: async (_req, reply) => {
			applyAcmeHeaders(reply, ctx, directoryLink(ctx));
			reply.code(204).send();
		},
	});

	// newAccount
	app.post('/new-account', async (req, reply) => {
		const parsed = await readJws(req, reply, ctx, ctx.urls.newAccount());
		if (!parsed.protectedHeader.jwk) {
			throw new AcmeError('malformed', 'newAccount requires "jwk" in protected header');
		}
		const tp = parsed.thumbprint;
		const existing = ctx.repos.findAccountByThumbprint(tp);
		const payload = (parsed.payloadJson as any) ?? {};
		if (existing) {
			reply
				.code(200)
				.header('Replay-Nonce', ctx.nonces.issue())
				.header('Location', ctx.urls.account(existing.id));
			return accountResponse(ctx, existing);
		}
		if (payload.onlyReturnExisting) {
			throw new AcmeError('accountDoesNotExist', 'No account matches the JWK', 400);
		}
		const acct = ctx.repos.insertAccount(
			JSON.stringify(parsed.jwk),
			tp,
			Array.isArray(payload.contact) ? payload.contact : null,
		);
		ctx.repos.audit({
			actorType: 'account',
			actorId: acct.id,
			action: 'account.create',
			target: acct.id,
			ip: req.ip,
		});
		reply
			.code(201)
			.header('Replay-Nonce', ctx.nonces.issue())
			.header('Location', ctx.urls.account(acct.id));
		return accountResponse(ctx, acct);
	});

	// account fetch / update
	app.post('/acct/:id', async (req, reply) => {
		const id = (req.params as any).id as string;
		const parsed = await readJws(req, reply, ctx, ctx.urls.account(id));
		if (!parsed.accountUrl || ctx.urls.parseAccountId(parsed.accountUrl) !== id) {
			throw new AcmeError('unauthorized', 'kid does not match URL account');
		}
		const acct = ctx.repos.getAccount(id);
		if (!acct) throw new AcmeError('accountDoesNotExist', 'No such account', 404);
		applyAcmeHeaders(reply, ctx);
		return accountResponse(ctx, acct);
	});

	// newOrder
	app.post('/new-order', async (req, reply) => {
		const parsed = await readJws(req, reply, ctx, ctx.urls.newOrder());
		const accountId = parsed.accountUrl ? ctx.urls.parseAccountId(parsed.accountUrl) : null;
		if (!accountId) throw new AcmeError('unauthorized', 'newOrder requires kid');
		const payload = (parsed.payloadJson as any) ?? {};
		const ids = Array.isArray(payload.identifiers) ? payload.identifiers : [];
		if (!ids.length) throw new AcmeError('malformed', 'No identifiers in order');
		for (const i of ids) {
			if (i.type !== 'dns') {
				throw new AcmeError('unsupportedIdentifier', `Only dns identifiers supported, got ${i.type}`);
			}
			if (!passesAllowList(i.value, ctx.config)) {
				throw new AcmeError('rejectedIdentifier', `Identifier not allowed: ${i.value}`);
			}
		}

		// Extension: clients can opt into server-managed DNS placement by
		// adding {"secutor":{"dnsPlacement":"server-managed"}} to newOrder.
		// Unknown clients ignore the extension; we just respond per RFC.
		const placementMode =
			(payload as any)?.secutor?.dnsPlacement === 'server-managed' ? 'server-managed' : 'client';
		if (placementMode === 'server-managed') {
			if (!ctx.dnsRegistry) {
				throw new AcmeError(
					'rejectedIdentifier',
					'server-managed DNS requested but no providers configured',
				);
			}
			for (const i of ids) {
				if (!ctx.dnsRegistry.hasProviderFor(i.value)) {
					throw new AcmeError(
						'rejectedIdentifier',
						`no DNS provider mapped to identifier "${i.value}"`,
					);
				}
			}
			if (!ctx.config.challenges.dns01) {
				throw new AcmeError(
					'rejectedIdentifier',
					'server-managed DNS requires dns01 challenge to be enabled',
				);
			}
		}

		const order = ctx.repos.insertOrder({
			accountId,
			identifiers: ids,
			notBefore: payload.notBefore ?? null,
			notAfter: payload.notAfter ?? null,
			ttlSec: ctx.config.orderTtlSec,
			dnsPlacement: placementMode,
		});
		const authzList = [];
		for (const i of ids) {
			const authz = ctx.repos.insertAuthz(order.id, i, ctx.config.orderTtlSec);
			authzList.push(authz);
			// Wildcard identifiers — only DNS-01 is permitted (RFC 8555 §8.4).
			if (ctx.config.challenges.dns01) {
				const ch = ctx.repos.insertChallenge(authz.id, 'dns-01', randomToken());
				// Server-managed: queue + place TXT immediately so the validator
				// can do its job without waiting for the client to POST chall.
				if (placementMode === 'server-managed') {
					ctx.repos.queueChallenge(ch.id);
				}
			}
			// http-01 doesn't make sense for server-managed (we can't be the
			// client). Skip it in that mode.
			if (placementMode !== 'server-managed' && ctx.config.challenges.http01 && !authz.wildcard) {
				ctx.repos.insertChallenge(authz.id, 'http-01', randomToken());
			}
		}
		ctx.repos.audit({
			actorType: 'account',
			actorId: accountId,
			action: 'order.create',
			target: order.id,
			ip: req.ip,
			details: {identifiers: ids},
		});
		reply
			.code(201)
			.header('Replay-Nonce', ctx.nonces.issue())
			.header('Location', ctx.urls.order(order.id));
		return orderResponse(ctx, order.id);
	});

	// fetch order
	app.post('/order/:id', async (req, reply) => {
		const id = (req.params as any).id as string;
		await readJws(req, reply, ctx, ctx.urls.order(id));
		applyAcmeHeaders(reply, ctx);
		return orderResponse(ctx, id);
	});

	// fetch authorization
	app.post('/authz/:id', async (req, reply) => {
		const id = (req.params as any).id as string;
		await readJws(req, reply, ctx, ctx.urls.authz(id));
		const authz = ctx.repos.getAuthz(id);
		if (!authz) throw new AcmeError('malformed', 'No such authorization', 404);
		applyAcmeHeaders(reply, ctx);
		return authzResponse(ctx, authz.id);
	});

	// trigger challenge (POST with empty {} body kicks off validation)
	app.post('/chall/:id', async (req, reply) => {
		const id = (req.params as any).id as string;
		const parsed = await readJws(req, reply, ctx, ctx.urls.challenge(id));
		const ch = ctx.repos.getChallenge(id);
		if (!ch) throw new AcmeError('malformed', 'No such challenge', 404);
		const accountId = parsed.accountUrl ? ctx.urls.parseAccountId(parsed.accountUrl) : null;
		if (!accountId) throw new AcmeError('unauthorized', 'kid required');
		// Cheap ownership check: traverse authz → order.account_id.
		const authz = ctx.repos.getAuthz(ch.authz_id);
		const order = authz
			? (ctx.repos.db.prepare('SELECT account_id FROM orders WHERE id=?').get(authz.order_id) as
					| {account_id: string}
					| undefined)
			: undefined;
		if (!order || order.account_id !== accountId) {
			throw new AcmeError('unauthorized', 'Account does not own this challenge');
		}
		if (ch.status === 'pending') ctx.repos.queueChallenge(id);
		// RFC 8555 §7.5.1: challenge response MUST include "up" Link header
		// pointing to the authorization.
		applyAcmeHeaders(reply, ctx, `<${ctx.urls.authz(ch.authz_id)}>;rel="up"`);
		return challengeResponse(ctx, ch.id);
	});

	// finalize
	app.post('/order/:id/finalize', async (req, reply) => {
		const id = (req.params as any).id as string;
		const parsed = await readJws(req, reply, ctx, ctx.urls.finalize(id));
		const accountId = parsed.accountUrl ? ctx.urls.parseAccountId(parsed.accountUrl) : null;
		const order = ctx.repos.getOrder(id);
		if (!order) throw new AcmeError('malformed', 'No such order', 404);
		if (order.account_id !== accountId) {
			throw new AcmeError('unauthorized', 'Account does not own this order');
		}
		if (order.status !== 'ready') {
			throw new AcmeError('orderNotReady', `Order is ${order.status}, not ready`);
		}
		const payload = (parsed.payloadJson as any) ?? {};
		if (!payload.csr) throw new AcmeError('badCSR', 'Missing csr field');
		const csrDer = b64uDecode(payload.csr);
		const csr = parseCsr(csrDer);

		const identifiers = JSON.parse(order.identifiers_json) as Array<{type: string; value: string}>;
		const want = expectedSans(identifiers);
		const cmp = compareSans(want, csr.sans.length ? csr.sans : csr.commonName ? [csr.commonName] : []);
		if (!('ok' in cmp) || cmp.ok !== true) {
			throw new AcmeError('badCSR', (cmp as any).reason);
		}

		const notBefore = new Date();
		const notAfter = new Date(notBefore.getTime() + ctx.config.leafValidityDays * 86400_000);
		const commonName = csr.commonName || [...want][0]!;

		ctx.repos.setOrderStatus(order.id, 'processing');
		let result;
		try {
			result = issueLeaf({
				caCertPem: ctx.ca.certPem,
				caKeyPem: ctx.ca.keyPem,
				subjectPublicKeyPem: csr.subjectPublicKeyPem,
				commonName,
				sans: [...want],
				notBefore,
				notAfter,
			});
		} catch (e: any) {
			ctx.repos.setOrderStatus(order.id, 'invalid', {detail: e?.message ?? 'sign failed'});
			throw new AcmeError('serverInternal', `Signing failed: ${e?.message ?? e}`, 500);
		}

		// Denormalise identifiers onto the cert row so listings don't need a
		// JOIN. `identifiers` (from order.identifiers_json) preserves wildcard
		// `*.` prefixes as the client sent them.
		const cert = ctx.repos.insertCert({
			orderId: order.id,
			accountId: order.account_id,
			serialHex: result.serialHex,
			pem: result.certPem,
			chainPem: ctx.ca.chainPem,
			notBefore: result.notBefore.toISOString(),
			notAfter: result.notAfter.toISOString(),
			identifiers: identifiers.map(i => String(i.value)),
		});
		ctx.repos.attachCertToOrder(order.id, cert.id, csrDer);
		ctx.repos.audit({
			actorType: 'account',
			actorId: accountId!,
			action: 'cert.issue',
			target: cert.id,
			ip: req.ip,
			details: {serial: result.serialHex, identifiers, fingerprint: result.fingerprint},
		});

		reply
			.code(200)
			.header('Replay-Nonce', ctx.nonces.issue())
			.header('Location', ctx.urls.order(order.id));
		return orderResponse(ctx, order.id);
	});

	// download cert (PEM chain)
	app.post('/cert/:id', async (req, reply) => {
		const id = (req.params as any).id as string;
		const parsed = await readJws(req, reply, ctx, ctx.urls.cert(id));
		const cert = ctx.repos.getCert(id);
		if (!cert) throw new AcmeError('malformed', 'No such certificate', 404);
		const accountId = parsed.accountUrl ? ctx.urls.parseAccountId(parsed.accountUrl) : null;
		if (cert.account_id !== accountId) {
			throw new AcmeError('unauthorized', 'Not your certificate');
		}
		reply
			.code(200)
			.header('Replay-Nonce', ctx.nonces.issue())
			.header('Content-Type', 'application/pem-certificate-chain');
		return cert.pem.trim() + '\n' + cert.chain_pem.trim() + '\n';
	});

	// revokeCert
	app.post('/revoke-cert', async (req, reply) => {
		const parsed = await readJws(req, reply, ctx, ctx.urls.revokeCert());
		const accountId = parsed.accountUrl ? ctx.urls.parseAccountId(parsed.accountUrl) : null;
		const payload = (parsed.payloadJson as any) ?? {};
		if (!payload.certificate) throw new AcmeError('malformed', 'Missing certificate field');
		const der = b64uDecode(payload.certificate);
		// Compute serial out of the DER. Cheap: rely on node:crypto.X509Certificate.
		const x = new crypto.X509Certificate(der);
		const serialHex = x.serialNumber.toLowerCase();
		const cert = ctx.repos.getCertBySerial(serialHex);
		if (!cert) throw new AcmeError('malformed', 'Unknown certificate', 404);
		if (accountId && cert.account_id !== accountId) {
			throw new AcmeError('unauthorized', 'Not your certificate');
		}
		if (cert.revoked) throw new AcmeError('alreadyRevoked', 'Already revoked');
		const reason = typeof payload.reason === 'number' ? payload.reason : 0;
		ctx.repos.revokeCert(cert.id, reason);
		ctx.repos.audit({
			actorType: 'account',
			actorId: accountId ?? null,
			action: 'cert.revoke',
			target: cert.id,
			ip: req.ip,
			details: {serial: serialHex, reason},
		});
		applyAcmeHeaders(reply, ctx);
		reply.code(200).send();
	});
}

function accountResponse(ctx: ServerCtx, acct: import('./repos.js').AccountRow) {
	return {
		status: acct.status,
		contact: acct.contact_json ? JSON.parse(acct.contact_json) : [],
		orders: ctx.urls.account(acct.id) + '/orders',
	};
}

function orderResponse(ctx: ServerCtx, orderId: string) {
	const o = ctx.repos.getOrder(orderId)!;
	const authzs = ctx.repos.listAuthzByOrder(orderId);
	return {
		status: o.status,
		expires: o.expires_at,
		identifiers: JSON.parse(o.identifiers_json),
		notBefore: o.not_before ?? undefined,
		notAfter: o.not_after ?? undefined,
		authorizations: authzs.map(a => ctx.urls.authz(a.id)),
		finalize: ctx.urls.finalize(o.id),
		certificate: o.certificate_id ? ctx.urls.cert(o.certificate_id) : undefined,
		error: o.error_json ? JSON.parse(o.error_json) : undefined,
	};
}

function authzResponse(ctx: ServerCtx, authzId: string) {
	const a = ctx.repos.getAuthz(authzId)!;
	const challenges = ctx.repos.listChallengesByAuthz(authzId).map(c => challengeResponse(ctx, c.id));
	return {
		status: a.status,
		expires: a.expires_at,
		identifier: {
			type: a.identifier_type,
			value: a.wildcard ? '*.' + a.identifier_value : a.identifier_value,
		},
		wildcard: !!a.wildcard,
		challenges,
	};
}

function challengeResponse(ctx: ServerCtx, challengeId: string) {
	const c = ctx.repos.getChallenge(challengeId)!;
	return {
		type: c.type,
		url: ctx.urls.challenge(c.id),
		status: c.status,
		token: c.token,
		validated: c.validated_at ?? undefined,
		error: c.error_json ? JSON.parse(c.error_json) : undefined,
	};
}
