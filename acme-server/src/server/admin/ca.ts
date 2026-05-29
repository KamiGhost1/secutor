// CA-bridge endpoints — proves to a remote admin that the hub holds the
// expected signing key, and exposes the cert/chain. No mutating ops here yet;
// stage/promote/rollback land in a follow-up that needs an atomic hot-replace
// of CaMaterial in memory.
//
// Verify protocol (POST /admin/v1/ca/verify):
//   1. TUI sends 32 random bytes (`nonce`, base64url).
//   2. Hub computes message = SHA-256("secutor-ca-verify-v1" || nonce_bytes).
//      The prefix is what makes this safe to expose — the resulting bytes
//      can never collide with a TBSCertificate or CSR an attacker might want
//      a free signature on.
//   3. Hub signs `message` with the CA private key in RAM and returns
//      {signature, alg, certPem}.
//   4. TUI verifies the signature against the public key extracted from its
//      LOCAL copy of the CA cert. If the keys differ, signature verification
//      fails — that's the whole point of the protocol.

import crypto from 'crypto';
import type {FastifyInstance, FastifyReply, FastifyRequest} from 'fastify';
import type {AdminCtx} from './index.js';
import {AdminRole, roleAtLeast} from './auth.js';
import {StageError} from '../caStore.js';

const VERIFY_PREFIX = Buffer.from('secutor-ca-verify-v1', 'utf8');

function requireRole(req: FastifyRequest, reply: FastifyReply, need: AdminRole): boolean {
	const r = req.auth?.role;
	if (!r || !roleAtLeast(r, need)) {
		reply.code(403).send({error: 'forbidden', detail: `requires role ${need}`});
		return false;
	}
	return true;
}

export function registerCaRoutes(app: FastifyInstance, ctx: AdminCtx): void {
	/* ───── GET /admin/v1/ca — public CA metadata ───── */
	app.get('/admin/v1/ca', async (req, reply) => {
		if (!requireRole(req, reply, 'viewer')) return reply;
		const cert = new crypto.X509Certificate(ctx.ca.certPem);
		const der = cert.raw;
		const certFp = crypto.createHash('sha256').update(der).digest('hex');
		const spkiDer = cert.publicKey.export({type: 'spki', format: 'der'}) as Buffer;
		const spkiFp = crypto.createHash('sha256').update(spkiDer).digest('hex');
		return {
			name: ctx.ca.name,
			subject: cert.subject,
			issuer: cert.issuer,
			serial_hex: ctx.ca.serial,
			not_before: cert.validFrom,
			not_after: ctx.ca.notAfter.toISOString(),
			cert_fingerprint: certFp,
			spki_fingerprint: spkiFp,
			key_algorithm: keyAlgLabel(cert.publicKey),
			chain_depth: ctx.ca.chainDepth,
		};
	});

	/* ───── GET /admin/v1/ca/chain — full PEM chain (signing CA + parents, no root) ───── */
	app.get('/admin/v1/ca/chain', async (req, reply) => {
		if (!requireRole(req, reply, 'viewer')) return reply;
		reply.header('Content-Type', 'application/x-pem-file');
		return ctx.ca.certPem + (ctx.ca.chainPem || '');
	});

	/* ───── POST /admin/v1/ca/verify — proof-of-possession ───── */
	app.post('/admin/v1/ca/verify', async (req, reply) => {
		if (!requireRole(req, reply, 'operator')) return reply;
		const body = (req.body as any) ?? {};
		if (typeof body.nonce !== 'string') {
			reply.code(400).send({error: 'bad-request', detail: 'nonce (base64url) required'});
			return reply;
		}
		let nonce: Buffer;
		try {
			nonce = Buffer.from(body.nonce, 'base64url');
		} catch (e: any) {
			reply.code(400).send({error: 'bad-request', detail: 'nonce not base64url'});
			return reply;
		}
		if (nonce.length < 16 || nonce.length > 128) {
			reply.code(400).send({error: 'bad-request', detail: 'nonce must be 16–128 bytes'});
			return reply;
		}
		const message = crypto
			.createHash('sha256')
			.update(Buffer.concat([VERIFY_PREFIX, nonce]))
			.digest();

		const keyObj = crypto.createPrivateKey(ctx.ca.keyPem);
		const alg = keyAlgLabel(keyObj);
		const hash = signHashFor(alg);
		let signature: Buffer;
		try {
			if (alg.startsWith('rsa')) {
				// RSASSA-PSS with SHA-256 — chosen specifically to be different from
				// the PKCS#1 v1.5 we use for cert signatures, so even a stolen
				// signature can't be repurposed inside a TBSCertificate.
				signature = crypto.sign(hash, message, {
					key: keyObj,
					padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
					saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
				} as any);
			} else {
				signature = crypto.sign(hash, message, keyObj);
			}
		} catch (e: any) {
			reply.code(500).send({error: 'sign-failed', detail: e?.message ?? String(e)});
			return reply;
		}
		ctx.repos.audit({
			actorType: 'admin',
			actorId: req.auth?.clientFingerprint ?? null,
			action: 'ca.verify',
			target: null,
			ip: req.ip,
		});
		return {
			alg,
			hash: hash ?? 'ed25519-intrinsic',
			signature: signature.toString('base64'),
			cert_pem: ctx.ca.certPem,
		};
	});

	/* ───── POST /admin/v1/ca/stage — load candidate (owner) ───── */
	app.post('/admin/v1/ca/stage', async (req, reply) => {
		if (!requireRole(req, reply, 'owner')) return reply;
		if (!ctx.caStore) {
			reply.code(501).send({error: 'rotation-disabled'});
			return reply;
		}
		const body = (req.body as any) ?? {};
		const certPem = String(body.cert_pem ?? '');
		const keyPem = String(body.key_pem ?? '');
		const chainPem = String(body.chain_pem ?? '');
		if (!certPem || !keyPem) {
			reply.code(400).send({error: 'missing-fields', detail: 'cert_pem and key_pem required'});
			return reply;
		}
		try {
			const staged = ctx.caStore.stage({certPem, keyPem, chainPem});
			ctx.repos.audit({
				actorType: 'admin',
				actorId: req.auth?.clientFingerprint ?? null,
				action: 'ca.stage',
				ip: req.ip,
				details: {fingerprint: staged.fingerprint, not_after: staged.notAfter.toISOString()},
			});
			return {
				staged: true,
				fingerprint: staged.fingerprint,
				key_algorithm: staged.keyAlgorithm,
				not_after: staged.notAfter.toISOString(),
				common_name: staged.commonName,
				staged_at: staged.stagedAt.toISOString(),
			};
		} catch (e) {
			if (e instanceof StageError) {
				reply.code(400).send({error: e.code, detail: e.message});
				return reply;
			}
			throw e;
		}
	});

	/* ───── GET /admin/v1/ca/staged ───── */
	app.get('/admin/v1/ca/staged', async (req, reply) => {
		if (!requireRole(req, reply, 'viewer')) return reply;
		if (!ctx.caStore) {
			reply.code(501).send({error: 'rotation-disabled'});
			return reply;
		}
		const s = ctx.caStore.getStaged();
		if (!s) return {staged: false};
		return {
			staged: true,
			fingerprint: s.fingerprint,
			key_algorithm: s.keyAlgorithm,
			not_after: s.notAfter.toISOString(),
			common_name: s.commonName,
			staged_at: s.stagedAt.toISOString(),
		};
	});

	/* ───── DELETE /admin/v1/ca/staged ───── */
	app.delete('/admin/v1/ca/staged', async (req, reply) => {
		if (!requireRole(req, reply, 'owner')) return reply;
		if (!ctx.caStore) {
			reply.code(501).send({error: 'rotation-disabled'});
			return reply;
		}
		const had = !!ctx.caStore.getStaged();
		ctx.caStore.discardStaged();
		if (had) {
			ctx.repos.audit({
				actorType: 'admin',
				actorId: req.auth?.clientFingerprint ?? null,
				action: 'ca.stage.discard',
				ip: req.ip,
			});
		}
		return {discarded: had};
	});

	/* ───── POST /admin/v1/ca/promote ───── */
	app.post('/admin/v1/ca/promote', async (req, reply) => {
		if (!requireRole(req, reply, 'owner')) return reply;
		if (!ctx.caStore) {
			reply.code(501).send({error: 'rotation-disabled'});
			return reply;
		}
		try {
			const r = ctx.caStore.promote();
			ctx.repos.audit({
				actorType: 'admin',
				actorId: req.auth?.clientFingerprint ?? null,
				action: 'ca.promote',
				ip: req.ip,
				details: r,
			});
			return {
				promoted: true,
				previous_fingerprint: r.previousFingerprint,
				new_fingerprint: r.newFingerprint,
				rollback_available: ctx.caStore.hasRollback(),
			};
		} catch (e) {
			if (e instanceof StageError) {
				reply.code(400).send({error: e.code, detail: e.message});
				return reply;
			}
			throw e;
		}
	});

	/* ───── POST /admin/v1/jobs/reissue ───── */
	app.post('/admin/v1/jobs/reissue', async (req, reply) => {
		if (!requireRole(req, reply, 'owner')) return reply;
		if (!ctx.reissueWorker) {
			reply.code(501).send({error: 'reissue-disabled'});
			return reply;
		}
		const body = (req.body as any) ?? {};
		const scope = body.scope as 'all-active' | 'by-account' | 'by-identifier-pattern';
		if (!['all-active', 'by-account', 'by-identifier-pattern'].includes(scope)) {
			reply.code(400).send({error: 'bad-scope'});
			return reply;
		}
		const job = ctx.reissueWorker.startJob({
			scope,
			accountIds: Array.isArray(body.accountIds) ? body.accountIds : undefined,
			identifierPattern: typeof body.identifierPattern === 'string' ? body.identifierPattern : undefined,
			ratePerSec: typeof body.ratePerSec === 'number' ? body.ratePerSec : undefined,
			actorFp: req.auth?.clientFingerprint ?? null,
		});
		ctx.repos.audit({
			actorType: 'admin',
			actorId: req.auth?.clientFingerprint ?? null,
			action: 'reissue.start',
			target: job.id,
			ip: req.ip,
			details: {scope, total: job.total},
		});
		return job;
	});

	/* ───── GET /admin/v1/jobs/:id ───── */
	app.get('/admin/v1/jobs/:id', async (req, reply) => {
		if (!requireRole(req, reply, 'viewer')) return reply;
		const id = (req.params as any).id as string;
		const job = ctx.repos.getReissueJob(id);
		if (!job) {
			reply.code(404).send({error: 'not-found'});
			return reply;
		}
		return job;
	});

	/* ───── POST /admin/v1/jobs/:id/cancel ───── */
	app.post('/admin/v1/jobs/:id/cancel', async (req, reply) => {
		if (!requireRole(req, reply, 'owner')) return reply;
		if (!ctx.reissueWorker) {
			reply.code(501).send({error: 'reissue-disabled'});
			return reply;
		}
		const id = (req.params as any).id as string;
		const ok = ctx.reissueWorker.cancel(id);
		if (!ok) {
			reply.code(409).send({error: 'cannot-cancel'});
			return reply;
		}
		ctx.repos.audit({
			actorType: 'admin',
			actorId: req.auth?.clientFingerprint ?? null,
			action: 'reissue.cancel',
			target: id,
			ip: req.ip,
		});
		return {cancelled: true};
	});

	/* ───── POST /admin/v1/ca/rollback ───── */
	app.post('/admin/v1/ca/rollback', async (req, reply) => {
		if (!requireRole(req, reply, 'owner')) return reply;
		if (!ctx.caStore) {
			reply.code(501).send({error: 'rotation-disabled'});
			return reply;
		}
		try {
			const r = ctx.caStore.rollback();
			ctx.repos.audit({
				actorType: 'admin',
				actorId: req.auth?.clientFingerprint ?? null,
				action: 'ca.rollback',
				ip: req.ip,
				details: r,
			});
			return {rolled_back: true, restored_fingerprint: r.restoredFingerprint};
		} catch (e) {
			if (e instanceof StageError) {
				reply.code(400).send({error: e.code, detail: e.message});
				return reply;
			}
			throw e;
		}
	});
}

function keyAlgLabel(key: crypto.KeyObject): string {
	const t = key.asymmetricKeyType;
	if (t === 'rsa' || t === 'rsa-pss') {
		const bits = (key.asymmetricKeyDetails as any)?.modulusLength ?? 2048;
		if (bits >= 4096) return 'rsa-4096';
		if (bits >= 3072) return 'rsa-3072';
		return 'rsa-2048';
	}
	if (t === 'ec') {
		const curve = (key.asymmetricKeyDetails as any)?.namedCurve;
		if (curve === 'P-384' || curve === 'secp384r1') return 'ecdsa-p384';
		return 'ecdsa-p256';
	}
	if (t === 'ed25519') return 'ed25519';
	throw new Error(`unsupported key type ${t}`);
}

function signHashFor(alg: string): string | null {
	if (alg === 'ed25519') return null;
	if (alg === 'ecdsa-p384') return 'sha384';
	return 'sha256';
}

/**
 * Verify a /ca/verify response on the client side. Exported so the TUI / a
 * CLI / a third-party tool can do it without duplicating the protocol.
 *
 * Returns true iff `signature` was produced over SHA-256("secutor-ca-verify-v1"
 * || nonce) by the private key paired with `expectedPublicKeyPem`.
 */
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
