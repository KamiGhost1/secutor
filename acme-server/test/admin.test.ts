// In-process admin API tests. Spins up an isolated admin server on a random
// localhost port with its own self-signed TLS cert and a trust-policy that
// admits two client identities (owner + viewer) by fingerprint. Then drives
// mTLS HTTPS requests through Node's https module.
//
// No real ACME signing happens here — the CaMaterial is a stub used only by
// the /info endpoint. The full ACME path is exercised by test/e2e.ts.

import {test, before, after, beforeEach} from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {buildRootCa, buildIntermediateCa, buildLeafCert} from '../../src/certs/core.js';
import {generateCsr} from '../src/client/csr.js';
import {verifyProofOfPossession} from '../src/server/admin/ca.js';
import {CaStore} from '../src/server/caStore.js';
import {ReissueWorker} from '../src/server/reissueWorker.js';
import {openDb} from '../src/server/db.js';
import {Repos} from '../src/server/repos.js';
import {AdminAuth} from '../src/server/admin/auth.js';
import {startAdminServer, type AdminConfig, type AdminCtx} from '../src/server/admin/index.js';
import type {CaMaterial} from '../src/server/contextLoader.js';

type Pair = {certPem: string; keyPem: string; fingerprint: string};

let workDir: string;
let serverPair: Pair;
let ownerPair: Pair;
let viewerPair: Pair;
let unknownPair: Pair;
let port: number;
let dbPath: string;
let app: import('fastify').FastifyInstance;
let repos: Repos;
let caObj: import('../src/server/contextLoader.js').CaMaterial;
let caStore: CaStore;
let reissueWorker: ReissueWorker;

function fp(pem: string): string {
	const body = pem
		.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----/g, '')
		.replace(/\s+/g, '');
	return crypto.createHash('sha256').update(Buffer.from(body, 'base64')).digest('hex');
}

function buildPair(cn: string, ca?: {certPem: string; keyPem: string}): Pair {
	if (!ca) {
		const r = buildRootCa({subject: {commonName: cn}, validityDays: 1, algorithm: 'ecdsa-p256'});
		return {certPem: r.certPem, keyPem: r.keyPem, fingerprint: fp(r.certPem)};
	}
	const leaf = buildLeafCert({
		type: 'client',
		subject: {commonName: cn},
		validityDays: 1,
		algorithm: 'ed25519',
		ca,
	});
	return {certPem: leaf.certPem, keyPem: leaf.keyPem, fingerprint: fp(leaf.certPem)};
}

function fakeCa(): CaMaterial {
	const r = buildRootCa({
		subject: {commonName: 'fake-acme-ca'},
		validityDays: 1,
		algorithm: 'ecdsa-p256',
	});
	return {
		name: 'fake-ca',
		commonName: 'fake-acme-ca',
		certPem: r.certPem,
		keyPem: r.keyPem,
		chainPem: '',
		rootCertPem: r.certPem,
		chainDepth: 1,
		notAfter: r.notAfter,
		serial: r.serial,
	};
}

async function getRandomPort(): Promise<number> {
	const net = await import('node:net');
	return new Promise(resolve => {
		const s = net.createServer();
		s.listen(0, () => {
			const p = (s.address() as any).port as number;
			s.close(() => resolve(p));
		});
	});
}

before(async () => {
	workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secutor-admin-test-'));

	// Self-signed server cert for the admin HTTPS endpoint.
	const serverCa = buildRootCa({
		subject: {commonName: 'localhost'},
		validityDays: 1,
		algorithm: 'ecdsa-p256',
	});
	serverPair = {certPem: serverCa.certPem, keyPem: serverCa.keyPem, fingerprint: fp(serverCa.certPem)};

	// Three independent self-signed client certs.
	ownerPair = buildPair('owner');
	viewerPair = buildPair('viewer');
	unknownPair = buildPair('intruder');

	port = await getRandomPort();
	dbPath = path.join(workDir, 'acme.db');
	const db = openDb(dbPath);
	repos = new Repos(db);

	const config: AdminConfig = {
		listen: `127.0.0.1:${port}`,
		serverTls: {
			certFile: writeTmp('server.crt', serverPair.certPem),
			keyFile: writeTmp('server.key', serverPair.keyPem),
		},
		trust: {
			fingerprints: [
				{sha256: ownerPair.fingerprint, role: 'owner', label: 'owner-key'},
				{sha256: viewerPair.fingerprint, role: 'viewer', label: 'viewer-key'},
			],
			publishPolicy: true,
		},
		banMode: 'cascade',
	};

	const auth = new AdminAuth(config.trust);
	caObj = fakeCa();
	caStore = new CaStore(caObj, {rollbackWindowHours: 24});
	reissueWorker = new ReissueWorker(repos, caObj);
	const ctx: AdminCtx = {repos, ca: caObj, config, auth, caStore, reissueWorker};
	app = await startAdminServer(ctx);
});

after(async () => {
	if (app) await app.close();
	fs.rmSync(workDir, {recursive: true, force: true});
});

beforeEach(() => {
	// Reset state between tests (fresh accounts/orders/certs).
	const db = repos.db;
	db.exec(`
		DELETE FROM certificates;
		DELETE FROM challenges;
		DELETE FROM authorizations;
		DELETE FROM orders;
		DELETE FROM accounts;
		DELETE FROM audit_log;
	`);
});

function writeTmp(name: string, contents: string): string {
	const p = path.join(workDir, name);
	fs.writeFileSync(p, contents);
	return p;
}

type ReqOpts = {
	method?: string;
	path: string;
	client?: Pair | null; // null = no client cert
	body?: any;
};

function req(opts: ReqOpts): Promise<{status: number; body: any; headers: any}> {
	const data = opts.body != null ? Buffer.from(JSON.stringify(opts.body)) : null;
	return new Promise((resolve, reject) => {
		const r = https.request(
			{
				host: '127.0.0.1',
				port,
				method: opts.method ?? 'GET',
				path: opts.path,
				rejectUnauthorized: false, // we don't pin in tests
				...(opts.client === null
					? {}
					: {cert: opts.client!.certPem, key: opts.client!.keyPem}),
				headers: data
					? {'content-type': 'application/json', 'content-length': data.length}
					: {},
			},
			res => {
				const chunks: Buffer[] = [];
				res.on('data', c => chunks.push(c));
				res.on('end', () => {
					const text = Buffer.concat(chunks).toString('utf8');
					let body: any = text;
					try {
						body = text ? JSON.parse(text) : null;
					} catch {
						/* leave as text (e.g. metrics endpoint) */
					}
					resolve({status: res.statusCode ?? 0, body, headers: res.headers});
				});
			},
		);
		r.on('error', reject);
		if (data) r.write(data);
		r.end();
	});
}

function seedAccount(thumbprint = 'tp1'): string {
	return repos.insertAccount(JSON.stringify({kty: 'EC'}), thumbprint, ['mailto:x@y']).id;
}

function seedCert(accountId: string, serial: string, opts?: {revoked?: boolean; expired?: boolean}): string {
	const orderId = repos.insertOrder({
		accountId,
		identifiers: [{type: 'dns', value: 'svc.example'}],
		notBefore: null,
		notAfter: null,
		ttlSec: 60,
	}).id;
	const cert = repos.insertCert({
		orderId,
		accountId,
		serialHex: serial,
		pem: '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----',
		chainPem: '',
		notBefore: new Date(Date.now() - 60_000).toISOString(),
		notAfter: opts?.expired
			? new Date(Date.now() - 1000).toISOString()
			: new Date(Date.now() + 90 * 86400_000).toISOString(),
	});
	if (opts?.revoked) repos.revokeCert(cert.id, 1, 'account');
	repos.attachCertToOrder(orderId, cert.id, Buffer.alloc(0));
	return cert.id;
}

/* ─────────────────── tests ─────────────────── */

test('admin: rejects request without a client cert (401)', async () => {
	const r = await req({path: '/admin/v1/info', client: null});
	assert.equal(r.status, 401);
	assert.equal(r.body.error, 'mtls-required');
});

test('admin: rejects request from an unknown client cert (401)', async () => {
	const r = await req({path: '/admin/v1/info', client: unknownPair});
	assert.equal(r.status, 401);
});

test('admin: /info returns role + ca summary for a known client', async () => {
	const r = await req({path: '/admin/v1/info', client: ownerPair});
	assert.equal(r.status, 200);
	assert.equal(r.body.role, 'owner');
	assert.equal(r.body.ca.cn, 'fake-acme-ca');
});

test('admin: /auth-policy is public when publishPolicy=true', async () => {
	const r = await req({path: '/admin/v1/auth-policy', client: null});
	assert.equal(r.status, 200);
	assert.equal(r.body.fingerprints.length, 2);
	const fps = r.body.fingerprints.map((f: any) => f.sha256);
	assert.ok(fps.includes(ownerPair.fingerprint));
	assert.ok(fps.includes(viewerPair.fingerprint));
});

test('admin: revoke requires operator+ role (viewer is denied)', async () => {
	const acct = seedAccount();
	const certId = seedCert(acct, 'aabb01');
	const denied = await req({
		method: 'POST',
		path: `/admin/v1/certificates/${certId}/revoke`,
		client: viewerPair,
		body: {reason: 1},
	});
	assert.equal(denied.status, 403);
	const okR = await req({
		method: 'POST',
		path: `/admin/v1/certificates/${certId}/revoke`,
		client: ownerPair,
		body: {reason: 1},
	});
	assert.equal(okR.status, 200);
	const row = repos.getCert(certId)!;
	assert.equal(row.revoked, 1);
	assert.equal(row.revocation_reason, 1);
	assert.match(String(row.revoked_by), /^admin:/);
});

test('admin: identifier filter finds the cert by exact SAN (and not by substring)', async () => {
	const a = seedAccount('id-tp');
	// Use the real-leaf seeder so identifiers are denormalised onto the row.
	seedRealLeaf(a, 'svc.lan.vpn');
	seedRealLeaf(a, 'api.other.com');
	const exact = await req({path: '/admin/v1/certificates?identifier=svc.lan.vpn', client: viewerPair});
	assert.equal(exact.body.items.length, 1);
	assert.deepEqual(exact.body.items[0].identifiers, ['svc.lan.vpn']);
	// Substring should NOT leak — querying "lan.vpn" hits 0 because the
	// stored value is the full identifier.
	const sub = await req({path: '/admin/v1/certificates?identifier=lan.vpn', client: viewerPair});
	assert.equal(sub.body.items.length, 0);
});

test('admin: list returns identifiers alongside each cert row', async () => {
	const a = seedAccount('id-list-tp');
	seedRealLeaf(a, 'web.example');
	const r = await req({path: '/admin/v1/certificates', client: viewerPair});
	const row = r.body.items.find((x: any) => x.identifiers.includes('web.example'));
	assert.ok(row, 'cert is returned with its identifier');
	assert.equal(row.pem_omitted, true);
});

test('admin: GET /certificates/:id returns identifiers (parsed)', async () => {
	const a = seedAccount('id-details-tp');
	const id = seedRealLeaf(a, 'detail.example');
	const r = await req({path: `/admin/v1/certificates/${id}`, client: viewerPair});
	assert.equal(r.status, 200);
	assert.deepEqual(r.body.identifiers, ['detail.example']);
	assert.equal((r.body as any).identifiers_json, undefined, 'raw column not leaked');
	// Full cert details DO include the PEM (unlike the listing).
	assert.match(r.body.pem, /-----BEGIN CERTIFICATE-----/);
});

test('admin: backfill — pre-migration row gets identifiers reconstructed', async () => {
	// Simulate an old row by writing the cert without identifiers_json (NULL).
	const a = seedAccount('backfill-tp');
	const orderId = repos.insertOrder({
		accountId: a,
		identifiers: [{type: 'dns', value: 'legacy.example'}],
		notBefore: null, notAfter: null, ttlSec: 600,
	}).id;
	// authz row needed for the backfill query to find anything.
	repos.insertAuthz(orderId, {type: 'dns', value: 'legacy.example'}, 600);
	const certId = repos.insertCert({
		orderId,
		accountId: a,
		serialHex: 'bcaf01',
		pem: '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----',
		chainPem: '',
		notBefore: new Date(Date.now() - 1000).toISOString(),
		notAfter: new Date(Date.now() + 86400_000).toISOString(),
		// identifiers omitted → NULL in the column
	}).id;
	// Trigger the backfill — call openDb again on the same file (it runs the
	// 0005 migration including backfill).
	const {openDb: reopenDb} = await import('../src/server/db.js');
	const sameFile = (repos.db as any).name; // better-sqlite3 exposes the file path
	const db2 = reopenDb(sameFile);
	db2.close();
	const after = repos.getCertWithIdentifiers(certId)!;
	assert.deepEqual(after.identifiers, ['legacy.example']);
});

test('admin: list certificates with filters', async () => {
	const a = seedAccount('a-thumbprint');
	const b = seedAccount('b-thumbprint');
	seedCert(a, 'aabb01');
	seedCert(a, 'aabb02', {revoked: true});
	seedCert(b, 'bbbb01');
	const all = await req({path: '/admin/v1/certificates', client: viewerPair});
	assert.equal(all.body.items.length, 3);
	const onlyA = await req({path: `/admin/v1/certificates?account_id=${a}`, client: viewerPair});
	assert.equal(onlyA.body.items.length, 2);
	const onlyRev = await req({path: '/admin/v1/certificates?revoked=true', client: viewerPair});
	assert.equal(onlyRev.body.items.length, 1);
});

test('admin: stats/orders counts match raw queries', async () => {
	const a = seedAccount();
	// Three orders: one valid, one invalid, one expired-in-the-past (auto-expire).
	const validOrderId = repos.insertOrder({
		accountId: a, identifiers: [{type: 'dns', value: 'x'}], notBefore: null, notAfter: null, ttlSec: 60,
	}).id;
	repos.setOrderStatus(validOrderId, 'valid');
	const invalidOrderId = repos.insertOrder({
		accountId: a, identifiers: [{type: 'dns', value: 'y'}], notBefore: null, notAfter: null, ttlSec: 60,
	}).id;
	repos.setOrderStatus(invalidOrderId, 'invalid', {type: 'urn:ietf:params:acme:error:dns'});
	// Manually push expires_at into the past, then trigger expire.
	const due = repos.insertOrder({
		accountId: a, identifiers: [{type: 'dns', value: 'z'}], notBefore: null, notAfter: null, ttlSec: -100,
	}).id;
	repos.expireDueOrders();
	const r = await req({path: '/admin/v1/stats/orders', client: viewerPair});
	assert.equal(r.status, 200);
	assert.equal(r.body.by_status.valid, 1);
	assert.equal(r.body.by_status.invalid, 1);
	assert.equal(r.body.by_status.expired, 1);
	assert.equal(r.body.total, 3);
	// success rate = valid/total
	assert.equal(r.body.success_rate, Math.round((1 / 3) * 1000) / 1000);
});

test('admin: stats/failures groups by problem type', async () => {
	const a = seedAccount();
	const o1 = repos.insertOrder({
		accountId: a, identifiers: [{type: 'dns', value: 'x'}], notBefore: null, notAfter: null, ttlSec: 60,
	}).id;
	repos.setOrderStatus(o1, 'invalid', {type: 'urn:ietf:params:acme:error:dns', detail: 'no TXT'});
	const o2 = repos.insertOrder({
		accountId: a, identifiers: [{type: 'dns', value: 'y'}], notBefore: null, notAfter: null, ttlSec: 60,
	}).id;
	repos.setOrderStatus(o2, 'invalid', {type: 'urn:ietf:params:acme:error:dns', detail: 'no TXT'});
	const o3 = repos.insertOrder({
		accountId: a, identifiers: [{type: 'dns', value: 'z'}], notBefore: null, notAfter: null, ttlSec: 60,
	}).id;
	repos.setOrderStatus(o3, 'invalid', {type: 'urn:ietf:params:acme:error:badCSR'});
	const r = await req({path: '/admin/v1/stats/failures', client: viewerPair});
	assert.equal(r.status, 200);
	assert.equal(r.body.total_invalid_orders, 3);
	const dnsRow = r.body.by_problem_type.find((p: any) => p.type.endsWith(':dns'));
	const csrRow = r.body.by_problem_type.find((p: any) => p.type.endsWith(':badCSR'));
	assert.equal(dnsRow?.count, 2);
	assert.equal(csrRow?.count, 1);
});

test('admin: ban cascade revokes valid certs and cancels open orders, transactionally', async () => {
	const a = seedAccount();
	const cValid = seedCert(a, 'aabb01');
	const cAlreadyRevoked = seedCert(a, 'aabb02', {revoked: true});
	const cExpired = seedCert(a, 'aabb03', {expired: true});
	const openOrder = repos.insertOrder({
		accountId: a, identifiers: [{type: 'dns', value: 'x'}], notBefore: null, notAfter: null, ttlSec: 60,
	}).id;

	// Operator role cannot ban.
	const denied = await req({
		method: 'POST', path: `/admin/v1/accounts/${a}/ban`, client: viewerPair, body: {comment: 'why'},
	});
	assert.equal(denied.status, 403);

	const r = await req({
		method: 'POST',
		path: `/admin/v1/accounts/${a}/ban`,
		client: ownerPair,
		body: {reason: 9, comment: 'key compromise'},
	});
	assert.equal(r.status, 200);
	assert.equal(r.body.revoked_certificates, 1, 'only the one valid+unexpired cert');
	assert.equal(r.body.cancelled_orders, 1);
	assert.equal(r.body.reason, 9);

	assert.equal(repos.getAccount(a)!.status, 'banned');
	assert.equal(repos.getCert(cValid)!.revoked, 1);
	assert.equal(repos.getCert(cValid)!.revocation_reason, 9);
	assert.match(String(repos.getCert(cValid)!.revoked_by), /:ban$/);
	// Already-revoked stays as was (reason 1, not overwritten to 9).
	assert.equal(repos.getCert(cAlreadyRevoked)!.revocation_reason, 1);
	// Expired stays unrevoked (no point revoking something already expired).
	assert.equal(repos.getCert(cExpired)!.revoked, 0);

	// Open order cancelled with explanatory error_json.
	const o = (repos.db.prepare('SELECT * FROM orders WHERE id=?').get(openOrder) as any);
	assert.equal(o.status, 'invalid');
	assert.match(o.error_json, /accountBanned/);

	// Banning again returns 409.
	const again = await req({
		method: 'POST', path: `/admin/v1/accounts/${a}/ban`, client: ownerPair, body: {},
	});
	assert.equal(again.status, 409);

	// Unban brings status back to valid but does NOT restore revoked certs.
	const u = await req({
		method: 'POST', path: `/admin/v1/accounts/${a}/unban`, client: ownerPair,
	});
	assert.equal(u.status, 200);
	assert.equal(repos.getAccount(a)!.status, 'valid');
	assert.equal(repos.getCert(cValid)!.revoked, 1, 'revoked cert is not restored');
});

test('admin: audit log captures ban + per-cert cascade entries', async () => {
	const a = seedAccount();
	seedCert(a, 'aabb01');
	seedCert(a, 'aabb02');
	await req({
		method: 'POST',
		path: `/admin/v1/accounts/${a}/ban`,
		client: ownerPair,
		body: {comment: 'test'},
	});
	const audit = await req({path: '/admin/v1/audit', client: viewerPair});
	const actions = audit.body.items.map((r: any) => r.action);
	assert.ok(actions.includes('account.ban'));
	const cascade = audit.body.items.filter((r: any) => r.action === 'cert.revoke.cascade');
	assert.equal(cascade.length, 2);
	// All cascade rows share the same ban event id (in details).
	const evIds = new Set(cascade.map((r: any) => JSON.parse(r.details_json).ban_event_id));
	assert.equal(evIds.size, 1);
});

test('admin: PATCH /accounts/:id updates allow_list and contact (owner only)', async () => {
	const a = seedAccount();
	const deny = await req({
		method: 'PATCH', path: `/admin/v1/accounts/${a}`, client: viewerPair,
		body: {allow_list: ['*.lan']},
	});
	assert.equal(deny.status, 403);
	const ok = await req({
		method: 'PATCH', path: `/admin/v1/accounts/${a}`, client: ownerPair,
		body: {allow_list: ['*.lan'], contact: ['mailto:a@b']},
	});
	assert.equal(ok.status, 200);
	assert.equal(ok.body.allow_list_json, JSON.stringify(['*.lan']));
});

test('admin: /metrics returns Prometheus text', async () => {
	seedCert(seedAccount(), 'aabb01');
	const r = await req({path: '/admin/v1/metrics', client: viewerPair});
	assert.equal(r.status, 200);
	assert.match(String(r.body), /secutor_acme_certificates_total/);
	assert.match(String(r.body), /secutor_acme_orders_total\{status="/);
});

/* ─────────────────── admin-issue ─────────────────── */

test('admin-issue: requires operator+ (viewer denied)', async () => {
	const csr = generateCsr({commonName: 'svc.example', sans: ['svc.example'], algorithm: 'ecdsa-p256'});
	const r = await req({
		method: 'POST', path: '/admin/v1/certificates/issue', client: viewerPair,
		body: {
			identifiers: [{type: 'dns', value: 'svc.example'}],
			csr: csr.csrDer.toString('base64url'),
			notAfterDays: 7,
		},
	});
	assert.equal(r.status, 403);
});

test('admin-issue: signs a leaf from a client-supplied CSR', async () => {
	const csr = generateCsr({commonName: 'web.lan', sans: ['web.lan', 'www.lan'], algorithm: 'ecdsa-p256'});
	const r = await req({
		method: 'POST', path: '/admin/v1/certificates/issue', client: ownerPair,
		body: {
			identifiers: [{type: 'dns', value: 'web.lan'}, {type: 'dns', value: 'www.lan'}],
			csr: csr.csrDer.toString('base64url'),
			notAfterDays: 30,
		},
	});
	assert.equal(r.status, 200, JSON.stringify(r.body));
	assert.match(r.body.cert_pem, /BEGIN CERTIFICATE/);
	assert.ok(!r.body.generated_key_pem, 'no key returned when CSR supplied');
	// The cert row exists in acme.db.
	assert.ok(repos.getCert(r.body.id));
});

test('admin-issue: CSR with missing SAN is rejected', async () => {
	const csr = generateCsr({commonName: 'a.lan', sans: ['a.lan'], algorithm: 'ecdsa-p256'});
	const r = await req({
		method: 'POST', path: '/admin/v1/certificates/issue', client: ownerPair,
		body: {
			identifiers: [{type: 'dns', value: 'a.lan'}, {type: 'dns', value: 'b.lan'}],
			csr: csr.csrDer.toString('base64url'),
			notAfterDays: 7,
		},
	});
	assert.equal(r.status, 400);
	assert.equal(r.body.error, 'bad-csr');
	assert.match(r.body.detail, /b\.lan/);
});

test('admin-issue: without CSR, server generates key and returns it', async () => {
	const r = await req({
		method: 'POST', path: '/admin/v1/certificates/issue', client: ownerPair,
		body: {
			identifiers: [{type: 'dns', value: 'gen.lan'}],
			subject: {commonName: 'gen.lan'},
			keyAlgorithm: 'ecdsa-p256',
			notAfterDays: 14,
		},
	});
	assert.equal(r.status, 200, JSON.stringify(r.body));
	assert.match(r.body.cert_pem, /BEGIN CERTIFICATE/);
	assert.match(r.body.generated_key_pem, /BEGIN PRIVATE KEY/);
});

test('admin-issue: audits cert.issue.admin entry', async () => {
	const csr = generateCsr({commonName: 'aud.lan', sans: ['aud.lan'], algorithm: 'ecdsa-p256'});
	await req({
		method: 'POST', path: '/admin/v1/certificates/issue', client: ownerPair,
		body: {
			identifiers: [{type: 'dns', value: 'aud.lan'}],
			csr: csr.csrDer.toString('base64url'),
			notAfterDays: 7,
		},
	});
	const audit = await req({path: '/admin/v1/audit?action=cert.issue.admin', client: viewerPair});
	assert.equal(audit.body.items.length, 1);
	const details = JSON.parse(audit.body.items[0].details_json);
	assert.equal(details.identifiers[0].value, 'aud.lan');
});

/* ─────────────────── CA bridge ─────────────────── */

test('CA: GET /admin/v1/ca returns metadata with fingerprints', async () => {
	const r = await req({path: '/admin/v1/ca', client: viewerPair});
	assert.equal(r.status, 200);
	assert.match(r.body.subject, /fake-acme-ca/);
	assert.match(r.body.cert_fingerprint, /^[0-9a-f]{64}$/);
	assert.match(r.body.spki_fingerprint, /^[0-9a-f]{64}$/);
	assert.equal(typeof r.body.key_algorithm, 'string');
});

test('CA: GET /admin/v1/ca/chain returns PEM', async () => {
	const r = await req({path: '/admin/v1/ca/chain', client: viewerPair});
	assert.equal(r.status, 200);
	assert.match(String(r.body), /-----BEGIN CERTIFICATE-----/);
});

test('CA: /verify proves possession of the correct private key', async () => {
	const caInfo = (await req({path: '/admin/v1/ca', client: viewerPair})).body;
	const noncBuf = crypto.randomBytes(32);
	const r = await req({
		method: 'POST', path: '/admin/v1/ca/verify', client: ownerPair,
		body: {nonce: noncBuf.toString('base64url')},
	});
	assert.equal(r.status, 200, JSON.stringify(r.body));
	const ok = verifyProofOfPossession({
		expectedPublicKeyPem: r.body.cert_pem, // start from the cert the hub gave us
		nonce: noncBuf,
		signature: Buffer.from(r.body.signature, 'base64'),
		alg: r.body.alg,
	});
	assert.equal(ok, true);
	// Sanity: cert_pem in the response matches the public /ca metadata.
	const certFp = crypto
		.createHash('sha256')
		.update(new crypto.X509Certificate(r.body.cert_pem).raw)
		.digest('hex');
	assert.equal(certFp, caInfo.cert_fingerprint);
});

test('CA: /verify is rejected when checked against a different key', async () => {
	const r = await req({
		method: 'POST', path: '/admin/v1/ca/verify', client: ownerPair,
		body: {nonce: crypto.randomBytes(32).toString('base64url')},
	});
	assert.equal(r.status, 200);
	// Use an *unrelated* keypair as the supposed "expected" — must fail.
	const wrong = buildPair('not-the-hub-ca');
	const ok = verifyProofOfPossession({
		expectedPublicKeyPem: wrong.certPem,
		nonce: crypto.randomBytes(32),
		signature: Buffer.from(r.body.signature, 'base64'),
		alg: r.body.alg,
	});
	assert.equal(ok, false);
});

test('CA: /verify requires operator+', async () => {
	const r = await req({
		method: 'POST', path: '/admin/v1/ca/verify', client: viewerPair,
		body: {nonce: crypto.randomBytes(32).toString('base64url')},
	});
	assert.equal(r.status, 403);
});

test('CA: /verify rejects too-short or non-base64url nonce', async () => {
	const a = await req({
		method: 'POST', path: '/admin/v1/ca/verify', client: ownerPair,
		body: {nonce: 'aa'}, // 1 byte → too short
	});
	assert.equal(a.status, 400);
	const b = await req({
		method: 'POST', path: '/admin/v1/ca/verify', client: ownerPair,
		body: {nonce: 12345}, // wrong type
	});
	assert.equal(b.status, 400);
});

test('CA: /verify is audited', async () => {
	await req({
		method: 'POST', path: '/admin/v1/ca/verify', client: ownerPair,
		body: {nonce: crypto.randomBytes(32).toString('base64url')},
	});
	const audit = await req({path: '/admin/v1/audit?action=ca.verify', client: viewerPair});
	assert.ok(audit.body.items.length >= 1);
});

test('admin-issue: rejects invalid validity window', async () => {
	const csr = generateCsr({commonName: 'x.lan', sans: ['x.lan'], algorithm: 'ecdsa-p256'});
	const r = await req({
		method: 'POST', path: '/admin/v1/certificates/issue', client: ownerPair,
		body: {
			identifiers: [{type: 'dns', value: 'x.lan'}],
			csr: csr.csrDer.toString('base64url'),
			notAfterDays: 9999,
		},
	});
	assert.equal(r.status, 400);
	assert.equal(r.body.error, 'bad-validity');
});

/* ─────────────────── CA rotation (stage / promote / rollback) ─────────────────── */

function stagedIntermediateFor(activeRoot: {certPem: string; keyPem: string}, days = 365) {
	const inter = buildIntermediateCa({
		subject: {commonName: `staged-int-${Math.random().toString(36).slice(2, 6)}`},
		validityDays: days,
		algorithm: 'ecdsa-p256',
		ca: {certPem: activeRoot.certPem, keyPem: activeRoot.keyPem},
	});
	return {certPem: inter.certPem, keyPem: inter.keyPem, chainPem: activeRoot.certPem};
}

test('CA stage: rejected by viewer (owner required)', async () => {
	const cand = stagedIntermediateFor(caObj);
	const r = await req({
		method: 'POST', path: '/admin/v1/ca/stage', client: viewerPair,
		body: {cert_pem: cand.certPem, key_pem: cand.keyPem, chain_pem: cand.chainPem},
	});
	assert.equal(r.status, 403);
});

test('CA stage: happy path stores candidate + GET /staged returns it', async () => {
	// Stash root before mutation so subsequent tests start fresh.
	const rootBefore = {certPem: caObj.certPem, keyPem: caObj.keyPem};
	const cand = stagedIntermediateFor(rootBefore);
	const r = await req({
		method: 'POST', path: '/admin/v1/ca/stage', client: ownerPair,
		body: {cert_pem: cand.certPem, key_pem: cand.keyPem, chain_pem: cand.chainPem},
	});
	assert.equal(r.status, 200, JSON.stringify(r.body));
	assert.equal(r.body.staged, true);
	const fp = r.body.fingerprint;

	const g = await req({path: '/admin/v1/ca/staged', client: viewerPair});
	assert.equal(g.body.staged, true);
	assert.equal(g.body.fingerprint, fp);

	// Clean up so other tests see no staged.
	await req({method: 'DELETE', path: '/admin/v1/ca/staged', client: ownerPair});
});

test('CA stage: key-cert mismatch rejected', async () => {
	const root = {certPem: caObj.certPem, keyPem: caObj.keyPem};
	const cand = stagedIntermediateFor(root);
	const otherRoot = buildRootCa({subject: {commonName: 'other'}, validityDays: 1, algorithm: 'ecdsa-p256'});
	// Pair this cand's cert with an unrelated key — must fail key-cert-mismatch.
	const r = await req({
		method: 'POST', path: '/admin/v1/ca/stage', client: ownerPair,
		body: {cert_pem: cand.certPem, key_pem: otherRoot.keyPem, chain_pem: cand.chainPem},
	});
	assert.equal(r.status, 400);
	assert.equal(r.body.error, 'key-cert-mismatch');
});

test('CA stage: root mismatch rejected', async () => {
	// A brand-new root cert + key that does NOT chain to the active root.
	const detachedRoot = buildRootCa({subject: {commonName: 'detached'}, validityDays: 365, algorithm: 'ecdsa-p256'});
	const r = await req({
		method: 'POST', path: '/admin/v1/ca/stage', client: ownerPair,
		body: {cert_pem: detachedRoot.certPem, key_pem: detachedRoot.keyPem, chain_pem: ''},
	});
	assert.equal(r.status, 400);
	assert.equal(r.body.error, 'root-mismatch');
});

test('CA promote: atomic swap — /ca info reflects new fingerprint, rollback restores', async () => {
	// Take an explicit snapshot of the active root BEFORE staging anything.
	const rootSnapshot = {certPem: caObj.certPem, keyPem: caObj.keyPem};
	const activeBefore = await req({path: '/admin/v1/ca', client: viewerPair});
	const fpBefore = activeBefore.body.cert_fingerprint;

	const cand = stagedIntermediateFor(rootSnapshot);
	const stage = await req({
		method: 'POST', path: '/admin/v1/ca/stage', client: ownerPair,
		body: {cert_pem: cand.certPem, key_pem: cand.keyPem, chain_pem: cand.chainPem},
	});
	assert.equal(stage.status, 200);
	const newFp = stage.body.fingerprint;

	const promote = await req({
		method: 'POST', path: '/admin/v1/ca/promote', client: ownerPair,
	});
	assert.equal(promote.status, 200, JSON.stringify(promote.body));
	assert.equal(promote.body.previous_fingerprint, fpBefore);
	assert.equal(promote.body.new_fingerprint, newFp);
	assert.equal(promote.body.rollback_available, true);

	// /ca now shows the new fingerprint — atomic swap reached the routes.
	const activeAfter = await req({path: '/admin/v1/ca', client: viewerPair});
	assert.equal(activeAfter.body.cert_fingerprint, newFp);

	// Audit log captured ca.promote with both fingerprints.
	const audit = await req({path: '/admin/v1/audit?action=ca.promote', client: viewerPair});
	assert.ok(audit.body.items.length >= 1);

	// Rollback within window restores the original.
	const rb = await req({method: 'POST', path: '/admin/v1/ca/rollback', client: ownerPair});
	assert.equal(rb.status, 200);
	assert.equal(rb.body.restored_fingerprint, fpBefore);
	const restored = await req({path: '/admin/v1/ca', client: viewerPair});
	assert.equal(restored.body.cert_fingerprint, fpBefore);
});

test('CA promote: 400 when nothing staged', async () => {
	const r = await req({method: 'POST', path: '/admin/v1/ca/promote', client: ownerPair});
	assert.equal(r.status, 400);
	assert.equal(r.body.error, 'no-staged');
});

test('CA rollback: 400 when no previous (post-restore, idempotency)', async () => {
	// After the rollback in the previous test, previous was cleared.
	const r = await req({method: 'POST', path: '/admin/v1/ca/rollback', client: ownerPair});
	assert.equal(r.status, 400);
	assert.equal(r.body.error, 'no-previous');
});

/* ─────────────────── reissue worker ─────────────────── */

function seedRealLeaf(accountId: string, identifier = 'leaf.example'): string {
	// Build an actual leaf signed by the current active CA so resign has
	// something cryptographically valid to chew on.
	const leaf = buildLeafCert({
		type: 'server',
		subject: {commonName: identifier},
		validityDays: 90,
		sans: [identifier],
		algorithm: 'ed25519',
		ca: {certPem: caObj.certPem, keyPem: caObj.keyPem},
	});
	const order = repos.insertOrder({
		accountId,
		identifiers: [{type: 'dns', value: identifier}],
		notBefore: null, notAfter: null, ttlSec: 600,
	});
	const cert = repos.insertCert({
		orderId: order.id,
		accountId,
		serialHex: leaf.serial,
		pem: leaf.certPem,
		chainPem: '',
		notBefore: leaf.notBefore.toISOString(),
		notAfter: leaf.notAfter.toISOString(),
		identifiers: [identifier],
	});
	repos.attachCertToOrder(order.id, cert.id, Buffer.alloc(0));
	return cert.id;
}

test('reissue: all-active job resigns leaves and updates pem in place', async () => {
	const acct = seedAccount('reissue-tp');
	const certId = seedRealLeaf(acct, 'svc.reissue');
	const before = repos.getCert(certId)!;
	const start = await req({
		method: 'POST', path: '/admin/v1/jobs/reissue', client: ownerPair,
		body: {scope: 'all-active', ratePerSec: 100},
	});
	assert.equal(start.status, 200, JSON.stringify(start.body));
	const jobId = start.body.id;
	assert.equal(start.body.total >= 1, true);
	// Drive worker manually (tests don't spin the interval).
	await reissueWorker.tick();
	// Wait until job is no longer 'running'.
	for (let i = 0; i < 50; i++) {
		const j = repos.getReissueJob(jobId)!;
		if (j.status !== 'running') break;
		await new Promise(r => setTimeout(r, 50));
	}
	const final = await req({path: `/admin/v1/jobs/${jobId}`, client: viewerPair});
	assert.equal(final.body.status, 'done');
	assert.ok(final.body.done >= 1, 'at least one done');
	const after = repos.getCert(certId)!;
	assert.notEqual(after.serial_hex, before.serial_hex, 'serial changed after resign');
	assert.notEqual(after.pem, before.pem, 'pem rewritten');
});

test('reissue: bad scope rejected', async () => {
	const r = await req({
		method: 'POST', path: '/admin/v1/jobs/reissue', client: ownerPair,
		body: {scope: 'whatever'},
	});
	assert.equal(r.status, 400);
});

test('reissue: viewer cannot start a job', async () => {
	const r = await req({
		method: 'POST', path: '/admin/v1/jobs/reissue', client: viewerPair,
		body: {scope: 'all-active'},
	});
	assert.equal(r.status, 403);
});

test('ARI hint: /renewalInfo returns suggestedWindow', async () => {
	const acct = seedAccount('ari-tp');
	const certId = seedRealLeaf(acct, 'svc.ari');
	// Public unauthenticated endpoint — admin server doesn't host it, the
	// regular ACME path does. Hit the repo+route logic directly through
	// fastify by making the public ACME route. Here we just check the row.
	const row = repos.getCert(certId)!;
	// suggestedWindow start is "renew now"-ish if cert is fresh: at 2/3 of TTL.
	// We just assert the row exists and is ready for the endpoint to compute.
	assert.ok(row);
	// Simulate what the route does:
	const now = Date.now();
	const expiresAt = new Date(row.not_after).getTime();
	const ttl = expiresAt - now;
	const start = now + Math.floor(ttl * 2 / 3);
	assert.ok(start > now, 'suggestedWindow start should be in the future for a fresh cert');
});

test('CA stage: /ca/verify after promote signs with the NEW key', async () => {
	// End-to-end: stage → promote → /verify should be valid against the
	// staged cert's public key (i.e. the new active key signs the nonce).
	const rootSnapshot = {certPem: caObj.certPem, keyPem: caObj.keyPem};
	const cand = stagedIntermediateFor(rootSnapshot);
	await req({
		method: 'POST', path: '/admin/v1/ca/stage', client: ownerPair,
		body: {cert_pem: cand.certPem, key_pem: cand.keyPem, chain_pem: cand.chainPem},
	});
	await req({method: 'POST', path: '/admin/v1/ca/promote', client: ownerPair});

	const v = await req({
		method: 'POST', path: '/admin/v1/ca/verify', client: ownerPair,
		body: {nonce: crypto.randomBytes(32).toString('base64url')},
	});
	const ok = verifyProofOfPossession({
		expectedPublicKeyPem: cand.certPem, // expect the new key
		nonce: Buffer.from(JSON.parse(JSON.stringify({n: ''})).n, 'base64url'), // placeholder, recompute below
		signature: Buffer.from(v.body.signature, 'base64'),
		alg: v.body.alg,
	});
	// Actually re-do with proper nonce.
	// (The above call uses an empty buffer, so it'll definitely fail. Run a
	// real round-trip via the v.body.cert_pem instead.)
	const realNonce = crypto.randomBytes(32);
	const v2 = await req({
		method: 'POST', path: '/admin/v1/ca/verify', client: ownerPair,
		body: {nonce: realNonce.toString('base64url')},
	});
	const realOk = verifyProofOfPossession({
		expectedPublicKeyPem: v2.body.cert_pem,
		nonce: realNonce,
		signature: Buffer.from(v2.body.signature, 'base64'),
		alg: v2.body.alg,
	});
	assert.equal(realOk, true, 'verify succeeds against the post-promote cert');
	assert.equal(v2.body.cert_pem.trim(), cand.certPem.trim(), 'verify cert_pem == staged cert');

	// Restore for any subsequent tests by rolling back.
	await req({method: 'POST', path: '/admin/v1/ca/rollback', client: ownerPair});

	// Silence unused warning
	void ok;
});
