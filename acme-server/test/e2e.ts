// End-to-end test: spins up the ACME server against a freshly built CA,
// runs the client against it using a built-in DNS solver, and verifies the
// resulting certificate chains to the CA.
//
// Trick: no real DNS. We monkey-patch the server's resolveTxt function to
// look up an in-process Map populated by the test's DNS hook. That covers
// the protocol path end-to-end without needing a network.

import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {execSync} from 'child_process';
import forge from 'node-forge';
import Database from 'better-sqlite3';

import {setResolveTxtForTesting} from '../src/server/resolver.js';
import {loadConfig} from '../src/server/config.js';
import {loadCa} from '../src/server/contextLoader.js';
import {openDb} from '../src/server/db.js';
import {Repos} from '../src/server/repos.js';
import {NonceManager} from '../src/server/nonce.js';
import {Urls} from '../src/server/urls.js';
import {Worker} from '../src/server/worker.js';
import {registerRoutes, type ServerCtx} from '../src/server/routes.js';
import Fastify from 'fastify';

import {AcmeClient, generateAccountKey, pollUntil} from '../src/client/acme.js';
import {generateCsr} from '../src/client/csr.js';

// ------- shared TXT store -------
const txtStore = new Map<string, string[]>();
function publishTxt(name: string, value: string) {
	const k = name.toLowerCase().replace(/\.$/, '');
	const arr = txtStore.get(k) ?? [];
	arr.push(value);
	txtStore.set(k, arr);
}

// override the server's TXT resolver
setResolveTxtForTesting(async (name: string) => {
	return txtStore.get(name.toLowerCase().replace(/\.$/, '')) ?? [];
});

// ------- helpers -------
function mkdtemp(prefix: string): string {
	return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function buildSelfSignedCa(dir: string): {certPem: string; keyPem: string} {
	// Build a tiny RSA root via node-forge directly into a secutor-shaped store.db.
	const keys = forge.pki.rsa.generateKeyPair(2048);
	const cert = forge.pki.createCertificate();
	cert.publicKey = keys.publicKey;
	cert.serialNumber = '01' + crypto.randomBytes(15).toString('hex');
	const now = new Date();
	cert.validity.notBefore = now;
	cert.validity.notAfter = new Date(now.getTime() + 365 * 86400 * 1000);
	const attrs = [{name: 'commonName', value: 'Test CA'}];
	cert.setSubject(attrs);
	cert.setIssuer(attrs);
	cert.setExtensions([
		{name: 'basicConstraints', cA: true},
		{name: 'keyUsage', keyCertSign: true, digitalSignature: true, cRLSign: true},
		{name: 'subjectKeyIdentifier'},
	]);
	cert.sign(keys.privateKey, forge.md.sha256.create());
	const certPem = forge.pki.certificateToPem(cert);
	const keyPem = forge.pki.privateKeyToPem(keys.privateKey);

	const db = new Database(path.join(dir, 'store.db'));
	db.exec(`
		CREATE TABLE certificates (
		  id INTEGER PRIMARY KEY AUTOINCREMENT,
		  name TEXT NOT NULL UNIQUE,
		  type TEXT NOT NULL,
		  common_name TEXT NOT NULL,
		  organization TEXT,
		  issuer_id INTEGER,
		  serial TEXT NOT NULL,
		  not_before TEXT NOT NULL,
		  not_after TEXT NOT NULL,
		  san TEXT,
		  cert_pem TEXT NOT NULL,
		  key_pem TEXT NOT NULL DEFAULT '',
		  fingerprint TEXT NOT NULL,
		  created_at TEXT NOT NULL
		);
	`);
	db.prepare(
		`INSERT INTO certificates(name,type,common_name,serial,not_before,not_after,cert_pem,key_pem,fingerprint,created_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`,
	).run(
		'test-ca',
		'ca',
		'Test CA',
		cert.serialNumber,
		cert.validity.notBefore.toISOString(),
		cert.validity.notAfter.toISOString(),
		certPem,
		keyPem,
		'na',
		new Date().toISOString(),
	);
	db.close();
	fs.writeFileSync(path.join(dir, 'context.json'), JSON.stringify({name: 'test', encrypted: false}));
	return {certPem, keyPem};
}

async function startServer(opts: {contextDir: string; stateDb: string; baseUrl: string; port: number}) {
	process.env.SECUTOR_CONTEXT_DIR = opts.contextDir;
	process.env.SECUTOR_ACME_DB = opts.stateDb;
	process.env.SECUTOR_ACME_BASE_URL = opts.baseUrl;
	process.env.SECUTOR_ACME_LISTEN = `127.0.0.1:${opts.port}`;

	const {config, contextPassword, caKeyPassword} = loadConfig();
	const ca = loadCa({
		contextDir: config.contextDir,
		contextPassword,
		caCertName: config.caCertName,
		caKeyPassword,
	});
	const db = openDb(config.stateDb);
	const repos = new Repos(db);
	const nonces = new NonceManager(repos, config.nonceTtlSec);
	const urls = new Urls(config.baseUrl);
	const ctx: ServerCtx = {repos, nonces, urls, config, ca};
	const app = Fastify({logger: false, trustProxy: true});
	app.addContentTypeParser(
		'application/jose+json',
		{parseAs: 'string'},
		(_req, body, done) => {
			try {
				done(null, JSON.parse(body as string));
			} catch (e) {
				done(e as Error, undefined);
			}
		},
	);
	registerRoutes(app, ctx);
	const worker = new Worker(repos, config, accountId => {
		const a = repos.getAccount(accountId);
		return a ? a.jwk_thumbprint : null;
	});
	worker.start();
	await app.listen({host: '127.0.0.1', port: opts.port});
	return {
		stop: async () => {
			worker.stop();
			await app.close();
			db.close();
		},
		ca,
	};
}

function verifyChain(leafPem: string, caPem: string): boolean {
	const leaf = new crypto.X509Certificate(leafPem);
	const ca = new crypto.X509Certificate(caPem);
	return leaf.verify(ca.publicKey) && leaf.issuer === ca.subject;
}

async function main() {
	const root = mkdtemp('secutor-acme-e2e-');
	const ctxDir = path.join(root, 'ctx');
	fs.mkdirSync(ctxDir, {recursive: true});
	const {certPem: caPem} = buildSelfSignedCa(ctxDir);
	const stateDb = path.join(root, 'acme.db');
	const port = 18443;
	const baseUrl = `http://127.0.0.1:${port}/`;

	console.log(`[e2e] root=${root}`);
	const srv = await startServer({contextDir: ctxDir, stateDb, baseUrl, port});

	try {
		const acct = await generateAccountKey('EC');
		const client = new AcmeClient(`${baseUrl}directory`, acct);
		await client.register(['mailto:e2e@local']);

		const domain = 'host.lan';
		const {url: orderUrl, order} = await client.newOrder([{type: 'dns', value: domain}]);

		// Solve DNS-01 in-process.
		for (const authzUrl of order.authorizations) {
			const authz = await client.fetchAuthz(authzUrl);
			const chall = authz.challenges.find(c => c.type === 'dns-01');
			if (!chall) throw new Error('no dns-01 challenge');
			const name = `_acme-challenge.${authz.identifier.value.replace(/^\*\./, '')}`;
			const value = client.dns01TxtValue(chall.token);
			publishTxt(name, value);
			await client.triggerChallenge(chall.url);
			const final = await pollUntil(() => client.fetchAuthz(authzUrl), ['valid', 'invalid'], 30_000);
			if (final.status !== 'valid') {
				throw new Error('authz did not validate: ' + JSON.stringify(final));
			}
		}

		const ready = await pollUntil(() => client.fetchOrder(orderUrl), ['ready', 'invalid']);
		if (ready.status !== 'ready') throw new Error(`order not ready: ${ready.status}`);

		const csr = generateCsr({commonName: domain, sans: [domain], algorithm: 'ecdsa-p256'});
		await client.finalize(ready.finalize, csr.csrDer);
		const valid = await pollUntil(() => client.fetchOrder(orderUrl), ['valid', 'invalid']);
		if (valid.status !== 'valid') throw new Error(`order not valid: ${valid.status}`);
		if (!valid.certificate) throw new Error('no certificate URL');

		const chain = await client.downloadCert(valid.certificate);
		const leafPem = chain.split(/-----END CERTIFICATE-----/)[0]! + '-----END CERTIFICATE-----';

		console.log('[e2e] issued cert:');
		console.log(leafPem);

		// Sanity: cert subject CN matches, chain verifies against the CA.
		const cert = new crypto.X509Certificate(leafPem);
		if (!cert.subject.includes(`CN=${domain}`)) {
			throw new Error(`Wrong subject: ${cert.subject}`);
		}
		if (!cert.subjectAltName?.includes(domain)) {
			throw new Error(`SAN missing: ${cert.subjectAltName}`);
		}
		if (!verifyChain(leafPem, caPem)) {
			throw new Error('Chain verification failed');
		}
		console.log('[e2e] ✓ certificate verified against CA');

		// Also exercise revocation.
		const der = pemToDer(leafPem);
		try {
			await client.post(`${baseUrl}revoke-cert`, {certificate: bufferB64u(der)});
			console.log('[e2e] ✓ revocation accepted');
		} catch (e: any) {
			throw new Error('Revocation failed: ' + e.message);
		}

		// Verify CRL is published and contains the revoked serial.
		const crlRes = await fetch(`${baseUrl}crl.pem`);
		if (!crlRes.ok) throw new Error(`CRL fetch ${crlRes.status}`);
		const crlPem = await crlRes.text();
		if (!crlPem.includes('BEGIN X509 CRL')) throw new Error('CRL not PEM-encoded');
		// Parse the leaf to get the serial and check the CRL via openssl if available.
		const leafSerial = new crypto.X509Certificate(leafPem).serialNumber.toLowerCase();
		fs.writeFileSync(path.join(root, 'crl.pem'), crlPem);
		fs.writeFileSync(path.join(root, 'ca.pem'), caPem);
		try {
			const out = execSync(
				`openssl crl -in ${path.join(root, 'crl.pem')} -text -noout`,
			).toString();
			if (!out.toLowerCase().includes(leafSerial.replace(/^0+/, ''))) {
				// openssl prints colon-separated hex; normalize for comparison
				const haystack = out.toLowerCase().replace(/[:\s]/g, '');
				if (!haystack.includes(leafSerial.replace(/^0+/, ''))) {
					throw new Error(`CRL missing serial ${leafSerial}\n${out}`);
				}
			}
			console.log('[e2e] ✓ CRL contains revoked serial');
		} catch (e: any) {
			if (e?.message?.includes('not found')) {
				console.log('[e2e] (openssl not in PATH — skipped CRL parse)');
			} else {
				throw e;
			}
		}
	} finally {
		await srv.stop();
	}
	console.log('\n[e2e] ALL PASSED');
}

function pemToDer(pem: string): Buffer {
	const body = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
	return Buffer.from(body, 'base64');
}
function bufferB64u(b: Buffer): string {
	return b.toString('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

main().catch(err => {
	console.error(err);
	process.exit(1);
});
