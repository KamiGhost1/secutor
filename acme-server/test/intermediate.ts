// E2E for the "Root + Intermediate" topology. Verifies that:
//   * with SECUTOR_CA_CERT_NAME pointing at the intermediate, the server signs
//     leaves with the intermediate (not the root);
//   * /ca.pem returns the *root* (for trust distribution);
//   * /chain.pem returns the intermediate (chain to root, root excluded);
//   * an issued leaf, plus the chain returned in application/pem-certificate-chain,
//     verifies all the way up to the root with `openssl verify`.

import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {execSync} from 'child_process';
import forge from 'node-forge';
import Database from 'better-sqlite3';
import Fastify from 'fastify';

import {setResolveTxtForTesting} from '../src/server/resolver.js';
import {loadConfig} from '../src/server/config.js';
import {loadCa} from '../src/server/contextLoader.js';
import {openDb} from '../src/server/db.js';
import {Repos} from '../src/server/repos.js';
import {NonceManager} from '../src/server/nonce.js';
import {Urls} from '../src/server/urls.js';
import {Worker} from '../src/server/worker.js';
import {registerRoutes, type ServerCtx} from '../src/server/routes.js';

import {AcmeClient, generateAccountKey, pollUntil} from '../src/client/acme.js';
import {generateCsr} from '../src/client/csr.js';

const txtStore = new Map<string, string[]>();
setResolveTxtForTesting(async (name: string) => {
	const k = name.toLowerCase().replace(/\.$/, '');
	return txtStore.get(k) ?? [];
});
function publishTxt(name: string, value: string) {
	const k = name.toLowerCase().replace(/\.$/, '');
	const arr = txtStore.get(k) ?? [];
	arr.push(value);
	txtStore.set(k, arr);
}

type CaBuilt = {certPem: string; keyPem: string; serial: string};

function buildRoot(commonName: string): CaBuilt {
	const keys = forge.pki.rsa.generateKeyPair(2048);
	const cert = forge.pki.createCertificate();
	cert.publicKey = keys.publicKey;
	cert.serialNumber = '01' + crypto.randomBytes(15).toString('hex');
	cert.validity.notBefore = new Date();
	cert.validity.notAfter = new Date(Date.now() + 365 * 86400 * 1000);
	const subj = [{name: 'commonName', value: commonName}];
	cert.setSubject(subj);
	cert.setIssuer(subj);
	cert.setExtensions([
		{name: 'basicConstraints', cA: true},
		{name: 'keyUsage', keyCertSign: true, digitalSignature: true, cRLSign: true},
		{name: 'subjectKeyIdentifier'},
	]);
	cert.sign(keys.privateKey, forge.md.sha256.create());
	return {
		certPem: forge.pki.certificateToPem(cert),
		keyPem: forge.pki.privateKeyToPem(keys.privateKey),
		serial: cert.serialNumber,
	};
}

function buildIntermediate(parent: CaBuilt, commonName: string): CaBuilt {
	const parentCert = forge.pki.certificateFromPem(parent.certPem);
	const parentKey = forge.pki.privateKeyFromPem(parent.keyPem);
	const keys = forge.pki.rsa.generateKeyPair(2048);
	const cert = forge.pki.createCertificate();
	cert.publicKey = keys.publicKey;
	cert.serialNumber = '02' + crypto.randomBytes(15).toString('hex');
	cert.validity.notBefore = new Date();
	cert.validity.notAfter = new Date(Date.now() + 365 * 86400 * 1000);
	cert.setSubject([{name: 'commonName', value: commonName}]);
	cert.setIssuer(parentCert.subject.attributes);
	cert.setExtensions([
		{name: 'basicConstraints', cA: true, pathLenConstraint: 0},
		{name: 'keyUsage', keyCertSign: true, digitalSignature: true, cRLSign: true},
		{name: 'subjectKeyIdentifier'},
		{
			name: 'authorityKeyIdentifier',
			keyIdentifier: parentCert.generateSubjectKeyIdentifier().getBytes(),
		},
	]);
	cert.sign(parentKey, forge.md.sha256.create());
	return {
		certPem: forge.pki.certificateToPem(cert),
		keyPem: forge.pki.privateKeyToPem(keys.privateKey),
		serial: cert.serialNumber,
	};
}

function writeContext(dir: string, root: CaBuilt, intermediate: CaBuilt) {
	fs.mkdirSync(dir, {recursive: true});
	const db = new Database(path.join(dir, 'store.db'));
	db.exec(`
		CREATE TABLE certificates (
		  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, type TEXT NOT NULL,
		  common_name TEXT NOT NULL, organization TEXT, issuer_id INTEGER, serial TEXT NOT NULL,
		  not_before TEXT NOT NULL, not_after TEXT NOT NULL, san TEXT,
		  cert_pem TEXT NOT NULL, key_pem TEXT NOT NULL DEFAULT '',
		  fingerprint TEXT NOT NULL, created_at TEXT NOT NULL
		);
	`);
	const insert = db.prepare(
		`INSERT INTO certificates(name,type,common_name,issuer_id,serial,not_before,not_after,cert_pem,key_pem,fingerprint,created_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
	);
	const rootRes = insert.run(
		'test-root', 'ca', 'Test Root CA', null, root.serial,
		new Date().toISOString(), new Date(Date.now() + 365 * 86400 * 1000).toISOString(),
		root.certPem, root.keyPem, 'na', new Date().toISOString(),
	);
	insert.run(
		'test-intermediate', 'ca', 'Test Intermediate', rootRes.lastInsertRowid, intermediate.serial,
		new Date().toISOString(), new Date(Date.now() + 365 * 86400 * 1000).toISOString(),
		intermediate.certPem, intermediate.keyPem, 'na', new Date().toISOString(),
	);
	db.close();
	fs.writeFileSync(path.join(dir, 'context.json'), JSON.stringify({name: 'test', encrypted: false}));
}

async function startServer(opts: {ctxDir: string; stateDb: string; port: number; caName: string}) {
	process.env.SECUTOR_CONTEXT_DIR = opts.ctxDir;
	process.env.SECUTOR_ACME_DB = opts.stateDb;
	process.env.SECUTOR_ACME_BASE_URL = `http://127.0.0.1:${opts.port}/`;
	process.env.SECUTOR_ACME_LISTEN = `127.0.0.1:${opts.port}`;
	process.env.SECUTOR_CA_CERT_NAME = opts.caName;

	const {config, contextPassword, caKeyPassword} = loadConfig();
	const ca = loadCa({
		contextDir: config.contextDir,
		contextPassword,
		caCertName: config.caCertName,
		caKeyPassword,
	});
	console.log(`[server] CA selected: name=${ca.name}, depth=${ca.chainDepth}, isRoot=${ca.chainDepth === 1}`);
	const db = openDb(config.stateDb);
	const repos = new Repos(db);
	const nonces = new NonceManager(repos, config.nonceTtlSec);
	const urls = new Urls(config.baseUrl);
	const ctx: ServerCtx = {repos, nonces, urls, config, ca};
	const app = Fastify({logger: false, trustProxy: true});
	app.addContentTypeParser('application/jose+json', {parseAs: 'string'}, (_r, body, done) => {
		try {
			done(null, JSON.parse(body as string));
		} catch (e) {
			done(e as Error, undefined);
		}
	});
	registerRoutes(app, ctx);
	const worker = new Worker(repos, config, accountId => {
		const a = repos.getAccount(accountId);
		return a ? a.jwk_thumbprint : null;
	});
	worker.start();
	await app.listen({host: '127.0.0.1', port: opts.port});
	return {
		ca,
		baseUrl: process.env.SECUTOR_ACME_BASE_URL!,
		stop: async () => {
			worker.stop();
			await app.close();
			db.close();
		},
	};
}

async function main() {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secutor-acme-int-'));
	console.log(`[test] root=${root}`);
	const ctxDir = path.join(root, 'ctx');
	const rootCa = buildRoot('Test Root CA');
	const intermediate = buildIntermediate(rootCa, 'Test Intermediate');
	writeContext(ctxDir, rootCa, intermediate);

	const srv = await startServer({
		ctxDir,
		stateDb: path.join(root, 'acme.db'),
		port: 18553,
		caName: 'test-intermediate',
	});

	try {
		// Sanity: /ca.pem == root, /chain.pem == intermediate
		const caPem = await fetch(`${srv.baseUrl}ca.pem`).then(r => r.text());
		const chainPem = await fetch(`${srv.baseUrl}chain.pem`).then(r => r.text());
		if (caPem.trim() !== rootCa.certPem.trim()) throw new Error('/ca.pem is not the root');
		if (chainPem.trim() !== intermediate.certPem.trim()) {
			throw new Error('/chain.pem is not the intermediate');
		}
		console.log('[test] ✓ /ca.pem == root, /chain.pem == intermediate');

		const acct = await generateAccountKey('EC');
		const client = new AcmeClient(`${srv.baseUrl}directory`, acct);
		await client.register(['mailto:int-test@local']);

		const domain = 'host.lan';
		const {url: orderUrl, order} = await client.newOrder([{type: 'dns', value: domain}]);

		for (const authzUrl of order.authorizations) {
			const authz = await client.fetchAuthz(authzUrl);
			const ch = authz.challenges.find(c => c.type === 'dns-01')!;
			const name = `_acme-challenge.${authz.identifier.value.replace(/^\*\./, '')}`;
			publishTxt(name, client.dns01TxtValue(ch.token));
			await client.triggerChallenge(ch.url);
			const final = await pollUntil(() => client.fetchAuthz(authzUrl), ['valid', 'invalid'], 30_000);
			if (final.status !== 'valid') throw new Error('authz did not validate');
		}

		const ready = await pollUntil(() => client.fetchOrder(orderUrl), ['ready', 'invalid']);
		if (ready.status !== 'ready') throw new Error('order not ready');

		const csr = generateCsr({commonName: domain, sans: [domain], algorithm: 'ecdsa-p256'});
		await client.finalize(ready.finalize, csr.csrDer);
		const valid = await pollUntil(() => client.fetchOrder(orderUrl), ['valid', 'invalid']);
		if (valid.status !== 'valid') throw new Error('order not valid');

		const fullchain = await client.downloadCert(valid.certificate!);
		// Parse the PEM bundle.
		const certs = fullchain
			.split(/(?<=-----END CERTIFICATE-----)/g)
			.map(s => s.trim())
			.filter(s => s.startsWith('-----BEGIN'));
		console.log(`[test] response contains ${certs.length} cert(s)`);
		if (certs.length < 2) {
			throw new Error(`Expected at least leaf+intermediate, got ${certs.length}`);
		}

		// Leaf must be signed by intermediate.
		const leaf = new crypto.X509Certificate(certs[0]!);
		const intCert = new crypto.X509Certificate(certs[1]!);
		const rootCert = new crypto.X509Certificate(rootCa.certPem);
		if (!leaf.verify(intCert.publicKey)) throw new Error('leaf not signed by intermediate');
		if (!intCert.verify(rootCert.publicKey)) throw new Error('intermediate not signed by root');
		if (leaf.issuer !== intCert.subject) throw new Error('leaf issuer != intermediate subject');
		console.log('[test] ✓ leaf → intermediate → root chain matches');

		// Run openssl verify with the root as CAfile and the chain bundle as untrusted intermediates.
		fs.writeFileSync(path.join(root, 'root.pem'), rootCa.certPem);
		fs.writeFileSync(path.join(root, 'fullchain.pem'), fullchain);
		fs.writeFileSync(path.join(root, 'leaf.pem'), certs[0]!);
		fs.writeFileSync(path.join(root, 'intermediates.pem'), certs.slice(1).join('\n'));
		const out = execSync(
			`openssl verify -CAfile ${path.join(root, 'root.pem')} ` +
				`-untrusted ${path.join(root, 'intermediates.pem')} ` +
				`${path.join(root, 'leaf.pem')}`,
		).toString().trim();
		if (!out.endsWith('OK')) throw new Error(`openssl verify failed: ${out}`);
		console.log(`[test] ✓ openssl verify: ${out}`);
	} finally {
		await srv.stop();
	}
	console.log('\n[test] ALL PASSED');
}

main().catch(err => {
	console.error(err);
	process.exit(1);
});
