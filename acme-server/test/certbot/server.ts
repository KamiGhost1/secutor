// Starts a real ACME server for certbot integration testing.
// The DNS resolver is overridden to read TXT values from files in
// $TXT_STORE/_acme-challenge.<name>.txt (one value per line). The certbot
// auth-hook (see auth-hook.sh) writes those files.

import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import forge from 'node-forge';
import Database from 'better-sqlite3';
import Fastify from 'fastify';

import {setResolveTxtForTesting} from '../../src/server/resolver.js';
import {loadConfig} from '../../src/server/config.js';
import {loadCa} from '../../src/server/contextLoader.js';
import {openDb} from '../../src/server/db.js';
import {Repos} from '../../src/server/repos.js';
import {NonceManager} from '../../src/server/nonce.js';
import {Urls} from '../../src/server/urls.js';
import {Worker} from '../../src/server/worker.js';
import {registerRoutes, type ServerCtx} from '../../src/server/routes.js';

const txtStore = process.env.TXT_STORE!;
if (!txtStore) {
	console.error('TXT_STORE env var required');
	process.exit(2);
}
fs.mkdirSync(txtStore, {recursive: true});

setResolveTxtForTesting(async (name: string) => {
	const file = path.join(txtStore, name.toLowerCase().replace(/\.$/, '') + '.txt');
	try {
		const data = fs.readFileSync(file, 'utf8');
		return data.split('\n').map(l => l.trim()).filter(Boolean);
	} catch {
		return [];
	}
});

function buildSelfSignedCa(dir: string): {certPem: string} {
	const keys = forge.pki.rsa.generateKeyPair(2048);
	const cert = forge.pki.createCertificate();
	cert.publicKey = keys.publicKey;
	cert.serialNumber = '01' + crypto.randomBytes(15).toString('hex');
	const now = new Date();
	cert.validity.notBefore = now;
	cert.validity.notAfter = new Date(now.getTime() + 365 * 86400 * 1000);
	const attrs = [{name: 'commonName', value: 'Certbot Test CA'}];
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
		  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, type TEXT NOT NULL,
		  common_name TEXT NOT NULL, organization TEXT, issuer_id INTEGER, serial TEXT NOT NULL,
		  not_before TEXT NOT NULL, not_after TEXT NOT NULL, san TEXT,
		  cert_pem TEXT NOT NULL, key_pem TEXT NOT NULL DEFAULT '',
		  fingerprint TEXT NOT NULL, created_at TEXT NOT NULL
		);
	`);
	db.prepare(
		`INSERT INTO certificates(name,type,common_name,serial,not_before,not_after,cert_pem,key_pem,fingerprint,created_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`,
	).run(
		'test-ca', 'ca', 'Certbot Test CA', cert.serialNumber,
		cert.validity.notBefore.toISOString(), cert.validity.notAfter.toISOString(),
		certPem, keyPem, 'na', new Date().toISOString(),
	);
	db.close();
	fs.writeFileSync(path.join(dir, 'context.json'), JSON.stringify({name: 'test', encrypted: false}));
	fs.writeFileSync(path.join(dir, '../ca.pem'), certPem);
	return {certPem};
}

async function main() {
	const root = process.env.ROOT ?? fs.mkdtempSync(path.join(os.tmpdir(), 'certbot-test-'));
	console.log(`[server] root=${root}`);
	const ctxDir = path.join(root, 'ctx');
	fs.mkdirSync(ctxDir, {recursive: true});
	buildSelfSignedCa(ctxDir);

	const port = parseInt(process.env.PORT ?? '18080', 10);
	process.env.SECUTOR_CONTEXT_DIR = ctxDir;
	process.env.SECUTOR_ACME_DB = path.join(root, 'acme.db');
	process.env.SECUTOR_ACME_BASE_URL = `http://127.0.0.1:${port}/`;
	process.env.SECUTOR_ACME_LISTEN = `127.0.0.1:${port}`;

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
	const app = Fastify({logger: {level: 'warn'}, trustProxy: true});
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
	await app.listen({host: '127.0.0.1', port});
	console.log(`[server] listening on http://127.0.0.1:${port}/`);

	const shutdown = async (sig: string) => {
		console.log(`[server] ${sig}, shutting down`);
		worker.stop();
		await app.close();
		db.close();
		process.exit(0);
	};
	process.on('SIGTERM', () => shutdown('SIGTERM'));
	process.on('SIGINT', () => shutdown('SIGINT'));
}

main();
