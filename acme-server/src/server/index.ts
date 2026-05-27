import Fastify from 'fastify';
import {loadConfig, parseListen} from './config.js';
import {loadCa} from './contextLoader.js';
import {openDb} from './db.js';
import {Repos} from './repos.js';
import {NonceManager} from './nonce.js';
import {Urls} from './urls.js';
import {Worker} from './worker.js';
import {registerRoutes, type ServerCtx} from './routes.js';

async function main() {
	const {config, contextPassword, caKeyPassword} = loadConfig();

	const ca = loadCa({
		contextDir: config.contextDir,
		contextPassword,
		caCertName: config.caCertName,
		caKeyPassword,
	});
	// Forget the file-derived password as soon as the key is in memory.
	// (Best-effort — V8 holds string copies, but we drop our reference.)

	const db = openDb(config.stateDb);
	const repos = new Repos(db);
	const nonces = new NonceManager(repos, config.nonceTtlSec);
	const urls = new Urls(config.baseUrl);

	const ctx: ServerCtx = {repos, nonces, urls, config, ca};

	const app = Fastify({
		logger: {
			level: process.env.LOG_LEVEL ?? 'info',
			redact: ['req.headers.authorization'],
		},
		bodyLimit: 1 * 1024 * 1024, // 1 MB — CSRs and JWS are small
		trustProxy: true,
	});

	// ACME content type for POST bodies.
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

	app.addHook('onClose', async () => {
		worker.stop();
		db.close();
	});

	const {host, port} = parseListen(config.listen);
	await app.listen({host, port});
	app.log.info(
		{
			baseUrl: config.baseUrl,
			signingCa: {
				name: ca.name,
				cn: ca.commonName,
				serial: ca.serial,
				notAfter: ca.notAfter.toISOString(),
				isRoot: ca.chainDepth === 1,
				chainDepthToRoot: ca.chainDepth,
			},
			dns01: config.challenges.dns01,
			http01: config.challenges.http01,
		},
		`secutor-acme ready — signing as "${ca.name}" (CN=${ca.commonName}), ${
			ca.chainDepth === 1
				? 'root CA, no intermediates'
				: `${ca.chainDepth - 1} intermediate(s) in chain`
		}`,
	);

	const stop = async (sig: string) => {
		app.log.info({sig}, 'shutting down');
		await app.close();
		process.exit(0);
	};
	process.on('SIGTERM', () => stop('SIGTERM'));
	process.on('SIGINT', () => stop('SIGINT'));
}

main().catch(err => {
	console.error('Fatal:', err);
	process.exit(1);
});
