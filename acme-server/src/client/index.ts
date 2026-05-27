#!/usr/bin/env node
// Mini-certbot. Wraps AcmeClient with a CLI for one-shot issuance.
//
// Usage:
//   secutor-acme-client \
//     --directory https://acme.lan/directory \
//     --domain foo.lan --domain '*.foo.lan' \
//     --challenge dns-01 \
//     --dns-hook manual \
//     --out ./certs/foo.lan \
//     --account-key ./account.key   (created if missing)
//     --contact mailto:ops@lan
//     --algorithm ecdsa-p256

import fs from 'fs';
import path from 'path';
import {parseArgs} from 'util';
import {AcmeClient, generateAccountKey, loadAccountKey, pollUntil} from './acme.js';
import {generateCsr} from './csr.js';
import {manualHook, scriptHook, rfc2136Hook, type DnsHook} from './dnsHooks.js';

type Args = {
	directory: string;
	domain: string[];
	challenge: 'dns-01' | 'http-01';
	'dns-hook'?: 'manual' | 'script' | 'rfc2136';
	'dns-hook-script'?: string;
	'rfc2136-server'?: string;
	'rfc2136-zone'?: string;
	'rfc2136-key'?: string;
	'rfc2136-ttl'?: string;
	out: string;
	'account-key': string;
	contact?: string[];
	algorithm: 'rsa-2048' | 'rsa-3072' | 'rsa-4096' | 'ecdsa-p256' | 'ecdsa-p384';
};

function parse(): Args {
	const {values} = parseArgs({
		options: {
			directory: {type: 'string'},
			domain: {type: 'string', multiple: true},
			challenge: {type: 'string', default: 'dns-01'},
			'dns-hook': {type: 'string', default: 'manual'},
			'dns-hook-script': {type: 'string'},
			'rfc2136-server': {type: 'string'},
			'rfc2136-zone': {type: 'string'},
			'rfc2136-key': {type: 'string'},
			'rfc2136-ttl': {type: 'string'},
			out: {type: 'string', default: './out'},
			'account-key': {type: 'string', default: './account.key'},
			contact: {type: 'string', multiple: true},
			algorithm: {type: 'string', default: 'ecdsa-p256'},
		},
		strict: true,
		allowPositionals: false,
	});
	if (!values.directory) throw new Error('--directory is required');
	if (!values.domain || !values.domain.length) throw new Error('--domain is required (repeatable)');
	if (values.challenge !== 'dns-01' && values.challenge !== 'http-01') {
		throw new Error('--challenge must be dns-01 or http-01');
	}
	return values as unknown as Args;
}

async function main() {
	const args = parse();
	fs.mkdirSync(args.out, {recursive: true});

	// Account key: load or create.
	let acctKey;
	if (fs.existsSync(args['account-key'])) {
		acctKey = await loadAccountKey(fs.readFileSync(args['account-key'], 'utf8'));
		console.log(`[+] Loaded account key: ${args['account-key']} (alg=${acctKey.alg})`);
	} else {
		acctKey = await generateAccountKey('EC');
		fs.writeFileSync(args['account-key'], acctKey.privateKeyPem, {mode: 0o600});
		console.log(`[+] Generated new account key: ${args['account-key']}`);
	}

	const client = new AcmeClient(args.directory, acctKey);
	await client.getDirectory();
	const kid = await client.register(args.contact);
	console.log(`[+] Account: ${kid}`);

	const {url: orderUrl, order} = await client.newOrder(
		args.domain.map(d => ({type: 'dns' as const, value: d})),
	);
	console.log(`[+] Order: ${orderUrl}`);
	console.log(`[+] Authorizations: ${order.authorizations.length}`);

	let hook: DnsHook;
	switch (args['dns-hook']) {
		case 'script':
			if (!args['dns-hook-script']) throw new Error('--dns-hook-script required');
			hook = scriptHook(args['dns-hook-script']);
			break;
		case 'rfc2136':
			if (!args['rfc2136-server'] || !args['rfc2136-zone'] || !args['rfc2136-key']) {
				throw new Error('--rfc2136-server, --rfc2136-zone, --rfc2136-key required');
			}
			hook = rfc2136Hook({
				server: args['rfc2136-server'],
				zone: args['rfc2136-zone'],
				keyFile: args['rfc2136-key'],
				ttl: args['rfc2136-ttl'] ? parseInt(args['rfc2136-ttl'], 10) : undefined,
			});
			break;
		default:
			hook = manualHook;
	}

	// Solve each authorization.
	const placements: Array<{name: string; value: string}> = [];
	for (const authzUrl of order.authorizations) {
		const authz = await client.fetchAuthz(authzUrl);
		const dnsName = authz.identifier.value.replace(/^\*\./, '');
		const want = args.challenge;
		const chall = authz.challenges.find(c => c.type === want);
		if (!chall) {
			throw new Error(`Authz for ${authz.identifier.value} has no ${want} challenge`);
		}
		if (want === 'dns-01') {
			const txtName = `_acme-challenge.${dnsName}`;
			const txtValue = client.dns01TxtValue(chall.token);
			await hook.place({name: txtName, value: txtValue});
			placements.push({name: txtName, value: txtValue});
		} else {
			// HTTP-01: caller is responsible for serving the file. Print instructions.
			const ka = client.keyAuthorization(chall.token);
			console.log(`\n  ↪ Please serve at http://${dnsName}/.well-known/acme-challenge/${chall.token}`);
			console.log(`      Body: ${ka}\n`);
			await new Promise(r => setTimeout(r, 100));
		}
		await client.triggerChallenge(chall.url);

		// Poll authz to valid/invalid
		const final = await pollUntil(() => client.fetchAuthz(authzUrl), ['valid', 'invalid']);
		if (final.status !== 'valid') {
			console.error('[!] Authorization failed:', JSON.stringify(final, null, 2));
			throw new Error(`Authorization for ${authz.identifier.value} did not validate`);
		}
		console.log(`[+] Authz valid: ${authz.identifier.value}`);
	}

	const ready = await pollUntil(() => client.fetchOrder(orderUrl), ['ready', 'invalid']);
	if (ready.status !== 'ready') throw new Error(`Order not ready: ${ready.status}`);

	// Generate CSR (the leaf's keypair, not the account key).
	const cn = args.domain[0]!.replace(/^\*\./, '');
	const csr = generateCsr({commonName: cn, sans: args.domain, algorithm: args.algorithm});
	fs.writeFileSync(path.join(args.out, 'privkey.pem'), csr.privateKeyPem, {mode: 0o600});
	fs.writeFileSync(path.join(args.out, 'csr.pem'), csr.csrPem);
	console.log(`[+] Generated CSR (algo=${args.algorithm}, CN=${cn}, SANs=${args.domain.join(',')})`);

	await client.finalize(ready.finalize, csr.csrDer);
	const valid = await pollUntil(() => client.fetchOrder(orderUrl), ['valid', 'invalid']);
	if (valid.status !== 'valid') {
		console.error('[!] Finalize failed:', JSON.stringify(valid, null, 2));
		throw new Error(`Order did not become valid: ${valid.status}`);
	}
	if (!valid.certificate) throw new Error('No certificate URL on valid order');

	const chain = await client.downloadCert(valid.certificate);
	const certPath = path.join(args.out, 'fullchain.pem');
	fs.writeFileSync(certPath, chain);
	console.log(`[+] Certificate written: ${certPath}`);

	// Cleanup DNS records (best-effort).
	for (const p of placements) {
		try {
			await hook.cleanup(p);
		} catch (e: any) {
			console.warn(`[!] Cleanup failed for ${p.name}: ${e?.message ?? e}`);
		}
	}
	console.log('[✓] Done.');
}

main().catch(err => {
	console.error('Error:', err?.message ?? err);
	process.exit(1);
});
