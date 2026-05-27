// Challenge validators. Both compute the key authorization
// (RFC 8555 §8.1: token + "." + base64url(JWK_Thumbprint(account key)))
// and either resolve a DNS TXT record (dns-01) or fetch an HTTP URL (http-01).

import http from 'http';
import {b64u, sha256} from './util.js';
import {resolveTxt} from './resolver.js';
import type {ResolverRule} from './config.js';

export function keyAuthorization(token: string, accountThumbprint: string): string {
	return `${token}.${accountThumbprint}`;
}

export function dns01TxtValue(token: string, accountThumbprint: string): string {
	// SHA-256 of the key authorization, base64url-encoded (RFC 8555 §8.4).
	return b64u(sha256(keyAuthorization(token, accountThumbprint)));
}

export type ValidationResult = {ok: boolean; detail?: string};

export async function validateDns01(opts: {
	identifier: string; // bare name, no "_acme-challenge." prefix
	wildcard: boolean;
	token: string;
	accountThumbprint: string;
	resolvers: ResolverRule[];
}): Promise<ValidationResult> {
	const expected = dns01TxtValue(opts.token, opts.accountThumbprint);
	const name = `_acme-challenge.${opts.identifier}`;
	let records: string[];
	try {
		records = await resolveTxt(name, opts.resolvers);
	} catch (e: any) {
		return {ok: false, detail: `DNS lookup failed for ${name}: ${e?.message ?? e}`};
	}
	if (!records.length) return {ok: false, detail: `No TXT records at ${name}`};
	if (!records.includes(expected)) {
		return {
			ok: false,
			detail: `TXT record at ${name} does not match expected key authorization`,
		};
	}
	return {ok: true};
}

export async function validateHttp01(opts: {
	identifier: string;
	token: string;
	accountThumbprint: string;
	port: number;
	timeoutMs?: number;
}): Promise<ValidationResult> {
	const expected = keyAuthorization(opts.token, opts.accountThumbprint);
	const url = `http://${opts.identifier}:${opts.port}/.well-known/acme-challenge/${opts.token}`;
	return new Promise(resolve => {
		const req = http.get(url, {timeout: opts.timeoutMs ?? 10_000}, res => {
			if (res.statusCode !== 200) {
				res.resume();
				return resolve({ok: false, detail: `HTTP ${res.statusCode} at ${url}`});
			}
			const chunks: Buffer[] = [];
			res.on('data', c => chunks.push(c));
			res.on('end', () => {
				const body = Buffer.concat(chunks).toString('utf8').trim();
				if (body === expected) return resolve({ok: true});
				return resolve({
					ok: false,
					detail: `HTTP body at ${url} does not match key authorization`,
				});
			});
		});
		req.on('error', err => resolve({ok: false, detail: `HTTP error: ${err.message}`}));
		req.on('timeout', () => {
			req.destroy();
			resolve({ok: false, detail: `HTTP timeout at ${url}`});
		});
	});
}
