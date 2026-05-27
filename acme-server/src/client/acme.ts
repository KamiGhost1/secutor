// ACME client library. Minimal but production-shaped:
//  - JWS-signed POST and POST-as-GET
//  - automatic nonce rotation from Replay-Nonce headers
//  - DNS-01 (with caller-supplied placement hook) and HTTP-01
//
// All methods throw on non-2xx ACME responses, surfacing the problem document.

import crypto from 'crypto';
import {
	exportJWK,
	importPKCS8,
	SignJWT,
	FlattenedSign,
	generateKeyPair,
	type JWK,
} from 'jose';

export type Identifier = {type: 'dns'; value: string};

export type Directory = {
	newNonce: string;
	newAccount: string;
	newOrder: string;
	revokeCert: string;
	keyChange: string;
	meta?: Record<string, unknown>;
};

export type OrderResponse = {
	status: 'pending' | 'ready' | 'processing' | 'valid' | 'invalid';
	expires: string;
	identifiers: Identifier[];
	authorizations: string[];
	finalize: string;
	certificate?: string;
	error?: unknown;
};

export type AuthzResponse = {
	status: string;
	expires: string;
	identifier: Identifier;
	wildcard?: boolean;
	challenges: Array<{
		type: string;
		url: string;
		status: string;
		token: string;
		error?: unknown;
	}>;
};

export type AccountKey = {
	privateKeyPem: string;
	publicJwk: JWK;
	thumbprint: string;
	alg: 'RS256' | 'ES256' | 'EdDSA';
};

function b64u(buf: Buffer): string {
	return buf.toString('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function jwkThumbprint(jwk: JWK): string {
	let canonical: Record<string, unknown>;
	switch (jwk.kty) {
		case 'RSA':
			canonical = {e: jwk.e, kty: 'RSA', n: jwk.n};
			break;
		case 'EC':
			canonical = {crv: jwk.crv, kty: 'EC', x: jwk.x, y: jwk.y};
			break;
		case 'OKP':
			canonical = {crv: jwk.crv, kty: 'OKP', x: jwk.x};
			break;
		default:
			throw new Error(`Unsupported kty: ${jwk.kty}`);
	}
	return b64u(crypto.createHash('sha256').update(JSON.stringify(canonical)).digest());
}

export async function generateAccountKey(
	algo: 'EC' | 'RSA' | 'Ed25519' = 'EC',
): Promise<AccountKey> {
	const opts: {alg: 'RS256' | 'ES256' | 'EdDSA'; gen: () => Promise<{privateKey: any; publicKey: any}>} =
		algo === 'RSA'
			? {alg: 'RS256', gen: () => generateKeyPair('RS256', {modulusLength: 2048, extractable: true} as any)}
			: algo === 'Ed25519'
				? {alg: 'EdDSA', gen: () => generateKeyPair('EdDSA', {crv: 'Ed25519', extractable: true} as any)}
				: {alg: 'ES256', gen: () => generateKeyPair('ES256', {extractable: true} as any)};
	const {privateKey, publicKey} = await opts.gen();
	const pub = await exportJWK(publicKey);
	const priv = (privateKey as crypto.KeyObject).export({type: 'pkcs8', format: 'pem'}) as string;
	return {privateKeyPem: priv, publicJwk: pub, thumbprint: jwkThumbprint(pub), alg: opts.alg};
}

export async function loadAccountKey(privateKeyPem: string): Promise<AccountKey> {
	const k = crypto.createPrivateKey(privateKeyPem);
	const pub = crypto.createPublicKey(k);
	const jwk = pub.export({format: 'jwk'}) as JWK;
	let alg: AccountKey['alg'];
	switch (k.asymmetricKeyType) {
		case 'rsa':
		case 'rsa-pss':
			alg = 'RS256';
			break;
		case 'ec':
			alg = 'ES256';
			break;
		case 'ed25519':
			alg = 'EdDSA';
			break;
		default:
			throw new Error(`Unsupported account key type: ${k.asymmetricKeyType}`);
	}
	return {privateKeyPem, publicJwk: jwk, thumbprint: jwkThumbprint(jwk), alg};
}

export class AcmeClient {
	private nonce: string | null = null;
	private directory: Directory | null = null;
	private kid: string | null = null;

	constructor(private directoryUrl: string, private acctKey: AccountKey) {}

	async getDirectory(): Promise<Directory> {
		if (this.directory) return this.directory;
		const res = await fetch(this.directoryUrl);
		if (!res.ok) throw new Error(`directory fetch failed: ${res.status}`);
		this.directory = (await res.json()) as Directory;
		this.consumeNonce(res);
		return this.directory;
	}

	private consumeNonce(res: Response): void {
		const n = res.headers.get('replay-nonce');
		if (n) this.nonce = n;
	}

	async getNonce(): Promise<string> {
		if (this.nonce) {
			const n = this.nonce;
			this.nonce = null;
			return n;
		}
		const dir = await this.getDirectory();
		const res = await fetch(dir.newNonce, {method: 'HEAD'});
		const n = res.headers.get('replay-nonce');
		if (!n) throw new Error('Server returned no nonce');
		return n;
	}

	private async signRequest(url: string, payload: unknown): Promise<string> {
		const priv = await importPKCS8(this.acctKey.privateKeyPem, this.acctKey.alg);
		const nonce = await this.getNonce();
		const header: Record<string, unknown> = {alg: this.acctKey.alg, nonce, url};
		if (this.kid) header.kid = this.kid;
		else header.jwk = this.acctKey.publicJwk;
		const bodyBytes =
			payload === null || payload === undefined
				? new Uint8Array(0)
				: new TextEncoder().encode(typeof payload === 'string' ? payload : JSON.stringify(payload));
		const jws = await new FlattenedSign(bodyBytes).setProtectedHeader(header as any).sign(priv);
		return JSON.stringify(jws);
	}

	async post(url: string, payload: unknown): Promise<{res: Response; body: unknown}> {
		for (let attempt = 0; attempt < 2; attempt++) {
			const body = await this.signRequest(url, payload);
			const res = await fetch(url, {
				method: 'POST',
				headers: {'Content-Type': 'application/jose+json'},
				body,
			});
			this.consumeNonce(res);
			const text = await res.text();
			let parsed: unknown = text;
			try {
				parsed = text ? JSON.parse(text) : null;
			} catch {}
			if (res.status === 400 && (parsed as any)?.type?.endsWith(':badNonce') && attempt === 0) {
				// fresh nonce was attached via header; retry once
				continue;
			}
			if (!res.ok) {
				throw new Error(`ACME ${url} → ${res.status}: ${typeof parsed === 'string' ? parsed : JSON.stringify(parsed)}`);
			}
			return {res, body: parsed};
		}
		throw new Error('Exhausted retry attempts');
	}

	async register(contact?: string[]): Promise<string> {
		const dir = await this.getDirectory();
		const {res, body} = await this.post(dir.newAccount, {
			termsOfServiceAgreed: true,
			contact: contact ?? [],
		});
		const loc = res.headers.get('location');
		if (!loc) throw new Error('newAccount: missing Location header');
		this.kid = loc;
		void body;
		return loc;
	}

	async newOrder(identifiers: Identifier[]): Promise<{url: string; order: OrderResponse}> {
		const dir = await this.getDirectory();
		const {res, body} = await this.post(dir.newOrder, {identifiers});
		const url = res.headers.get('location');
		if (!url) throw new Error('newOrder: missing Location');
		return {url, order: body as OrderResponse};
	}

	async fetchOrder(url: string): Promise<OrderResponse> {
		const {body} = await this.post(url, ''); // POST-as-GET
		return body as OrderResponse;
	}

	async fetchAuthz(url: string): Promise<AuthzResponse> {
		const {body} = await this.post(url, '');
		return body as AuthzResponse;
	}

	async triggerChallenge(url: string): Promise<unknown> {
		const {body} = await this.post(url, {});
		return body;
	}

	async finalize(finalizeUrl: string, csrDer: Buffer): Promise<OrderResponse> {
		const {body} = await this.post(finalizeUrl, {csr: b64u(csrDer)});
		return body as OrderResponse;
	}

	async downloadCert(certUrl: string): Promise<string> {
		const {body} = await this.post(certUrl, '');
		return body as string;
	}

	keyAuthorization(token: string): string {
		return `${token}.${this.acctKey.thumbprint}`;
	}

	dns01TxtValue(token: string): string {
		const ka = this.keyAuthorization(token);
		return b64u(crypto.createHash('sha256').update(ka).digest());
	}
}

/**
 * Poll an order or authz until it reaches one of the target statuses
 * or until timeout. Exponential-ish: 1s, 2s, 3s, 5s, 5s ...
 */
export async function pollUntil<T extends {status: string}>(
	fetcher: () => Promise<T>,
	targets: string[],
	timeoutMs = 120_000,
): Promise<T> {
	const start = Date.now();
	const delays = [1000, 2000, 3000, 5000];
	let i = 0;
	while (true) {
		const obj = await fetcher();
		if (targets.includes(obj.status)) return obj;
		if (Date.now() - start > timeoutMs) {
			throw new Error(`Poll timeout (status=${obj.status})`);
		}
		await new Promise(r => setTimeout(r, delays[Math.min(i, delays.length - 1)]!));
		i++;
	}
}
