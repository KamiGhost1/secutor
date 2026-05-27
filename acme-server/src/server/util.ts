import crypto from 'crypto';

export function b64u(buf: Buffer | string): string {
	const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf, 'utf8');
	return b
		.toString('base64')
		.replace(/=+$/g, '')
		.replace(/\+/g, '-')
		.replace(/\//g, '_');
}

export function b64uDecode(s: string): Buffer {
	const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
	return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}

export function sha256(buf: Buffer | string): Buffer {
	return crypto.createHash('sha256').update(buf).digest();
}

export function jwkThumbprint(jwk: Record<string, unknown>): string {
	// RFC 7638: canonical members per key type, sorted lexicographically.
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
			throw new Error(`Unsupported JWK kty: ${jwk.kty}`);
	}
	const json = JSON.stringify(canonical);
	return b64u(sha256(json));
}

export function nowIso(): string {
	return new Date().toISOString();
}

export function isoPlus(ms: number): string {
	return new Date(Date.now() + ms).toISOString();
}

export function randomToken(bytes = 32): string {
	return b64u(crypto.randomBytes(bytes));
}
