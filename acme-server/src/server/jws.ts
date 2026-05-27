// RFC 8555 §6.2 — every ACME request body is a flattened JWS.
//
// Headers MUST include:
//   alg (≠ "none"), nonce, url, and exactly one of {jwk, kid}.
// "jwk" is used for newAccount / revokeCert with a cert key; everything else
// uses "kid" = the account URL.

import {flattenedVerify, importJWK, type JWK} from 'jose';
import {b64uDecode, jwkThumbprint} from './util.js';
import {AcmeError} from './errors.js';

export type ParsedJws = {
	protectedHeader: {
		alg: string;
		nonce: string;
		url: string;
		jwk?: JWK;
		kid?: string;
	};
	payload: Buffer; // raw (may be empty for POST-as-GET)
	payloadJson: unknown | null; // parsed if non-empty
	jwk: JWK; // resolved (from header or from kid lookup)
	thumbprint: string;
	accountUrl?: string;
};

const ALLOWED_ALG = new Set([
	'RS256',
	'RS384',
	'RS512',
	'ES256',
	'ES384',
	'ES512',
	'EdDSA',
	'PS256',
	'PS384',
	'PS512',
]);

export type JwsRequestBody = {
	protected: string;
	payload: string;
	signature: string;
};

export async function verifyJws(
	body: JwsRequestBody,
	expectedUrl: string,
	resolveJwkByKid: (kid: string) => JWK | null,
): Promise<ParsedJws> {
	if (!body || typeof body !== 'object' || !body.protected || !body.signature) {
		throw new AcmeError('malformed', 'Request is not a JWS object');
	}
	const protectedHeader = JSON.parse(b64uDecode(body.protected).toString('utf8'));

	if (!protectedHeader.alg || !ALLOWED_ALG.has(protectedHeader.alg)) {
		throw new AcmeError('badSignatureAlgorithm', `Unsupported alg: ${protectedHeader.alg}`);
	}
	if (!protectedHeader.nonce) {
		throw new AcmeError('badNonce', 'Missing nonce');
	}
	if (!protectedHeader.url || protectedHeader.url !== expectedUrl) {
		throw new AcmeError('unauthorized', `JWS url mismatch (got ${protectedHeader.url})`);
	}
	const hasJwk = !!protectedHeader.jwk;
	const hasKid = !!protectedHeader.kid;
	if (hasJwk === hasKid) {
		throw new AcmeError('malformed', 'Must specify exactly one of jwk/kid');
	}

	let jwk: JWK;
	let accountUrl: string | undefined;
	if (hasJwk) {
		jwk = protectedHeader.jwk as JWK;
	} else {
		const kid = protectedHeader.kid as string;
		const resolved = resolveJwkByKid(kid);
		if (!resolved) {
			throw new AcmeError('accountDoesNotExist', `Unknown kid: ${kid}`, 400);
		}
		jwk = resolved;
		accountUrl = kid;
	}

	const key = await importJWK(jwk, protectedHeader.alg);
	let verified;
	try {
		verified = await flattenedVerify(body, key);
	} catch (err: any) {
		throw new AcmeError('unauthorized', `JWS verification failed: ${err?.message ?? err}`);
	}

	const payload = Buffer.from(verified.payload);
	const payloadJson = payload.length === 0 ? null : JSON.parse(payload.toString('utf8'));

	return {
		protectedHeader,
		payload,
		payloadJson,
		jwk,
		thumbprint: jwkThumbprint(jwk as unknown as Record<string, unknown>),
		accountUrl,
	};
}
