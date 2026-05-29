// Verifies the TUI's AdminApi wrapper drives the CA proof-of-possession
// protocol correctly: signs over the prefix+nonce on the server side, and
// the client check accepts the signature iff the supplied public key
// actually pairs with the server's private key.

import {test} from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import https from 'node:https';
import net from 'node:net';

import {buildRootCa} from '../src/certs/core.js';
import {makeHubClient} from '../src/net/hubClient.js';
import {AdminApi, verifyProofOfPossession} from '../src/net/adminApi.js';
import type {Hub} from '../src/storage/hubStore.js';

const PREFIX = Buffer.from('secutor-ca-verify-v1', 'utf8');

function sha256(buf: Buffer): string {
	return crypto.createHash('sha256').update(buf).digest('hex');
}

function pemToDer(pem: string): Buffer {
	const body = pem.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----/g, '').replace(/\s+/g, '');
	return Buffer.from(body, 'base64');
}

async function getPort(): Promise<number> {
	return new Promise(r => {
		const s = net.createServer();
		s.listen(0, () => {
			const p = (s.address() as any).port;
			s.close(() => r(p));
		});
	});
}

function signNonce(privPem: string, alg: string, nonce: Buffer): Buffer {
	const message = crypto.createHash('sha256').update(Buffer.concat([PREFIX, nonce])).digest();
	const key = crypto.createPrivateKey(privPem);
	const hash =
		alg === 'ed25519' ? null : alg === 'ecdsa-p384' ? 'sha384' : 'sha256';
	if (alg.startsWith('rsa')) {
		return crypto.sign(hash, message, {
			key,
			padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
			saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
		} as any);
	}
	return crypto.sign(hash, message, key);
}

function spinFakeHub(caPair: {certPem: string; keyPem: string}, alg: string) {
	const serverCa = buildRootCa({
		subject: {commonName: 'admin-srv'},
		validityDays: 1,
		algorithm: 'ecdsa-p256',
	});
	const clientCa = buildRootCa({
		subject: {commonName: 'admin-cli'},
		validityDays: 1,
		algorithm: 'ecdsa-p256',
	});
	return (async () => {
		const port = await getPort();
		const server = https.createServer(
			{cert: serverCa.certPem, key: serverCa.keyPem, requestCert: false},
			(req, res) => {
				let body = '';
				req.on('data', c => (body += c));
				req.on('end', () => {
					if (req.url === '/admin/v1/ca/verify' && req.method === 'POST') {
						const {nonce} = JSON.parse(body);
						const n = Buffer.from(nonce, 'base64url');
						const sig = signNonce(caPair.keyPem, alg, n);
						res.writeHead(200, {'content-type': 'application/json'});
						res.end(JSON.stringify({
							alg,
							hash: alg === 'ed25519' ? 'ed25519-intrinsic' : alg === 'ecdsa-p384' ? 'sha384' : 'sha256',
							signature: sig.toString('base64'),
							cert_pem: caPair.certPem,
						}));
						return;
					}
					res.writeHead(404).end();
				});
			},
		);
		await new Promise<void>(r => server.listen(port, '127.0.0.1', () => r()));
		const hub: Hub = {
			id: 'h', name: 'h',
			baseUrl: `https://127.0.0.1:${port}/`,
			serverFingerprint: sha256(pemToDer(serverCa.certPem)),
			clientAuth: {kind: 'file', certPath: '', keyPath: ''},
			addedAt: new Date().toISOString(),
		};
		const identity = {certPem: clientCa.certPem, keyPem: clientCa.keyPem, source: 'file' as const};
		const client = makeHubClient(hub, identity);
		return {
			api: new AdminApi(client),
			stop: async () => {
				client.close();
				await new Promise<void>(r => server.close(() => r()));
			},
		};
	})();
}

for (const alg of ['ecdsa-p256', 'ecdsa-p384', 'ed25519', 'rsa-2048'] as const) {
	test(`adminApi.verifyCa: ${alg} round-trip — correct expected key passes`, async () => {
		const ca = buildRootCa({
			subject: {commonName: `verify-${alg}`},
			validityDays: 1,
			algorithm: alg,
		});
		const {api, stop} = await spinFakeHub({certPem: ca.certPem, keyPem: ca.keyPem}, alg);
		try {
			const r = await api.verifyCa(ca.certPem);
			assert.equal(r.ok, true, `should accept matching key for ${alg}`);
			assert.equal(r.alg, alg);
			assert.equal(r.hubCertFingerprint, sha256(pemToDer(ca.certPem)));
		} finally {
			await stop();
		}
	});

	test(`adminApi.verifyCa: ${alg} — wrong expected key fails`, async () => {
		const ca = buildRootCa({subject: {commonName: 't'}, validityDays: 1, algorithm: alg});
		const other = buildRootCa({subject: {commonName: 'other'}, validityDays: 1, algorithm: alg});
		const {api, stop} = await spinFakeHub({certPem: ca.certPem, keyPem: ca.keyPem}, alg);
		try {
			const r = await api.verifyCa(other.certPem);
			assert.equal(r.ok, false, `should reject mismatched key for ${alg}`);
		} finally {
			await stop();
		}
	});
}

test('verifyProofOfPossession: unit — accepts a fresh signature over prefix+nonce', () => {
	const ca = buildRootCa({subject: {commonName: 'unit'}, validityDays: 1, algorithm: 'ecdsa-p256'});
	const nonce = crypto.randomBytes(32);
	const sig = signNonce(ca.keyPem, 'ecdsa-p256', nonce);
	assert.equal(
		verifyProofOfPossession({expectedPublicKeyPem: ca.certPem, nonce, signature: sig, alg: 'ecdsa-p256'}),
		true,
	);
});

test('verifyProofOfPossession: unit — rejects mutated nonce', () => {
	const ca = buildRootCa({subject: {commonName: 'unit2'}, validityDays: 1, algorithm: 'ecdsa-p256'});
	const nonce = crypto.randomBytes(32);
	const sig = signNonce(ca.keyPem, 'ecdsa-p256', nonce);
	const tampered = Buffer.from(nonce);
	tampered[0] ^= 0xff;
	assert.equal(
		verifyProofOfPossession({expectedPublicKeyPem: ca.certPem, nonce: tampered, signature: sig, alg: 'ecdsa-p256'}),
		false,
	);
});
