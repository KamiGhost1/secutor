import {test, before} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {buildRootCa, buildLeafCert} from '../src/certs/core.js';
import {
	signBuffer,
	signFile,
	verifyBuffer,
	verifyFile,
	manifestToJson,
	manifestFromJson,
	writeDetachedSignature,
	readDetachedSignature,
	buildSignatureBundle,
	parseSignatureBundle,
} from '../src/certs/signing.js';
import {KeyAlgorithm, encryptPrivateKey} from '../src/certs/keys.js';

let tmpRoot: string;

before(() => {
	tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'secutor-sig-'));
});

function dir(label: string): string {
	const d = path.join(tmpRoot, `${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
	fs.mkdirSync(d, {recursive: true});
	return d;
}

const ALGOS: KeyAlgorithm[] = ['rsa-2048', 'ecdsa-p256', 'ecdsa-p384', 'ed25519'];

for (const algo of ALGOS) {
	test(`sign + verify a buffer (${algo})`, () => {
		const root = buildRootCa({
			subject: {commonName: `sig-${algo}`},
			validityDays: 365,
			algorithm: algo,
		});
		const leaf = buildLeafCert({
			type: 'client',
			subject: {commonName: `signer-${algo}`},
			validityDays: 90,
			ca: {certPem: root.certPem, keyPem: root.keyPem},
			algorithm: algo,
		});

		const payload = Buffer.from('the quick brown fox jumps over the lazy dog');
		const manifest = signBuffer(payload, {
			privateKeyPem: leaf.keyPem,
			certPem: leaf.certPem,
		});

		assert.equal(manifest.alg, algo);
		assert.equal(manifest.v, 1);
		assert.equal(manifest.signer?.commonName, `signer-${algo}`);

		const result = verifyBuffer(payload, manifest);
		assert.equal(result.ok, true, `verify failed: ${result.reason}`);
		assert.equal(result.algorithm, algo);

		// Tampered payload must fail.
		const tampered = Buffer.from(payload);
		tampered[0] ^= 0x01;
		const bad = verifyBuffer(tampered, manifest);
		assert.equal(bad.ok, false);
		assert.match(bad.reason!, /digest|signature|match/i);
	});
}

test('signing with encrypted private key requires the passphrase', () => {
	const root = buildRootCa({
		subject: {commonName: 'enc-signer-root'},
		validityDays: 365,
	});
	const leaf = buildLeafCert({
		type: 'client',
		subject: {commonName: 'enc-signer'},
		validityDays: 90,
		ca: {certPem: root.certPem, keyPem: root.keyPem},
	});
	const encryptedKey = encryptPrivateKey(leaf.keyPem, 'pw');

	const payload = Buffer.from('hello');

	assert.throws(
		() => signBuffer(payload, {privateKeyPem: encryptedKey}),
		/password-protected|encrypted/i,
	);
	const m = signBuffer(payload, {privateKeyPem: encryptedKey, keyPassword: 'pw', certPem: leaf.certPem});
	const r = verifyBuffer(payload, m);
	assert.equal(r.ok, true);
});

test('detached signature file round-trip', () => {
	const d = dir('detached');
	const dataFile = path.join(d, 'app.bin');
	fs.writeFileSync(dataFile, Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x42, 0x42, 0x42]));

	const root = buildRootCa({
		subject: {commonName: 'detach-root'},
		validityDays: 365,
		algorithm: 'ed25519',
	});
	const leaf = buildLeafCert({
		type: 'client',
		subject: {commonName: 'detach-signer'},
		validityDays: 90,
		ca: {certPem: root.certPem, keyPem: root.keyPem},
		algorithm: 'ed25519',
	});

	const m = signFile(dataFile, {privateKeyPem: leaf.keyPem, certPem: leaf.certPem});
	const sigFile = writeDetachedSignature(dataFile, m);
	assert.ok(fs.existsSync(sigFile));

	const loaded = readDetachedSignature(sigFile);
	assert.equal(loaded.alg, m.alg);
	const r = verifyFile(dataFile, loaded);
	assert.equal(r.ok, true, r.reason);
});

test('bundled mode wraps and extracts data + manifest', () => {
	const data = Buffer.from('payload-payload-payload');
	const root = buildRootCa({
		subject: {commonName: 'bundle-root'},
		validityDays: 30,
		algorithm: 'ecdsa-p256',
	});
	const leaf = buildLeafCert({
		type: 'client',
		subject: {commonName: 'bundle-signer'},
		validityDays: 30,
		ca: {certPem: root.certPem, keyPem: root.keyPem},
		algorithm: 'ecdsa-p256',
	});

	const m = signBuffer(data, {privateKeyPem: leaf.keyPem, certPem: leaf.certPem});
	const bundle = buildSignatureBundle(data, m);

	const parsed = parseSignatureBundle(bundle);
	assert.deepEqual(parsed.data, data);
	const r = verifyBuffer(parsed.data, parsed.manifest);
	assert.equal(r.ok, true, r.reason);
});

test('verifier rejects when wrong cert/SPKI is supplied', () => {
	const rootA = buildRootCa({subject: {commonName: 'A'}, validityDays: 30});
	const leafA = buildLeafCert({
		type: 'client',
		subject: {commonName: 'a-signer'},
		validityDays: 30,
		ca: {certPem: rootA.certPem, keyPem: rootA.keyPem},
	});
	const rootB = buildRootCa({subject: {commonName: 'B'}, validityDays: 30});
	const leafB = buildLeafCert({
		type: 'client',
		subject: {commonName: 'b-signer'},
		validityDays: 30,
		ca: {certPem: rootB.certPem, keyPem: rootB.keyPem},
	});

	const data = Buffer.from('x');
	const m = signBuffer(data, {privateKeyPem: leafA.keyPem, certPem: leafA.certPem});

	const r = verifyBuffer(data, m, {expectedSignerPem: leafB.certPem});
	assert.equal(r.ok, false);
});

test('fingerprint pinning rejects a swapped cert (even if manifest carries it)', () => {
	const root = buildRootCa({subject: {commonName: 'pin'}, validityDays: 30});
	const leaf = buildLeafCert({
		type: 'client',
		subject: {commonName: 'pin-signer'},
		validityDays: 30,
		ca: {certPem: root.certPem, keyPem: root.keyPem},
	});
	const data = Buffer.from('x');
	const m = signBuffer(data, {privateKeyPem: leaf.keyPem, certPem: leaf.certPem});
	const r = verifyBuffer(data, m, {
		expectedFingerprint: '00'.repeat(32),
	});
	assert.equal(r.ok, false);
	assert.match(r.reason!, /fingerprint/i);
});

test('manifest JSON round-trip', () => {
	const root = buildRootCa({subject: {commonName: 'mj'}, validityDays: 30});
	const leaf = buildLeafCert({
		type: 'client',
		subject: {commonName: 'mj-signer'},
		validityDays: 30,
		ca: {certPem: root.certPem, keyPem: root.keyPem},
	});
	const m = signBuffer(Buffer.from('zz'), {privateKeyPem: leaf.keyPem, certPem: leaf.certPem});
	const json = manifestToJson(m);
	const back = manifestFromJson(json);
	assert.deepEqual(back, m);
});
