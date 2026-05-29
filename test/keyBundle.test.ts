import {test} from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
	buildPlainBundle,
	buildEncryptedBundle,
	parseBundle,
	bundleVariant,
	isBundleFile,
	newManifest,
	textToData,
	dataToText,
	bytesToData,
	dataToBytes,
	BundleManifest,
} from '../src/transfer/keyBundle.js';

// Use low scrypt cost throughout the test file so the suite stays fast.
// The format encodes these params per-file, so production defaults stay strong.
const CHEAP = {logN: 12, r: 8, p: 1};

function sampleLeafManifest(): BundleManifest {
	return newManifest('leaf', 'my-leaf', 'ctx-a', [
		{role: 'cert', encoding: 'pem', data: textToData('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n')},
		{role: 'key', encoding: 'pem', encrypted: false, data: textToData('-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----\n')},
	], {
		fingerprint: 'aa'.repeat(32),
		links: {issuerFingerprint: 'bb'.repeat(32)},
	});
}

test('plain bundle: round-trip without payload', () => {
	const m = sampleLeafManifest();
	const buf = buildPlainBundle(m);
	assert.ok(isBundleFile(buf), 'magic recognized');
	assert.equal(bundleVariant(buf), 'plain');

	const parsed = parseBundle(buf);
	assert.equal(parsed.encrypted, false);
	assert.equal(parsed.payload.length, 0);
	assert.equal(parsed.manifest.kind, 'leaf');
	assert.equal(parsed.manifest.name, 'my-leaf');
	assert.equal(parsed.manifest.items.length, 2);
	assert.equal(parsed.manifest.items[0]!.role, 'cert');
	assert.match(
		dataToText(parsed.manifest.items[0]!.data),
		/BEGIN CERTIFICATE/,
	);
});

test('plain bundle: round-trip with trailing payload (P12 DER)', () => {
	const m = newManifest('profile', 'svc.p12', 'ctx-a', [
		{role: 'p12', encoding: 'pkcs12', data: ''}, // data empty — actual bytes in payload
	]);
	const fakeDer = crypto.randomBytes(2048);
	const buf = buildPlainBundle(m, fakeDer);
	const parsed = parseBundle(buf);

	assert.equal(parsed.payload.length, fakeDer.length);
	assert.equal(parsed.payload.equals(fakeDer), true);
	assert.equal(parsed.manifest.items[0]!.role, 'p12');
});

test('encrypted bundle: round-trip with correct password', () => {
	const m = sampleLeafManifest();
	const buf = buildEncryptedBundle(m, undefined, 'correct horse battery staple', CHEAP);
	assert.equal(bundleVariant(buf), 'encrypted');

	const parsed = parseBundle(buf, 'correct horse battery staple');
	assert.equal(parsed.encrypted, true);
	assert.equal(parsed.manifest.kind, 'leaf');
	assert.equal(parsed.manifest.items[0]!.role, 'cert');
});

test('encrypted bundle: wrong password fails with clear error', () => {
	const m = sampleLeafManifest();
	const buf = buildEncryptedBundle(m, undefined, 'real-pass', CHEAP);
	assert.throws(() => parseBundle(buf, 'wrong-pass'), /wrong password|corrupted/);
});

test('encrypted bundle: missing password fails before any KDF work', () => {
	const m = sampleLeafManifest();
	const buf = buildEncryptedBundle(m, undefined, 'pw', CHEAP);
	assert.throws(() => parseBundle(buf), /password required/);
});

test('encrypted bundle: tampered ciphertext rejected by AEAD', () => {
	const m = sampleLeafManifest();
	const buf = buildEncryptedBundle(m, undefined, 'pw', CHEAP);
	// Flip a byte deep inside the ciphertext.
	buf[buf.length - 30] ^= 0x01;
	assert.throws(() => parseBundle(buf, 'pw'), /wrong password|corrupted/);
});

test('encrypted bundle: payload survives the envelope', () => {
	const m = newManifest('profile', 'svc.p12', 'ctx-a', [
		{role: 'p12', encoding: 'pkcs12', data: ''},
	]);
	const fakeDer = crypto.randomBytes(4096);
	const buf = buildEncryptedBundle(m, fakeDer, 'pw', CHEAP);
	const parsed = parseBundle(buf, 'pw');
	assert.equal(parsed.payload.equals(fakeDer), true);
});

test('isBundleFile / bundleVariant reject garbage', () => {
	const garbage = Buffer.from('this is not a bundle');
	assert.equal(isBundleFile(garbage), false);
	assert.equal(bundleVariant(garbage), null);
});

test('parseBundle rejects truncated header', () => {
	assert.throws(() => parseBundle(Buffer.from('SECUTOR_KB')), /bad magic|too short|version/);
});

test('parseBundle rejects unknown version', () => {
	const m = sampleLeafManifest();
	const buf = buildPlainBundle(m);
	buf[11] = 0x09; // bump version byte
	assert.throws(() => parseBundle(buf), /unsupported bundle version/);
});

test('parseBundle rejects malformed manifest length', () => {
	const m = sampleLeafManifest();
	const buf = buildPlainBundle(m);
	// 12 = header end, next 4 bytes = manifest length BE. Make it huge.
	buf.writeUInt32BE(0xffffffff, 12);
	assert.throws(() => parseBundle(buf), /out of range/);
});

test('parseBundle rejects manifest with wrong v', () => {
	const m = sampleLeafManifest();
	(m as any).v = 99;
	const buf = buildPlainBundle(m);
	assert.throws(() => parseBundle(buf), /v1 schema/);
});

test('subtree manifest carries multiple items with per-item meta', () => {
	const m = newManifest('subtree', 'root-bundle', 'ctx-a', [
		{role: 'cert', encoding: 'pem', data: textToData('ROOT'), meta: {name: 'root', type: 'ca', fingerprint: '11'.repeat(32)}},
		{role: 'child', encoding: 'pem', data: textToData('INTER'), meta: {name: 'intermediate', type: 'ca', fingerprint: '22'.repeat(32), issuerFingerprint: '11'.repeat(32)}},
		{role: 'child', encoding: 'pem', data: textToData('LEAF'), meta: {name: 'leaf', type: 'server', fingerprint: '33'.repeat(32), issuerFingerprint: '22'.repeat(32)}},
	], {
		links: {subtreeFingerprints: ['11'.repeat(32), '22'.repeat(32), '33'.repeat(32)]},
	});
	const buf = buildPlainBundle(m);
	const parsed = parseBundle(buf);
	assert.equal(parsed.manifest.kind, 'subtree');
	assert.equal(parsed.manifest.items.length, 3);
	assert.equal(parsed.manifest.items[2]!.meta?.issuerFingerprint, '22'.repeat(32));
	assert.equal(parsed.manifest.links?.subtreeFingerprints?.length, 3);
});

test('bytes helpers round-trip', () => {
	const b = crypto.randomBytes(100);
	assert.equal(dataToBytes(bytesToData(b)).equals(b), true);
	const s = 'hello\nworld\n';
	assert.equal(dataToText(textToData(s)), s);
});

test('encrypted bundle: different password produces different ciphertext', () => {
	const m = sampleLeafManifest();
	const a = buildEncryptedBundle(m, undefined, 'pw-a', CHEAP);
	const b = buildEncryptedBundle(m, undefined, 'pw-b', CHEAP);
	// Different salt + different key, so even header beyond byte 11 differs.
	assert.notEqual(a.equals(b), true);
});

test('encrypted bundle: same password produces different ciphertext (random salt/iv)', () => {
	const m = sampleLeafManifest();
	const a = buildEncryptedBundle(m, undefined, 'pw', CHEAP);
	const b = buildEncryptedBundle(m, undefined, 'pw', CHEAP);
	assert.notEqual(a.equals(b), true);
});
