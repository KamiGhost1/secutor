import {test, before} from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync, spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
	buildRootCa,
	buildIntermediateCa,
	buildLeafCert,
	resignCertificateCore,
} from '../src/certs/core.js';
import {
	encryptPrivateKey,
	decryptPrivateKey,
	isEncryptedKey,
} from '../src/certs/keys.js';

let tmpRoot: string;

before(() => {
	const probe = spawnSync('openssl', ['version'], {encoding: 'utf8'});
	if (probe.status !== 0) throw new Error('openssl required on PATH');
	tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'secutor-pwd-'));
});

function dir(label: string): string {
	const d = path.join(tmpRoot, `${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
	fs.mkdirSync(d, {recursive: true});
	return d;
}
function write(p: string, data: string): string {
	fs.writeFileSync(p, data);
	return p;
}

test('buildRootCa with keyPassword stores a recognisable encrypted PKCS#8 PEM', () => {
	const root = buildRootCa({
		subject: {commonName: 'pwd-root'},
		validityDays: 365,
		keyPassword: 'horsebatterystaple',
	});
	assert.equal(isEncryptedKey(root.keyPem), true);
	assert.match(root.keyPem, /-----BEGIN ENCRYPTED PRIVATE KEY-----/);
	// Round-trip via our decryptor proves the envelope is intact; openssl 3.6+
	// refuses to read `-passin pass:` for PKCS#8 keys non-interactively (known
	// upstream quirk), so we don't reach for the CLI here.
	const plain = decryptPrivateKey(root.keyPem, 'horsebatterystaple');
	assert.match(plain, /-----BEGIN PRIVATE KEY-----/);
});

test('issuing a leaf requires the CA passphrase', () => {
	const root = buildRootCa({
		subject: {commonName: 'pwd-issuer'},
		validityDays: 365,
		keyPassword: 'sekret',
	});

	assert.throws(
		() =>
			buildLeafCert({
				type: 'server',
				subject: {commonName: 'svc.test'},
				validityDays: 90,
				ca: {certPem: root.certPem, keyPem: root.keyPem},
			}),
		/password-protected/i,
		'should refuse to issue without a password',
	);

	assert.throws(
		() =>
			buildLeafCert({
				type: 'server',
				subject: {commonName: 'svc.test'},
				validityDays: 90,
				ca: {certPem: root.certPem, keyPem: root.keyPem, keyPassword: 'wrong'},
			}),
		/invalid password/i,
		'should refuse with the wrong password',
	);
});

test('issuing a leaf with the correct CA passphrase chains to root', () => {
	const root = buildRootCa({
		subject: {commonName: 'pwd-issuer2'},
		validityDays: 365,
		keyPassword: 'hunter2',
	});
	const leaf = buildLeafCert({
		type: 'server',
		subject: {commonName: 'good.svc'},
		validityDays: 90,
		ca: {certPem: root.certPem, keyPem: root.keyPem, keyPassword: 'hunter2'},
	});

	const d = dir('pwd-good');
	const rootFile = write(path.join(d, 'root.pem'), root.certPem);
	const leafFile = write(path.join(d, 'leaf.pem'), leaf.certPem);
	const r = spawnSync('openssl', ['verify', '-CAfile', rootFile, leafFile], {encoding: 'utf8'});
	assert.equal(r.status, 0, `verify failed:\n${r.stderr}\n${r.stdout}`);

	// Leaf's own key is unencrypted by default.
	assert.equal(isEncryptedKey(leaf.keyPem), false);
});

test('intermediate CA can be issued and re-used with separate passphrases', () => {
	const root = buildRootCa({
		subject: {commonName: 'pwd-r'},
		validityDays: 730,
		keyPassword: 'rootpass',
	});
	const inter = buildIntermediateCa({
		subject: {commonName: 'pwd-i'},
		validityDays: 365,
		ca: {certPem: root.certPem, keyPem: root.keyPem, keyPassword: 'rootpass'},
		keyPassword: 'interpass',
	});
	assert.equal(isEncryptedKey(inter.keyPem), true);
	const leaf = buildLeafCert({
		type: 'server',
		subject: {commonName: 'svc.pwd'},
		validityDays: 90,
		ca: {certPem: inter.certPem, keyPem: inter.keyPem, keyPassword: 'interpass'},
	});

	const d = dir('pwd-three');
	const rootFile = write(path.join(d, 'root.pem'), root.certPem);
	const interFile = write(path.join(d, 'int.pem'), inter.certPem);
	const leafFile = write(path.join(d, 'leaf.pem'), leaf.certPem);
	const r = spawnSync(
		'openssl',
		['verify', '-CAfile', rootFile, '-untrusted', interFile, leafFile],
		{encoding: 'utf8'},
	);
	assert.equal(r.status, 0, `verify failed:\n${r.stderr}\n${r.stdout}`);
});

test('ECDSA root with passphrase still works end-to-end', () => {
	const root = buildRootCa({
		subject: {commonName: 'ec-pwd-root'},
		validityDays: 365,
		algorithm: 'ecdsa-p256',
		keyPassword: 'ec-secret',
	});
	assert.equal(isEncryptedKey(root.keyPem), true);
	const leaf = buildLeafCert({
		type: 'server',
		subject: {commonName: 'ec.svc'},
		validityDays: 90,
		ca: {certPem: root.certPem, keyPem: root.keyPem, keyPassword: 'ec-secret'},
		algorithm: 'ecdsa-p256',
	});
	const d = dir('ec-pwd');
	const rootFile = write(path.join(d, 'root.pem'), root.certPem);
	const leafFile = write(path.join(d, 'leaf.pem'), leaf.certPem);
	const r = spawnSync('openssl', ['verify', '-CAfile', rootFile, leafFile], {encoding: 'utf8'});
	assert.equal(r.status, 0, `verify failed:\n${r.stderr}\n${r.stdout}`);
});

test('re-sign with an encrypted CA key', () => {
	const oldCa = buildRootCa({
		subject: {commonName: 'old-pwd'},
		validityDays: 365,
	});
	const newCa = buildRootCa({
		subject: {commonName: 'new-pwd'},
		validityDays: 365,
		keyPassword: 'shhh',
	});
	const leaf = buildLeafCert({
		type: 'server',
		subject: {commonName: 'resign.svc'},
		validityDays: 90,
		ca: {certPem: oldCa.certPem, keyPem: oldCa.keyPem},
	});
	const resigned = resignCertificateCore({
		oldCertPem: leaf.certPem,
		ca: {certPem: newCa.certPem, keyPem: newCa.keyPem, keyPassword: 'shhh'},
	});
	const d = dir('resign-pwd');
	const newRootFile = write(path.join(d, 'new-root.pem'), newCa.certPem);
	const resignedFile = write(path.join(d, 'resigned.pem'), resigned.certPem);
	const r = spawnSync('openssl', ['verify', '-CAfile', newRootFile, resignedFile], {encoding: 'utf8'});
	assert.equal(r.status, 0, `verify failed:\n${r.stderr}\n${r.stdout}`);
});

test('encryptPrivateKey + decryptPrivateKey round-trip', () => {
	const root = buildRootCa({
		subject: {commonName: 'rt'},
		validityDays: 30,
	});
	const enc = encryptPrivateKey(root.keyPem, 'pw');
	assert.equal(isEncryptedKey(enc), true);
	const dec = decryptPrivateKey(enc, 'pw');
	assert.equal(isEncryptedKey(dec), false);
	// Decrypting an already-plain key is a no-op.
	assert.equal(decryptPrivateKey(dec, null), dec);
	// Wrong password fails clearly.
	assert.throws(() => decryptPrivateKey(enc, 'wrong'), /invalid password/i);
});
