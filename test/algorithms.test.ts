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
import {KeyAlgorithm} from '../src/certs/keys.js';

let tmpRoot: string;

before(() => {
	const probe = spawnSync('openssl', ['version'], {encoding: 'utf8'});
	if (probe.status !== 0) {
		throw new Error('openssl is required on PATH for algorithm tests');
	}
	tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'secutor-algo-'));
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
function verify(args: string[]): {ok: boolean; output: string} {
	const r = spawnSync('openssl', ['verify', ...args], {encoding: 'utf8'});
	return {ok: r.status === 0, output: (r.stdout || '') + (r.stderr || '')};
}
function pubkeyAlg(file: string): string {
	return execFileSync('openssl', ['x509', '-in', file, '-noout', '-text'], {encoding: 'utf8'});
}

const SIGNING: KeyAlgorithm[] = [
	'ecdsa-p256',
	'ecdsa-p384',
	'ed25519',
];

for (const algo of SIGNING) {
	test(`${algo}: root CA self-verifies via openssl`, () => {
		const d = dir(`root-${algo}`);
		const root = buildRootCa({
			subject: {commonName: `root-${algo}`},
			validityDays: 365,
			algorithm: algo,
		});
		assert.equal(root.algorithm, algo);
		const f = write(path.join(d, 'root.pem'), root.certPem);
		const v = verify(['-CAfile', f, f]);
		assert.equal(v.ok, true, `openssl verify failed for ${algo}:\n${v.output}`);

		const text = pubkeyAlg(f);
		if (algo === 'ecdsa-p256') {
			assert.match(text, /id-ecPublicKey|ASN1 OID: prime256v1|ASN1 OID: P-256/);
			assert.match(text, /ecdsa-with-SHA256/);
		} else if (algo === 'ecdsa-p384') {
			assert.match(text, /id-ecPublicKey|secp384r1|P-384/);
			assert.match(text, /ecdsa-with-SHA384/);
		} else if (algo === 'ed25519') {
			assert.match(text, /ED25519|Ed25519/);
		}
	});

	test(`${algo}: leaf signed by ${algo} root verifies via openssl`, () => {
		const d = dir(`leaf-${algo}`);
		const root = buildRootCa({
			subject: {commonName: `root-${algo}`},
			validityDays: 365,
			algorithm: algo,
		});
		const leaf = buildLeafCert({
			type: 'server',
			subject: {commonName: 'svc.test'},
			validityDays: 90,
			sans: ['svc.test', '10.0.0.5'],
			ca: {certPem: root.certPem, keyPem: root.keyPem},
			algorithm: algo,
		});
		const rootFile = write(path.join(d, 'root.pem'), root.certPem);
		const leafFile = write(path.join(d, 'leaf.pem'), leaf.certPem);
		const v = verify(['-CAfile', rootFile, leafFile]);
		assert.equal(v.ok, true, `verify failed for leaf signed by ${algo} root:\n${v.output}`);

		const text = pubkeyAlg(leafFile);
		assert.match(text, /DNS:svc\.test/);
		assert.match(text, /IP Address:10\.0\.0\.5/);
	});

	test(`${algo}: three-tier chain (root → int → leaf) verifies via openssl`, () => {
		const d = dir(`chain-${algo}`);
		const root = buildRootCa({
			subject: {commonName: `root-${algo}`},
			validityDays: 730,
			algorithm: algo,
		});
		const inter = buildIntermediateCa({
			subject: {commonName: `int-${algo}`},
			validityDays: 365,
			ca: {certPem: root.certPem, keyPem: root.keyPem},
			algorithm: algo,
		});
		const leaf = buildLeafCert({
			type: 'server',
			subject: {commonName: 'svc.chain'},
			validityDays: 90,
			ca: {certPem: inter.certPem, keyPem: inter.keyPem},
			algorithm: algo,
		});
		const rootFile = write(path.join(d, 'root.pem'), root.certPem);
		const interFile = write(path.join(d, 'int.pem'), inter.certPem);
		const leafFile = write(path.join(d, 'leaf.pem'), leaf.certPem);

		const v = verify(['-CAfile', rootFile, '-untrusted', interFile, leafFile]);
		assert.equal(v.ok, true, `${algo} chain failed:\n${v.output}`);
	});
}

test('mixed: RSA root signs ECDSA leaf — verifies', () => {
	const d = dir('mixed-rsa-ec');
	const root = buildRootCa({
		subject: {commonName: 'rsa-root'},
		validityDays: 365,
		// default RSA
	});
	const leaf = buildLeafCert({
		type: 'server',
		subject: {commonName: 'ec.under.rsa'},
		validityDays: 90,
		ca: {certPem: root.certPem, keyPem: root.keyPem},
		algorithm: 'ecdsa-p256',
	});
	const rootFile = write(path.join(d, 'root.pem'), root.certPem);
	const leafFile = write(path.join(d, 'leaf.pem'), leaf.certPem);
	const v = verify(['-CAfile', rootFile, leafFile]);
	assert.equal(v.ok, true, `mixed RSA→ECDSA failed:\n${v.output}`);

	const text = pubkeyAlg(leafFile);
	assert.match(text, /id-ecPublicKey|prime256v1|P-256/);
	// Signature alg is RSA (the CA's algorithm):
	assert.match(text, /sha256WithRSAEncryption/);
});

test('mixed: ECDSA root signs RSA leaf — verifies', () => {
	const d = dir('mixed-ec-rsa');
	const root = buildRootCa({
		subject: {commonName: 'ec-root'},
		validityDays: 365,
		algorithm: 'ecdsa-p256',
	});
	const leaf = buildLeafCert({
		type: 'server',
		subject: {commonName: 'rsa.under.ec'},
		validityDays: 90,
		ca: {certPem: root.certPem, keyPem: root.keyPem},
		algorithm: 'rsa-2048',
	});
	const rootFile = write(path.join(d, 'root.pem'), root.certPem);
	const leafFile = write(path.join(d, 'leaf.pem'), leaf.certPem);
	const v = verify(['-CAfile', rootFile, leafFile]);
	assert.equal(v.ok, true, `mixed ECDSA→RSA failed:\n${v.output}`);

	const text = pubkeyAlg(leafFile);
	assert.match(text, /rsaEncryption/);
	assert.match(text, /ecdsa-with-SHA256/);
});

test('re-sign ECDSA leaf with a fresh ECDSA CA preserves the public key', () => {
	const d = dir('resign-ec');
	const oldCa = buildRootCa({
		subject: {commonName: 'old-ec-root'},
		validityDays: 365,
		algorithm: 'ecdsa-p256',
	});
	const newCa = buildRootCa({
		subject: {commonName: 'new-ec-root'},
		validityDays: 365,
		algorithm: 'ecdsa-p384',
	});
	const leaf = buildLeafCert({
		type: 'server',
		subject: {commonName: 'ec.resign'},
		validityDays: 90,
		ca: {certPem: oldCa.certPem, keyPem: oldCa.keyPem},
		algorithm: 'ecdsa-p256',
	});
	const resigned = resignCertificateCore({
		oldCertPem: leaf.certPem,
		ca: {certPem: newCa.certPem, keyPem: newCa.keyPem},
	});
	const newCaFile = write(path.join(d, 'new-root.pem'), newCa.certPem);
	const oldLeafFile = write(path.join(d, 'old-leaf.pem'), leaf.certPem);
	const resignedFile = write(path.join(d, 'resigned.pem'), resigned.certPem);

	const ok = verify(['-CAfile', newCaFile, resignedFile]);
	assert.equal(ok.ok, true, `re-signed ECDSA leaf failed:\n${ok.output}`);

	// Public key preserved across re-sign.
	const oldPub = execFileSync('openssl', ['x509', '-in', oldLeafFile, '-pubkey', '-noout'], {encoding: 'utf8'});
	const newPub = execFileSync('openssl', ['x509', '-in', resignedFile, '-pubkey', '-noout'], {encoding: 'utf8'});
	assert.equal(newPub, oldPub, 'public key must be preserved on re-sign');

	// Signature algorithm now reflects the new CA (P-384 → SHA-384).
	const text = pubkeyAlg(resignedFile);
	assert.match(text, /ecdsa-with-SHA384/);
});
