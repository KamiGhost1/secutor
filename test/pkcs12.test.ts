import {test, before} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync, spawnSync} from 'node:child_process';

import {buildRootCa, buildLeafCert, buildIntermediateCa} from '../src/certs/core.js';
import {buildP12, parseP12} from '../src/certs/p12.js';
import {KeyAlgorithm} from '../src/certs/keys.js';

let tmpRoot: string;
let opensslVersion = '';

before(() => {
	const probe = spawnSync('openssl', ['version'], {encoding: 'utf8'});
	if (probe.status !== 0) {
		throw new Error('openssl is required on PATH for PKCS#12 interop tests');
	}
	opensslVersion = (probe.stdout || '').trim();
	tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'secutor-p12-'));
});

function dir(label: string): string {
	const d = path.join(tmpRoot, `${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
	fs.mkdirSync(d, {recursive: true});
	return d;
}

function opensslReadsP12(blob: Buffer, password: string): {ok: boolean; output: string} {
	const d = dir('openssl');
	const p = path.join(d, 'test.p12');
	fs.writeFileSync(p, blob);
	const args = ['pkcs12', '-info', '-noout', '-in', p, '-passin', `pass:${password}`];
	const r = spawnSync('openssl', args, {encoding: 'utf8'});
	return {ok: r.status === 0, output: (r.stdout || '') + (r.stderr || '')};
}

const ALGOS: KeyAlgorithm[] = ['rsa-2048', 'ecdsa-p256', 'ecdsa-p384', 'ed25519'];

for (const algo of ALGOS) {
	test(`P12 round-trip (${algo})`, async () => {
		const root = buildRootCa({
			subject: {commonName: `p12-${algo}`},
			validityDays: 30,
			algorithm: algo,
		});
		const leaf = buildLeafCert({
			type: 'server',
			subject: {commonName: `leaf-${algo}.svc`},
			validityDays: 30,
			ca: {certPem: root.certPem, keyPem: root.keyPem},
			algorithm: algo,
		});
		const blob = await buildP12({
			leafCertPem: leaf.certPem,
			leafPrivateKeyPem: leaf.keyPem,
			chainCertPems: [root.certPem],
			password: 'pw',
			friendlyName: `friendly-${algo}`,
		});
		const parsed = await parseP12(blob, 'pw');
		assert.equal(parsed.certPems.length, 2, `expected 2 certs for ${algo}`);
		assert.ok(parsed.privateKeyPem, `expected private key for ${algo}`);
		assert.match(parsed.certPems[0]!, /-----BEGIN CERTIFICATE-----/);
		assert.match(parsed.privateKeyPem!, /-----BEGIN PRIVATE KEY-----/);
	});

	test(`P12 wrong password fails (${algo})`, async () => {
		const root = buildRootCa({
			subject: {commonName: `wrong-${algo}`},
			validityDays: 30,
			algorithm: algo,
		});
		const leaf = buildLeafCert({
			type: 'client',
			subject: {commonName: `client-${algo}`},
			validityDays: 30,
			ca: {certPem: root.certPem, keyPem: root.keyPem},
			algorithm: algo,
		});
		const blob = await buildP12({
			leafCertPem: leaf.certPem,
			leafPrivateKeyPem: leaf.keyPem,
			chainCertPems: [root.certPem],
			password: 'right',
		});
		await assert.rejects(parseP12(blob, 'wrong'), /integrity|wrong password|MAC/i);
	});
}

test('P12 contains the full chain (root → intermediate → leaf)', async () => {
	const root = buildRootCa({
		subject: {commonName: 'chain-root'},
		validityDays: 365,
		algorithm: 'ecdsa-p256',
	});
	const inter = buildIntermediateCa({
		subject: {commonName: 'chain-int'},
		validityDays: 90,
		ca: {certPem: root.certPem, keyPem: root.keyPem},
		algorithm: 'ecdsa-p256',
	});
	const leaf = buildLeafCert({
		type: 'server',
		subject: {commonName: 'chain.leaf'},
		validityDays: 30,
		ca: {certPem: inter.certPem, keyPem: inter.keyPem},
		algorithm: 'ecdsa-p256',
	});
	const blob = await buildP12({
		leafCertPem: leaf.certPem,
		leafPrivateKeyPem: leaf.keyPem,
		chainCertPems: [inter.certPem, root.certPem],
		password: 'pw',
	});
	const parsed = await parseP12(blob, 'pw');
	assert.equal(parsed.certPems.length, 3);
});

test('openssl can read our PKCS#12 (RSA leaf)', async () => {
	const root = buildRootCa({subject: {commonName: 'oss-rsa'}, validityDays: 30});
	const leaf = buildLeafCert({
		type: 'server',
		subject: {commonName: 'rsa-svc.test'},
		validityDays: 30,
		ca: {certPem: root.certPem, keyPem: root.keyPem},
	});
	const blob = await buildP12({
		leafCertPem: leaf.certPem,
		leafPrivateKeyPem: leaf.keyPem,
		chainCertPems: [root.certPem],
		password: 'pw',
		friendlyName: 'rsa-friendly',
	});
	const r = opensslReadsP12(blob, 'pw');
	assert.equal(r.ok, true, `openssl failed (${opensslVersion}):\n${r.output}`);
});

test('openssl can read our PKCS#12 (ECDSA leaf)', async () => {
	const root = buildRootCa({subject: {commonName: 'oss-ec'}, validityDays: 30, algorithm: 'ecdsa-p256'});
	const leaf = buildLeafCert({
		type: 'server',
		subject: {commonName: 'ec-svc.test'},
		validityDays: 30,
		ca: {certPem: root.certPem, keyPem: root.keyPem},
		algorithm: 'ecdsa-p256',
	});
	const blob = await buildP12({
		leafCertPem: leaf.certPem,
		leafPrivateKeyPem: leaf.keyPem,
		chainCertPems: [root.certPem],
		password: 'pw',
	});
	const r = opensslReadsP12(blob, 'pw');
	assert.equal(r.ok, true, `openssl failed:\n${r.output}`);
});

test('openssl can read our PKCS#12 (Ed25519 leaf)', async () => {
	const root = buildRootCa({subject: {commonName: 'oss-ed'}, validityDays: 30, algorithm: 'ed25519'});
	const leaf = buildLeafCert({
		type: 'client',
		subject: {commonName: 'ed-client'},
		validityDays: 30,
		ca: {certPem: root.certPem, keyPem: root.keyPem},
		algorithm: 'ed25519',
	});
	const blob = await buildP12({
		leafCertPem: leaf.certPem,
		leafPrivateKeyPem: leaf.keyPem,
		chainCertPems: [root.certPem],
		password: 'pw',
	});
	const r = opensslReadsP12(blob, 'pw');
	assert.equal(r.ok, true, `openssl failed:\n${r.output}`);
});

test('we can read back an openssl-generated PKCS#12 (RSA)', async () => {
	const d = dir('osssrc');
	const keyPath = path.join(d, 'k.pem');
	const certPath = path.join(d, 'c.pem');
	const p12Path = path.join(d, 'src.p12');
	execFileSync('openssl', ['genrsa', '-out', keyPath, '2048']);
	execFileSync('openssl', [
		'req', '-new', '-x509', '-key', keyPath, '-out', certPath,
		'-days', '30', '-subj', '/CN=osstest',
	]);
	execFileSync('openssl', [
		'pkcs12', '-export',
		'-inkey', keyPath, '-in', certPath,
		'-out', p12Path, '-passout', 'pass:srcpw',
		'-name', 'osstest',
	]);

	const buf = fs.readFileSync(p12Path);
	const parsed = await parseP12(buf, 'srcpw');
	assert.ok(parsed.privateKeyPem, 'expected key from openssl P12');
	assert.ok(parsed.certPems.length >= 1, 'expected at least one cert from openssl P12');
});
