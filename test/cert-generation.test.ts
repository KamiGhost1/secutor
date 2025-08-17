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

let tmpRoot: string;

before(() => {
	const probe = spawnSync('openssl', ['version'], {encoding: 'utf8'});
	if (probe.status !== 0) {
		throw new Error(
			'openssl is required on PATH to run cert-generation tests. ' +
				`spawn result: ${probe.error?.message ?? probe.stderr}`,
		);
	}
	tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'secutor-test-'));
});

function tmpDir(label: string): string {
	const d = path.join(tmpRoot, `${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
	fs.mkdirSync(d, {recursive: true});
	return d;
}

function write(file: string, data: string): string {
	fs.writeFileSync(file, data);
	return file;
}

function opensslVerify(args: string[]): {ok: boolean; output: string} {
	const r = spawnSync('openssl', ['verify', ...args], {encoding: 'utf8'});
	return {
		ok: r.status === 0,
		output: (r.stdout || '') + (r.stderr || ''),
	};
}

function opensslText(certPath: string): string {
	return execFileSync('openssl', ['x509', '-in', certPath, '-noout', '-text'], {
		encoding: 'utf8',
	});
}

test('root CA self-verifies via openssl', () => {
	const dir = tmpDir('root');
	const root = buildRootCa({
		subject: {commonName: 'test-root', organizationName: 'Secutor Tests'},
		validityDays: 365,
	});
	const rootFile = write(path.join(dir, 'root.pem'), root.certPem);

	const r = opensslVerify(['-CAfile', rootFile, rootFile]);
	assert.equal(r.ok, true, `openssl verify failed:\n${r.output}`);
});

test('leaf signed directly by root verifies via openssl', () => {
	const dir = tmpDir('direct');
	const root = buildRootCa({
		subject: {commonName: 'test-root', organizationName: 'Secutor Tests'},
		validityDays: 365,
	});
	const leaf = buildLeafCert({
		type: 'server',
		subject: {commonName: 'example.test'},
		validityDays: 90,
		sans: ['example.test', 'www.example.test'],
		ca: {certPem: root.certPem, keyPem: root.keyPem},
	});

	const rootFile = write(path.join(dir, 'root.pem'), root.certPem);
	const leafFile = write(path.join(dir, 'leaf.crt'), leaf.certPem);

	const r = opensslVerify(['-CAfile', rootFile, leafFile]);
	assert.equal(r.ok, true, `openssl verify failed:\n${r.output}`);
});

test('leaf signed by intermediate CA verifies (regression for AKI bug)', () => {
	const dir = tmpDir('intermediate');
	const root = buildRootCa({
		subject: {commonName: 'test-root', organizationName: 'Secutor Tests'},
		validityDays: 730,
	});
	const inter = buildIntermediateCa({
		subject: {commonName: 'test-int', organizationName: 'Secutor Tests'},
		validityDays: 365,
		ca: {certPem: root.certPem, keyPem: root.keyPem},
	});
	const leaf = buildLeafCert({
		type: 'server',
		subject: {commonName: 'service.test'},
		validityDays: 90,
		ca: {certPem: inter.certPem, keyPem: inter.keyPem},
	});

	const rootFile = write(path.join(dir, 'root.pem'), root.certPem);
	const interFile = write(path.join(dir, 'int.pem'), inter.certPem);
	const leafFile = write(path.join(dir, 'leaf.crt'), leaf.certPem);
	const chainFile = write(path.join(dir, 'chain.pem'), inter.certPem + root.certPem);

	const viaUntrusted = opensslVerify([
		'-CAfile',
		rootFile,
		'-untrusted',
		interFile,
		leafFile,
	]);
	assert.equal(viaUntrusted.ok, true, `verify -untrusted failed:\n${viaUntrusted.output}`);

	const viaCAfileChain = opensslVerify(['-CAfile', chainFile, leafFile]);
	assert.equal(
		viaCAfileChain.ok,
		true,
		`verify with chain as -CAfile failed:\n${viaCAfileChain.output}`,
	);
});

test('client certificate verifies and reports clientAuth EKU', () => {
	const dir = tmpDir('client');
	const root = buildRootCa({
		subject: {commonName: 'test-root'},
		validityDays: 365,
	});
	const leaf = buildLeafCert({
		type: 'client',
		subject: {commonName: 'alice@example.test'},
		validityDays: 90,
		ca: {certPem: root.certPem, keyPem: root.keyPem},
	});
	const rootFile = write(path.join(dir, 'root.pem'), root.certPem);
	const leafFile = write(path.join(dir, 'client.crt'), leaf.certPem);

	const r = opensslVerify(['-purpose', 'sslclient', '-CAfile', rootFile, leafFile]);
	assert.equal(r.ok, true, `openssl verify (sslclient) failed:\n${r.output}`);

	const text = opensslText(leafFile);
	assert.ok(
		text.includes('TLS Web Client Authentication'),
		`expected client EKU in cert text:\n${text}`,
	);
	assert.ok(
		!text.includes('TLS Web Server Authentication'),
		`unexpected server EKU in client cert:\n${text}`,
	);
});

test('server SANs are present in issued certificate', () => {
	const dir = tmpDir('sans');
	const root = buildRootCa({
		subject: {commonName: 'test-root'},
		validityDays: 365,
	});
	const leaf = buildLeafCert({
		type: 'server',
		subject: {commonName: 'primary.test'},
		validityDays: 90,
		sans: ['alt-1.test', '10.0.0.5'],
		ca: {certPem: root.certPem, keyPem: root.keyPem},
	});
	const leafFile = write(path.join(dir, 'leaf.crt'), leaf.certPem);
	const text = opensslText(leafFile);

	assert.ok(text.includes('DNS:primary.test'), `missing DNS:primary.test:\n${text}`);
	assert.ok(text.includes('DNS:alt-1.test'), `missing DNS:alt-1.test:\n${text}`);
	assert.ok(text.includes('IP Address:10.0.0.5'), `missing IP SAN:\n${text}`);
});

test('serial number is encoded as a positive integer', () => {
	const dir = tmpDir('serial');
	for (let i = 0; i < 8; i++) {
		const root = buildRootCa({
			subject: {commonName: `test-root-${i}`},
			validityDays: 30,
		});
		const file = write(path.join(dir, `root-${i}.pem`), root.certPem);
		const out = execFileSync('openssl', ['asn1parse', '-in', file], {encoding: 'utf8'});
		const serialLine = out.split('\n').find(l => /INTEGER\s*:/.test(l) && !/:02$/.test(l));
		assert.ok(serialLine, `could not locate serial line in:\n${out}`);
		assert.ok(
			!serialLine!.includes(':-'),
			`serial encoded as negative integer: ${serialLine}`,
		);
	}
});

test('renew (re-sign with same CA + new validity) extends notAfter and verifies', () => {
	const dir = tmpDir('renew-leaf');
	const ca = buildRootCa({
		subject: {commonName: 'renew-root'},
		validityDays: 365,
	});
	const leaf = buildLeafCert({
		type: 'server',
		subject: {commonName: 'renew.svc'},
		validityDays: 1,
		sans: ['renew.svc', 'alt.renew.svc'],
		ca: {certPem: ca.certPem, keyPem: ca.keyPem},
	});
	const renewed = resignCertificateCore({
		oldCertPem: leaf.certPem,
		ca: {certPem: ca.certPem, keyPem: ca.keyPem},
		validityDays: 730,
	});

	const caFile = write(path.join(dir, 'ca.pem'), ca.certPem);
	const renewedFile = write(path.join(dir, 'renewed.crt'), renewed.certPem);

	const r = opensslVerify(['-CAfile', caFile, renewedFile]);
	assert.equal(r.ok, true, `renewed cert did not verify:\n${r.output}`);

	assert.ok(renewed.notAfter.getTime() > leaf.notAfter.getTime(), 'notAfter must advance');
	const target = new Date(renewed.notBefore.getTime() + 730 * 86400_000);
	assert.ok(
		Math.abs(renewed.notAfter.getTime() - target.getTime()) < 5 * 1000,
		`expected ~730d window, got ${(renewed.notAfter.getTime() - renewed.notBefore.getTime()) / 86400_000}d`,
	);

	const text = opensslText(renewedFile);
	assert.ok(text.includes('CN = renew.svc') || text.includes('CN=renew.svc'));
	assert.ok(text.includes('DNS:renew.svc'));
	assert.ok(text.includes('DNS:alt.renew.svc'));
});

test('self-renew of a root CA preserves the public key', () => {
	const dir = tmpDir('renew-root');
	const ca = buildRootCa({
		subject: {commonName: 'renewable-root'},
		validityDays: 30,
	});
	const renewed = resignCertificateCore({
		oldCertPem: ca.certPem,
		ca: {certPem: ca.certPem, keyPem: ca.keyPem},
		validityDays: 3650,
	});

	const oldFile = write(path.join(dir, 'old.pem'), ca.certPem);
	const newFile = write(path.join(dir, 'new.pem'), renewed.certPem);

	const verifyAsRoot = opensslVerify(['-CAfile', newFile, newFile]);
	assert.equal(verifyAsRoot.ok, true, `self-renewed root failed self-verify:\n${verifyAsRoot.output}`);

	assert.ok(renewed.notAfter.getTime() > ca.notAfter.getTime(), 'notAfter must advance');

	const oldPub = execFileSync('openssl', ['x509', '-in', oldFile, '-pubkey', '-noout'], {encoding: 'utf8'});
	const newPub = execFileSync('openssl', ['x509', '-in', newFile, '-pubkey', '-noout'], {encoding: 'utf8'});
	assert.equal(newPub, oldPub, 'public key must be preserved on self-renew');

	assert.notEqual(renewed.serial, ca.serial, 'serial must change on renew');
});

test('re-signed leaf chains to the new CA', () => {
	const dir = tmpDir('resign');
	const oldCa = buildRootCa({
		subject: {commonName: 'old-root'},
		validityDays: 365,
	});
	const newCa = buildRootCa({
		subject: {commonName: 'new-root'},
		validityDays: 365,
	});
	const leaf = buildLeafCert({
		type: 'server',
		subject: {commonName: 'svc.test'},
		validityDays: 30,
		ca: {certPem: oldCa.certPem, keyPem: oldCa.keyPem},
	});
	const resigned = resignCertificateCore({
		oldCertPem: leaf.certPem,
		ca: {certPem: newCa.certPem, keyPem: newCa.keyPem},
	});

	const newRootFile = write(path.join(dir, 'new-root.pem'), newCa.certPem);
	const resignedFile = write(path.join(dir, 'resigned.crt'), resigned.certPem);

	const ok = opensslVerify(['-CAfile', newRootFile, resignedFile]);
	assert.equal(ok.ok, true, `re-signed cert did not verify:\n${ok.output}`);

	const oldRootFile = write(path.join(dir, 'old-root.pem'), oldCa.certPem);
	const reject = opensslVerify(['-CAfile', oldRootFile, resignedFile]);
	assert.equal(
		reject.ok,
		false,
		`re-signed cert unexpectedly verified against the old CA:\n${reject.output}`,
	);
});
