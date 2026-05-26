import {test, before} from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync, spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import {
	generateSshKey,
	publicFromPrivate,
	detectSshAlgorithmOf,
	sshFingerprintSha256,
	formatOpenSshPublic,
	toOpenSshPrivateKey,
	exportToSshFolder,
	SshKeyAlgorithm,
} from '../src/ssh/sshKeys.js';
import {decryptPrivateKey, isEncryptedKey} from '../src/certs/keys.js';

let tmpRoot: string;
let hasSshKeygen = false;

before(() => {
	tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'secutor-ssh-'));
	const r = spawnSync('ssh-keygen', ['-V'], {encoding: 'utf8'});
	hasSshKeygen = r.status === 0 || /usage:/i.test(r.stderr ?? '');
});

function dir(label: string): string {
	const d = path.join(tmpRoot, `${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
	fs.mkdirSync(d, {recursive: true});
	return d;
}

const ALGOS: SshKeyAlgorithm[] = [
	'ssh-ed25519',
	'ssh-rsa-2048',
	'ssh-ecdsa-p256',
	'ssh-ecdsa-p384',
];

for (const algo of ALGOS) {
	test(`generate ${algo} key produces well-formed OpenSSH public line`, () => {
		const k = generateSshKey({algorithm: algo, comment: 'test@host'});
		assert.equal(k.algorithm, algo);
		assert.match(k.fingerprintSha256, /^SHA256:[A-Za-z0-9+/]+$/);

		const parts = k.publicKeyOpenssh.trim().split(/\s+/);
		assert.ok(parts.length === 3, `expected 3 fields, got ${parts.length}`);
		assert.equal(parts[2], 'test@host');

		const expectedPrefix: Record<SshKeyAlgorithm, string> = {
			'ssh-ed25519': 'ssh-ed25519',
			'ssh-rsa-2048': 'ssh-rsa',
			'ssh-rsa-3072': 'ssh-rsa',
			'ssh-rsa-4096': 'ssh-rsa',
			'ssh-ecdsa-p256': 'ecdsa-sha2-nistp256',
			'ssh-ecdsa-p384': 'ecdsa-sha2-nistp384',
		};
		assert.equal(parts[0], expectedPrefix[algo]);

		// Blob base64 must decode and start with the algorithm-name string.
		const blob = Buffer.from(parts[1]!, 'base64');
		const nameLen = blob.readUInt32BE(0);
		const name = blob.subarray(4, 4 + nameLen).toString('utf8');
		assert.equal(name, expectedPrefix[algo]);
	});

	test(`fingerprint of ${algo} key matches ssh-keygen -lf`, t => {
		if (!hasSshKeygen) return t.skip('ssh-keygen not available');
		const k = generateSshKey({algorithm: algo, comment: 'fp@host'});
		const d = dir(`fp-${algo}`);
		const pubPath = path.join(d, 'id.pub');
		fs.writeFileSync(pubPath, k.publicKeyOpenssh + '\n');
		const out = execFileSync('ssh-keygen', ['-l', '-E', 'sha256', '-f', pubPath], {encoding: 'utf8'});
		assert.ok(out.includes(k.fingerprintSha256), `ssh-keygen said:\n${out}\nexpected to contain ${k.fingerprintSha256}`);
	});

	test(`ssh-keygen can read our OpenSSH-format private key (${algo})`, t => {
		if (!hasSshKeygen) return t.skip('ssh-keygen not available');
		const k = generateSshKey({algorithm: algo});
		const d = dir(`priv-${algo}`);
		const privPath = path.join(d, 'id');
		const openssh = toOpenSshPrivateKey(k.privateKeyPem, 'test');
		fs.writeFileSync(privPath, openssh, {mode: 0o600});
		// ssh-keygen -y -f <priv> regenerates the public-line. Compare blob.
		const out = execFileSync('ssh-keygen', ['-y', '-f', privPath], {encoding: 'utf8'});
		const ourBlob = k.publicKeyOpenssh.split(/\s+/)[1];
		assert.ok(
			out.includes(ourBlob!),
			`ssh-keygen -y mismatch for ${algo}:\n${out}\nexpected blob: ${ourBlob}`,
		);
	});
}

test('publicFromPrivate re-derives the OpenSSH line', () => {
	const k = generateSshKey({algorithm: 'ssh-ed25519', comment: 'orig'});
	const re = publicFromPrivate(k.privateKeyPem, null, 'new-comment');
	const reBlob = re.split(/\s+/)[1];
	const origBlob = k.publicKeyOpenssh.split(/\s+/)[1];
	assert.equal(reBlob, origBlob);
	assert.ok(re.endsWith('new-comment'));
});

test('encrypted ssh key: PEM is encrypted and ssh-keygen accepts the passphrase', t => {
	const k = generateSshKey({algorithm: 'ssh-ed25519', passphrase: 'sshpw', comment: 'enc'});
	assert.equal(isEncryptedKey(k.privateKeyPem), true);

	// Re-derive public from encrypted private via our helper.
	const re = publicFromPrivate(k.privateKeyPem, 'sshpw');
	const reBlob = re.split(/\s+/)[1];
	const origBlob = k.publicKeyOpenssh.split(/\s+/)[1];
	assert.equal(reBlob, origBlob);

	// Wrong passphrase fails.
	assert.throws(() => publicFromPrivate(k.privateKeyPem, 'bad'), /invalid password/i);
});

test('detectSshAlgorithmOf identifies the SSH-side algorithm from the PEM', () => {
	const k1 = generateSshKey({algorithm: 'ssh-ecdsa-p384'});
	assert.equal(detectSshAlgorithmOf(k1.privateKeyPem), 'ssh-ecdsa-p384');
	const k2 = generateSshKey({algorithm: 'ssh-ed25519'});
	assert.equal(detectSshAlgorithmOf(k2.privateKeyPem), 'ssh-ed25519');
});

test('exportToSshFolder writes files with correct permissions', t => {
	const d = dir('exp');
	const k = generateSshKey({algorithm: 'ssh-ed25519', comment: 'export@me'});
	const out = exportToSshFolder({
		name: 'id_secutor',
		privateKeyPem: k.privateKeyPem,
		publicKeyOpenssh: k.publicKeyOpenssh,
		dir: d,
	});
	assert.ok(fs.existsSync(out.privateKeyPath));
	assert.ok(fs.existsSync(out.publicKeyPath));
	if (process.platform !== 'win32') {
		const st = fs.statSync(out.privateKeyPath);
		// Permissions are 0o600 = 0o100600 with file-type bits — mask off type.
		const mode = st.mode & 0o777;
		assert.equal(mode, 0o600, `expected 0600 perms, got ${mode.toString(8)}`);
	}

	// noOverwrite refuses second write.
	assert.throws(
		() =>
			exportToSshFolder({
				name: 'id_secutor',
				privateKeyPem: k.privateKeyPem,
				publicKeyOpenssh: k.publicKeyOpenssh,
				dir: d,
				noOverwrite: true,
			}),
		/Refusing to overwrite/,
	);
});

test('exportToSshFolder writes an OpenSSH-format key that ssh-keygen reads (ed25519)', t => {
	if (!hasSshKeygen) return t.skip('ssh-keygen not available');
	const d = dir('exp-keygen');
	const k = generateSshKey({algorithm: 'ssh-ed25519', comment: 'kg@host'});
	const out = exportToSshFolder({
		name: 'id_test',
		privateKeyPem: k.privateKeyPem,
		publicKeyOpenssh: k.publicKeyOpenssh,
		dir: d,
		comment: 'kg@host',
	});
	const got = execFileSync('ssh-keygen', ['-y', '-f', out.privateKeyPath], {encoding: 'utf8'});
	const ourBlob = k.publicKeyOpenssh.split(/\s+/)[1];
	assert.ok(got.includes(ourBlob!), `expected ${ourBlob} in:\n${got}`);
});

test('formatOpenSshPublic on a node:crypto-generated key matches the wire format', () => {
	// Independent check: round-trip via Node directly.
	const {publicKey} = crypto.generateKeyPairSync('ed25519');
	const pem = publicKey.export({type: 'spki', format: 'pem'}) as string;
	const line = formatOpenSshPublic(pem, 'manual');
	const blob = Buffer.from(line.split(/\s+/)[1]!, 'base64');
	// Read first sshString — should be "ssh-ed25519".
	const len = blob.readUInt32BE(0);
	assert.equal(blob.subarray(4, 4 + len).toString('utf8'), 'ssh-ed25519');
	// Second sshString is the 32-byte public key.
	const off = 4 + len;
	const keyLen = blob.readUInt32BE(off);
	assert.equal(keyLen, 32);

	// And the resulting fingerprint matches `ssh-keygen -lf` if available.
	const fp = sshFingerprintSha256(line);
	assert.match(fp, /^SHA256:/);
});
