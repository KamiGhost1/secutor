import {test, before, after} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

import {buildRootCa, buildLeafCert} from '../src/certs/core.js';
import {encryptPrivateKey} from '../src/certs/keys.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..');
const CLI_ENTRY = path.join(REPO_ROOT, 'src', 'cli.tsx');

let tmpRoot: string;
let secutorHome: string;

before(() => {
	tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'secutor-cli-'));
	secutorHome = path.join(tmpRoot, 'home');
	fs.mkdirSync(secutorHome, {recursive: true});
});

after(() => {
	try {
		fs.rmSync(tmpRoot, {recursive: true, force: true});
	} catch {}
});

function workDir(label: string): string {
	const d = path.join(
		tmpRoot,
		`${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
	);
	fs.mkdirSync(d, {recursive: true});
	return d;
}

type RunResult = {status: number; stdout: string; stderr: string};

function runCli(args: string[], opts?: {input?: string; home?: string}): RunResult {
	const r = spawnSync(
		process.execPath,
		['--import', 'tsx', CLI_ENTRY, ...args],
		{
			encoding: 'utf8',
			input: opts?.input,
			env: {
				...process.env,
				SECUTOR_HOME: opts?.home ?? secutorHome,
				// suppress experimental loader warnings on stderr noise
				NODE_NO_WARNINGS: '1',
			},
		},
	);
	return {
		status: r.status ?? -1,
		stdout: r.stdout ?? '',
		stderr: r.stderr ?? '',
	};
}

function writeSignerFiles(label: string, opts?: {encryptedWith?: string}): {
	dir: string;
	keyFile: string;
	certFile: string;
} {
	const d = workDir(label);
	const root = buildRootCa({
		subject: {commonName: `${label}-root`},
		validityDays: 30,
		algorithm: 'ed25519',
	});
	const leaf = buildLeafCert({
		type: 'client',
		subject: {commonName: `${label}-signer`},
		validityDays: 30,
		ca: {certPem: root.certPem, keyPem: root.keyPem},
		algorithm: 'ed25519',
	});
	const keyFile = path.join(d, 'key.pem');
	const certFile = path.join(d, 'cert.pem');
	const keyPem = opts?.encryptedWith
		? encryptPrivateKey(leaf.keyPem, opts.encryptedWith)
		: leaf.keyPem;
	fs.writeFileSync(keyFile, keyPem);
	fs.writeFileSync(certFile, leaf.certPem);
	return {dir: d, keyFile, certFile};
}

test('sign + verify round-trip with key/cert files (detached)', () => {
	const {dir, keyFile, certFile} = writeSignerFiles('detached');
	const payload = path.join(dir, 'payload.txt');
	fs.writeFileSync(payload, 'hello world');

	const sign = runCli([
		'sign',
		payload,
		'--key-file',
		keyFile,
		'--cert-file',
		certFile,
	]);
	assert.equal(sign.status, 0, sign.stderr);
	assert.ok(fs.existsSync(`${payload}.sig`), 'detached .sig must be written');

	const ver = runCli(['verify', payload]);
	assert.equal(ver.status, 0, ver.stderr);
	assert.match(ver.stdout, /OK: signature is valid/);
	assert.match(ver.stdout, /Algorithm: ed25519/);
});

test('--out overrides default detached signature path', () => {
	const {dir, keyFile, certFile} = writeSignerFiles('out');
	const payload = path.join(dir, 'a.bin');
	fs.writeFileSync(payload, Buffer.from([1, 2, 3, 4]));
	const out = path.join(dir, 'custom.sig');

	const sign = runCli([
		'sign',
		payload,
		'--key-file',
		keyFile,
		'--cert-file',
		certFile,
		'--out',
		out,
	]);
	assert.equal(sign.status, 0, sign.stderr);
	assert.ok(fs.existsSync(out));
	assert.ok(!fs.existsSync(`${payload}.sig`));

	const ver = runCli(['verify', payload, '--sig', out]);
	assert.equal(ver.status, 0, ver.stderr);
});

test('bundle mode round-trip', () => {
	const {dir, keyFile, certFile} = writeSignerFiles('bundle');
	const payload = path.join(dir, 'app.bin');
	fs.writeFileSync(payload, Buffer.from('bundled payload'));
	const bundle = path.join(dir, 'app.secsig');

	const sign = runCli([
		'sign',
		payload,
		'--key-file',
		keyFile,
		'--cert-file',
		certFile,
		'--mode',
		'bundle',
		'--out',
		bundle,
	]);
	assert.equal(sign.status, 0, sign.stderr);
	assert.ok(fs.existsSync(bundle));

	// Bundle verify needs only the bundle path; no --sig.
	const ver = runCli(['verify', bundle]);
	assert.equal(ver.status, 0, ver.stderr);
	assert.match(ver.stdout, /bundle mode/);
});

test('verify --signer-file overrides embedded cert', () => {
	const {dir, keyFile, certFile} = writeSignerFiles('signerfile');
	const payload = path.join(dir, 'p.txt');
	fs.writeFileSync(payload, 'verify-with-signer-file');

	const sign = runCli([
		'sign',
		payload,
		'--key-file',
		keyFile,
		'--cert-file',
		certFile,
	]);
	assert.equal(sign.status, 0, sign.stderr);

	const ok = runCli(['verify', payload, '--signer-file', certFile]);
	assert.equal(ok.status, 0, ok.stderr);

	// A different cert should be rejected.
	const otherFiles = writeSignerFiles('other');
	const bad = runCli(['verify', payload, '--signer-file', otherFiles.certFile]);
	assert.equal(bad.status, 1);
	assert.match(bad.stderr, /FAIL/);
});

test('verify --fingerprint pinning accepts match, rejects mismatch', () => {
	const {dir, keyFile, certFile} = writeSignerFiles('fp');
	const payload = path.join(dir, 'p.txt');
	fs.writeFileSync(payload, 'fp-test');

	runCli(['sign', payload, '--key-file', keyFile, '--cert-file', certFile]);
	const manifest = JSON.parse(fs.readFileSync(`${payload}.sig`, 'utf8'));
	const fp = manifest.signer.fingerprint as string;
	assert.ok(/^[0-9a-f]+$/.test(fp));

	const ok = runCli(['verify', payload, '--fingerprint', fp]);
	assert.equal(ok.status, 0, ok.stderr);

	const bad = runCli(['verify', payload, '--fingerprint', '00'.repeat(32)]);
	assert.equal(bad.status, 1);
	assert.match(bad.stderr, /fingerprint/i);
});

test('tampered data fails verification with exit 1', () => {
	const {dir, keyFile, certFile} = writeSignerFiles('tamper');
	const payload = path.join(dir, 'p.txt');
	fs.writeFileSync(payload, 'original');

	const sign = runCli(['sign', payload, '--key-file', keyFile, '--cert-file', certFile]);
	assert.equal(sign.status, 0, sign.stderr);

	fs.writeFileSync(payload, 'changed');
	const ver = runCli(['verify', payload]);
	assert.equal(ver.status, 1);
	assert.match(ver.stderr, /digest|signature|match/i);
});

test('encrypted key requires the right password (via flag)', () => {
	const {dir, keyFile, certFile} = writeSignerFiles('enc', {encryptedWith: 'topsecret'});
	const payload = path.join(dir, 'p.txt');
	fs.writeFileSync(payload, 'encrypted-key-flag');

	const ok = runCli([
		'sign',
		payload,
		'--key-file',
		keyFile,
		'--cert-file',
		certFile,
		'--key-password',
		'topsecret',
	]);
	assert.equal(ok.status, 0, ok.stderr);

	fs.unlinkSync(`${payload}.sig`);
	const bad = runCli([
		'sign',
		payload,
		'--key-file',
		keyFile,
		'--cert-file',
		certFile,
		'--key-password',
		'WRONG',
	]);
	assert.equal(bad.status, 2);
	assert.match(bad.stderr, /password|decrypt/i);
});

test('encrypted key password can be read from stdin', () => {
	const {dir, keyFile, certFile} = writeSignerFiles('enc-stdin', {encryptedWith: 'pw1'});
	const payload = path.join(dir, 'p.txt');
	fs.writeFileSync(payload, 'stdin-pw');

	const ok = runCli(
		[
			'sign',
			payload,
			'--key-file',
			keyFile,
			'--cert-file',
			certFile,
			'--key-password-stdin',
		],
		{input: 'pw1\n'},
	);
	assert.equal(ok.status, 0, ok.stderr);

	const ver = runCli(['verify', payload]);
	assert.equal(ver.status, 0, ver.stderr);
});

test('usage errors return exit code 2', () => {
	const missingFile = runCli(['sign']);
	assert.equal(missingFile.status, 2);
	assert.match(missingFile.stderr, /Missing <file>/);

	const noSource = runCli(['sign', '/dev/null']);
	assert.equal(noSource.status, 2);
	assert.match(noSource.stderr, /signer source/i);

	const bothSources = runCli([
		'sign',
		'/dev/null',
		'--key-file',
		'/dev/null',
		'--context',
		'demo',
		'--cert',
		'x',
	]);
	assert.equal(bothSources.status, 2);
	assert.match(bothSources.stderr, /one signer source/i);
});

test('help is printed and exits 0', () => {
	const sh = runCli(['sign', '--help']);
	assert.equal(sh.status, 0);
	assert.match(sh.stdout, /Usage:\s+secutor sign/);

	const vh = runCli(['verify', '--help']);
	assert.equal(vh.status, 0);
	assert.match(vh.stdout, /Usage:\s+secutor verify/);
});

// ----------------------------- context tests -----------------------------

function bootstrapContext(name: string, password: string | null): string {
	// Bootstrap runs in a child process so the storage modules (which capture
	// SECUTOR_HOME at import time) get a fresh module graph per context.
	const home = path.join(tmpRoot, `home-${name}`);
	fs.mkdirSync(path.join(home, 'contexts'), {recursive: true});

	const script = `
		import {ensureRoot} from '${REPO_ROOT}/src/storage/paths.js';
		import {createContext} from '${REPO_ROOT}/src/storage/contextStore.js';
		import {openContext, closeContext} from '${REPO_ROOT}/src/storage/db.js';
		import {createCA} from '${REPO_ROOT}/src/certs/generator.js';
		const pw = ${JSON.stringify(password)};
		ensureRoot();
		createContext({name: ${JSON.stringify(name)}, password: pw ?? undefined});
		openContext(${JSON.stringify(name)}, pw);
		createCA({
			name: 'mycert',
			commonName: 'ctx-signer',
			organization: null,
			validityDays: 30,
			keyAlgorithm: 'ed25519',
			keyPassword: null,
		});
		closeContext();
	`;
	const r = spawnSync(
		process.execPath,
		['--import', 'tsx', '--input-type=module', '-e', script],
		{
			encoding: 'utf8',
			env: {
				...process.env,
				SECUTOR_HOME: home,
				NODE_NO_WARNINGS: '1',
			},
		},
	);
	if (r.status !== 0) {
		throw new Error(`Context bootstrap failed: ${r.stderr || r.stdout}`);
	}
	return home;
}

test('sign + verify via encrypted context (password as flag)', () => {
	const home = bootstrapContext('demo', 'ctxpw');
	const d = workDir('ctx-flag');
	const payload = path.join(d, 'p.txt');
	fs.writeFileSync(payload, 'context-signed');

	const sign = runCli(
		[
			'sign',
			payload,
			'--context',
			'demo',
			'--cert',
			'mycert',
			'--context-password',
			'ctxpw',
		],
		{home},
	);
	assert.equal(sign.status, 0, sign.stderr);
	assert.ok(fs.existsSync(`${payload}.sig`));

	const ver = runCli(
		[
			'verify',
			payload,
			'--context',
			'demo',
			'--cert',
			'mycert',
			'--context-password',
			'ctxpw',
		],
		{home},
	);
	assert.equal(ver.status, 0, ver.stderr);
	assert.match(ver.stdout, /Signer CN: ctx-signer/);
});

test('sign via context: password via stdin', () => {
	const home = bootstrapContext('demo2', 'ctxpw2');
	const d = workDir('ctx-stdin');
	const payload = path.join(d, 'p.txt');
	fs.writeFileSync(payload, 'context-stdin');

	const sign = runCli(
		[
			'sign',
			payload,
			'--context',
			'demo2',
			'--cert',
			'mycert',
			'--context-password-stdin',
		],
		{home, input: 'ctxpw2\n'},
	);
	assert.equal(sign.status, 0, sign.stderr);

	const ver = runCli(['verify', payload], {home});
	assert.equal(ver.status, 0, ver.stderr);
});

test('verify via context with wrong password exits 2', () => {
	const home = bootstrapContext('demo3', 'rightpw');
	const d = workDir('ctx-wrong');
	const payload = path.join(d, 'p.txt');
	fs.writeFileSync(payload, 'wrong-pw');

	const sign = runCli(
		[
			'sign',
			payload,
			'--context',
			'demo3',
			'--cert',
			'mycert',
			'--context-password',
			'rightpw',
		],
		{home},
	);
	assert.equal(sign.status, 0, sign.stderr);

	const ver = runCli(
		[
			'verify',
			payload,
			'--context',
			'demo3',
			'--cert',
			'mycert',
			'--context-password',
			'WRONG',
		],
		{home},
	);
	assert.equal(ver.status, 2);
	assert.match(ver.stderr, /Incorrect password/i);
});

test('verify via context: missing cert name produces usage error', () => {
	const home = bootstrapContext('demo4', null);
	const d = workDir('ctx-missing');
	const payload = path.join(d, 'p.txt');
	fs.writeFileSync(payload, 'missing-cert');

	const sign = runCli(
		['sign', payload, '--context', 'demo4', '--cert', 'mycert'],
		{home},
	);
	assert.equal(sign.status, 0, sign.stderr);

	const ver = runCli(
		['verify', payload, '--context', 'demo4', '--cert', 'no-such-cert'],
		{home},
	);
	assert.equal(ver.status, 2);
	assert.match(ver.stderr, /not found/i);
});
