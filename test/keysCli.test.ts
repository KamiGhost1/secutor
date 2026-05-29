// End-to-end CLI smoke for `secutor keys` — runs the CLI as a child process
// with an isolated SECUTOR_HOME so it bootstraps + uses real contexts.

import {test, before} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const REPO_ROOT = path.resolve(
	path.dirname(fileURLToPath(import.meta.url)),
	'..',
);

let tmpRoot: string;

before(() => {
	tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'secutor-keys-cli-'));
});

function runCli(args: string[], home: string, stdin?: string) {
	const r = spawnSync(
		process.execPath,
		['--import', 'tsx', path.join(REPO_ROOT, 'src', 'cli.tsx'), ...args],
		{
			encoding: 'utf8',
			input: stdin,
			env: {
				...process.env,
				SECUTOR_HOME: home,
				NODE_NO_WARNINGS: '1',
			},
		},
	);
	return {status: r.status, stdout: r.stdout, stderr: r.stderr};
}

function bootstrapWithCa(homeLabel: string, ctxName: string): string {
	const home = path.join(tmpRoot, `home-${homeLabel}`);
	fs.mkdirSync(path.join(home, 'contexts'), {recursive: true});
	const script = `
		import {ensureRoot} from '${REPO_ROOT}/src/storage/paths.js';
		import {createContext} from '${REPO_ROOT}/src/storage/contextStore.js';
		import {openContext, closeContext} from '${REPO_ROOT}/src/storage/db.js';
		import {createCA, issueCert} from '${REPO_ROOT}/src/certs/generator.js';
		ensureRoot();
		createContext({name: ${JSON.stringify(ctxName)}});
		openContext(${JSON.stringify(ctxName)}, null);
		const caId = createCA({
			name: 'rootca',
			commonName: 'cli-root',
			validityDays: 365,
			algorithm: 'ecdsa-p256',
		});
		issueCert('server', {
			name: 'leaf',
			caId,
			commonName: 'svc.cli',
			validityDays: 90,
			sans: ['svc.cli'],
			algorithm: 'ed25519',
		});
		closeContext();
	`;
	const r = spawnSync(
		process.execPath,
		['--import', 'tsx', '--input-type=module', '-e', script],
		{
			encoding: 'utf8',
			env: {...process.env, SECUTOR_HOME: home, NODE_NO_WARNINGS: '1'},
		},
	);
	if (r.status !== 0) throw new Error(`bootstrap failed: ${r.stderr || r.stdout}`);
	return home;
}

function makeEmptyHome(label: string, ctxName: string): string {
	const home = path.join(tmpRoot, `home-${label}`);
	fs.mkdirSync(path.join(home, 'contexts'), {recursive: true});
	const r = spawnSync(
		process.execPath,
		[
			'--import',
			'tsx',
			'--input-type=module',
			'-e',
			`
				import {ensureRoot} from '${REPO_ROOT}/src/storage/paths.js';
				import {createContext} from '${REPO_ROOT}/src/storage/contextStore.js';
				ensureRoot();
				createContext({name: ${JSON.stringify(ctxName)}});
			`,
		],
		{
			encoding: 'utf8',
			env: {...process.env, SECUTOR_HOME: home, NODE_NO_WARNINGS: '1'},
		},
	);
	if (r.status !== 0) throw new Error(`mkhome failed: ${r.stderr || r.stdout}`);
	return home;
}

test('keys --help prints usage and exits 0', () => {
	const r = runCli(['keys', '--help'], path.join(tmpRoot, 'home-help'));
	assert.equal(r.status, 0);
	assert.match(r.stdout, /Usage:\s+secutor keys export/);
});

test('keys export → keys import round-trip across homes (plain)', () => {
	const homeA = bootstrapWithCa('a-plain', 'src');
	const homeB = makeEmptyHome('b-plain', 'dst');
	const out = path.join(tmpRoot, 'leaf.skb');

	const exp = runCli(
		['keys', 'export', 'leaf', '--context', 'src', '--out', out, '--include-parents'],
		homeA,
	);
	assert.equal(exp.status, 0, exp.stderr || exp.stdout);
	assert.match(exp.stdout, /wrote cert bundle "leaf"/);
	assert.ok(fs.existsSync(out));

	const imp = runCli(['keys', 'import', out, '--context', 'dst'], homeB);
	assert.equal(imp.status, 0, imp.stderr || imp.stdout);
	assert.match(imp.stdout, /inserted cert "leaf"/);
	// Parent CA also bundled, so two inserts total.
	assert.match(imp.stdout, /inserted cert "rootca"/);
});

test('keys export → keys import (encrypted bundle, password via flag)', () => {
	const homeA = bootstrapWithCa('a-enc', 'src');
	const homeB = makeEmptyHome('b-enc', 'dst');
	const out = path.join(tmpRoot, 'leaf-enc.skb');

	const exp = runCli(
		[
			'keys', 'export', 'leaf',
			'--context', 'src',
			'--out', out,
			'--encrypt',
			'--bundle-password', 'envelope-pw',
		],
		homeA,
	);
	assert.equal(exp.status, 0, exp.stderr || exp.stdout);
	assert.match(exp.stdout, /encrypted/);

	// Wrong password → fails.
	const bad = runCli(
		['keys', 'import', out, '--context', 'dst', '--bundle-password', 'nope'],
		homeB,
	);
	assert.equal(bad.status, 2);
	assert.match(bad.stderr, /wrong password|corrupted/);

	// Right password → succeeds.
	const ok = runCli(
		['keys', 'import', out, '--context', 'dst', '--bundle-password', 'envelope-pw'],
		homeB,
	);
	assert.equal(ok.status, 0, ok.stderr);
	assert.match(ok.stdout, /inserted cert "leaf"/);
});

test('keys export rejects nonexistent cert', () => {
	const home = bootstrapWithCa('a-missing', 'src');
	const r = runCli(['keys', 'export', 'no-such', '--context', 'src'], home);
	assert.equal(r.status, 2);
	assert.match(r.stderr, /No certificate named "no-such"/);
});

test('keys transfer not allowed when --from and --to are the same', () => {
	const home = bootstrapWithCa('a-same', 'src');
	const r = runCli(['keys', 'transfer', 'leaf', '--from', 'src', '--to', 'src'], home);
	assert.equal(r.status, 2);
	assert.match(r.stderr, /must be different/);
});

test('keys --subtree from a non-CA fails clearly', () => {
	const home = bootstrapWithCa('a-non-ca-sub', 'src');
	const r = runCli(
		['keys', 'export', 'leaf', '--context', 'src', '--subtree'],
		home,
	);
	assert.equal(r.status, 2);
	assert.match(r.stderr, /--subtree only applies to CA/);
});

test('keys --subtree from a CA exports root + leaf', () => {
	const homeA = bootstrapWithCa('a-sub', 'src');
	const homeB = makeEmptyHome('b-sub', 'dst');
	const out = path.join(tmpRoot, 'sub.skb');
	const exp = runCli(
		['keys', 'export', 'rootca', '--context', 'src', '--out', out, '--subtree'],
		homeA,
	);
	assert.equal(exp.status, 0, exp.stderr);
	const imp = runCli(['keys', 'import', out, '--context', 'dst'], homeB);
	assert.equal(imp.status, 0, imp.stderr);
	assert.match(imp.stdout, /inserted cert "rootca"/);
	assert.match(imp.stdout, /inserted cert "leaf"/);
	assert.match(imp.stdout, /relinked/);
});

test('keys import respects --rename', () => {
	const homeA = bootstrapWithCa('a-rn', 'src');
	const homeB = makeEmptyHome('b-rn', 'dst');
	const out = path.join(tmpRoot, 'leaf-rn.skb');
	runCli(['keys', 'export', 'leaf', '--context', 'src', '--out', out], homeA);
	const imp = runCli(
		['keys', 'import', out, '--context', 'dst', '--rename', 'renamed-leaf'],
		homeB,
	);
	assert.equal(imp.status, 0, imp.stderr);
	assert.match(imp.stdout, /inserted cert "renamed-leaf"/);
});
