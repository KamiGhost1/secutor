// Pin enforcement and identity-resolver tests for the mTLS hub client.
// Spins up two tiny HTTPS endpoints (one per scenario) on random ports so
// each test fully controls what cert the "server" presents.

import {test, before, after, beforeEach} from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import net from 'node:net';

import {buildRootCa, buildLeafCert} from '../src/certs/core.js';
import {makeHubClient, probeServerFingerprint, HubError} from '../src/net/hubClient.js';
import {resolveIdentity, EncryptedKeyError} from '../src/net/clientIdentity.js';
import {addHub, listHubs, removeHub} from '../src/storage/hubStore.js';
import {saveEntry, listEntries, deleteEntry} from '../src/storage/hubKeystore.js';
import {createContext, deleteContext, listContexts} from '../src/storage/contextStore.js';
import {openContext, closeContext} from '../src/storage/db.js';
import {certRepo} from '../src/storage/repos.js';
import {encryptPrivateKey} from '../src/certs/keys.js';

let tmpHome: string;

before(() => {
	tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'secutor-hubclient-'));
	process.env.SECUTOR_HOME = tmpHome;
});

after(() => {
	try { closeContext(); } catch {}
	try { fs.rmSync(tmpHome, {recursive: true, force: true}); } catch {}
});

beforeEach(() => {
	try { closeContext(); } catch {}
	for (const c of listContexts()) deleteContext(c.name);
	for (const h of listHubs()) removeHub(h.id);
	for (const e of listEntries()) deleteEntry(e.name);
});

function fp(pem: string): string {
	const body = pem.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----/g, '').replace(/\s+/g, '');
	return crypto.createHash('sha256').update(Buffer.from(body, 'base64')).digest('hex');
}

async function getRandomPort(): Promise<number> {
	return new Promise(resolve => {
		const s = net.createServer();
		s.listen(0, () => {
			const p = (s.address() as any).port as number;
			s.close(() => resolve(p));
		});
	});
}

async function spinHttps(certPem: string, keyPem: string, handler: (req: any, res: any) => void) {
	const port = await getRandomPort();
	const server = https.createServer(
		{cert: certPem, key: keyPem, requestCert: false},
		handler,
	);
	await new Promise<void>(r => server.listen(port, '127.0.0.1', () => r()));
	return {
		port,
		baseUrl: `https://127.0.0.1:${port}/`,
		close: () => new Promise<void>(r => server.close(() => r())),
	};
}

test('hubClient: rejects connection when server fingerprint does not match pin', async () => {
	const real = buildRootCa({subject: {commonName: 'real'}, validityDays: 1, algorithm: 'ecdsa-p256'});
	const intruder = buildRootCa({subject: {commonName: 'intruder'}, validityDays: 1, algorithm: 'ecdsa-p256'});
	const server = await spinHttps(intruder.certPem, intruder.keyPem, (_req, res) => {
		res.writeHead(200, {'content-type': 'application/json'});
		res.end('{"ok":true}');
	});
	try {
		const client = buildPair();
		const hub = addHub({
			name: 't', baseUrl: server.baseUrl,
			serverFingerprint: fp(real.certPem), // wrong pin: real, but server is intruder
			clientAuth: {kind: 'file', certPath: writeTmp('c.crt', client.certPem), keyPath: writeTmp('c.key', client.keyPem)},
		});
		const h = makeHubClient(hub, {certPem: client.certPem, keyPem: client.keyPem, source: 'file'});
		await assert.rejects(
			h.request({method: 'GET', path: '/'}),
			(err: any) => err instanceof HubError && err.code === 'cert-pin-mismatch',
		);
		h.close();
	} finally {
		await server.close();
	}
});

test('hubClient: succeeds when pin matches', async () => {
	const server_ca = buildRootCa({subject: {commonName: 'server'}, validityDays: 1, algorithm: 'ecdsa-p256'});
	const server = await spinHttps(server_ca.certPem, server_ca.keyPem, (_req, res) => {
		res.writeHead(200, {'content-type': 'application/json'});
		res.end(JSON.stringify({ok: true, url: 'hit'}));
	});
	try {
		const client = buildPair();
		const hub = addHub({
			name: 't', baseUrl: server.baseUrl,
			serverFingerprint: fp(server_ca.certPem),
			clientAuth: {kind: 'file', certPath: writeTmp('c.crt', client.certPem), keyPath: writeTmp('c.key', client.keyPem)},
		});
		const h = makeHubClient(hub, {certPem: client.certPem, keyPem: client.keyPem, source: 'file'});
		const r = await h.request({method: 'GET', path: '/anything'});
		assert.equal(r.status, 200);
		assert.equal((r.body as any).ok, true);
		h.close();
	} finally {
		await server.close();
	}
});

test('hubClient: probeServerFingerprint returns the server cert fingerprint', async () => {
	const server_ca = buildRootCa({subject: {commonName: 'probe'}, validityDays: 1, algorithm: 'ecdsa-p256'});
	const server = await spinHttps(server_ca.certPem, server_ca.keyPem, (_req, res) => {
		res.writeHead(404);
		res.end();
	});
	try {
		const got = await probeServerFingerprint(server.baseUrl);
		assert.equal(got, fp(server_ca.certPem));
	} finally {
		await server.close();
	}
});

test('identity resolver: context source — encrypted key throws EncryptedKeyError without password', () => {
	createContext({name: 'idctx'});
	openContext('idctx', null);
	const pair = buildPair();
	const enc = encryptPrivateKey(pair.keyPem, 'secret');
	certRepo.insert({
		name: 'admin-cli', type: 'client', common_name: 'admin', organization: null,
		issuer_id: null, serial: '1', not_before: new Date().toISOString(),
		not_after: new Date(Date.now() + 86400_000).toISOString(),
		san: null, cert_pem: pair.certPem, key_pem: enc, fingerprint: fp(pair.certPem),
	});
	assert.throws(
		() => resolveIdentity({kind: 'context', context: 'idctx', certName: 'admin-cli'}),
		(err: any) => err instanceof EncryptedKeyError,
	);
	// With the right password, resolution succeeds and gives plaintext key.
	const out = resolveIdentity(
		{kind: 'context', context: 'idctx', certName: 'admin-cli'},
		{keyPassword: 'secret'},
	);
	assert.equal(out.source, 'context');
	assert.match(out.keyPem, /-----BEGIN PRIVATE KEY-----/);
});

test('identity resolver: file source reads PEMs straight from disk', () => {
	const pair = buildPair();
	const certPath = writeTmp('id.crt', pair.certPem);
	const keyPath = writeTmp('id.key', pair.keyPem);
	const out = resolveIdentity({kind: 'file', certPath, keyPath});
	assert.equal(out.source, 'file');
	assert.equal(out.certPem, pair.certPem);
});

test('identity resolver: keystore source with encrypted entry needs password', () => {
	const pair = buildPair();
	saveEntry({name: 'kx', certPem: pair.certPem, keyPem: pair.keyPem, encryptWith: 'envelope', fingerprint: fp(pair.certPem)});
	assert.throws(
		() => resolveIdentity({kind: 'keystore', keystoreEntry: 'kx'}),
		(err: any) => err instanceof EncryptedKeyError,
	);
	const ok = resolveIdentity({kind: 'keystore', keystoreEntry: 'kx'}, {keyPassword: 'envelope'});
	assert.equal(ok.source, 'keystore');
	assert.equal(ok.certPem.trim(), pair.certPem.trim());
});

test('hubStore + keystore: list / add / remove round-trip survives reads', () => {
	const h = addHub({
		name: 'one', baseUrl: 'https://h.lan/',
		serverFingerprint: 'ab'.repeat(32),
		clientAuth: {kind: 'keystore', keystoreEntry: 'k'},
	});
	const e = saveEntry({name: 'k', certPem: '-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----', keyPem: '-----BEGIN PRIVATE KEY-----\nBB\n-----END PRIVATE KEY-----', fingerprint: 'cd'.repeat(32)});
	const hubs = listHubs();
	const entries = listEntries();
	assert.equal(hubs[0]!.id, h.id);
	assert.equal(entries[0]!.name, e.name);
	removeHub(h.id);
	deleteEntry(e.name);
	assert.equal(listHubs().length, 0);
	assert.equal(listEntries().length, 0);
});

function buildPair() {
	const r = buildRootCa({subject: {commonName: 'admin-client'}, validityDays: 1, algorithm: 'ecdsa-p256'});
	return r;
}

function writeTmp(name: string, data: string): string {
	const p = path.join(tmpHome, name);
	fs.writeFileSync(p, data);
	return p;
}
