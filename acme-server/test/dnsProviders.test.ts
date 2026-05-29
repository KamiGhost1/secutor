// DNS-provider dispatcher + server-managed worker tests. Uses an in-memory
// provider so the suite stays hermetic — no real nsupdate or external scripts.

import {test, before, after, beforeEach} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {openDb} from '../src/server/db.js';
import {Repos} from '../src/server/repos.js';
import {Worker} from '../src/server/worker.js';
import {
	DnsProviderRegistry,
	type DnsProviderConfig,
	buildChallengeName,
} from '../src/server/dnsProviders.js';
import {memoryProvider} from '../src/dns/providers.js';
import {dns01TxtValue} from '../src/server/challenges.js';
import type {Config} from '../src/server/config.js';

let workDir: string;
let repos: Repos;

before(() => {
	workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secutor-dns-'));
});

after(() => {
	fs.rmSync(workDir, {recursive: true, force: true});
});

beforeEach(() => {
	const db = openDb(path.join(workDir, `acme-${Math.random().toString(36).slice(2)}.db`));
	repos = new Repos(db);
});

function fakeConfig(): Config {
	return {
		listen: '0',
		baseUrl: 'http://x/',
		contextDir: '',
		contextPasswordFile: null,
		caCertName: null,
		caKeyPasswordFile: null,
		stateDb: '',
		resolvers: [],
		challenges: {dns01: true, http01: false, http01Port: 80},
		leafValidityDays: 90,
		nonceTtlSec: 60,
		orderTtlSec: 600,
	};
}

/* ─── dispatcher ─── */

test('dispatcher: longest-zone match wins', () => {
	const rules: DnsProviderConfig[] = [
		{type: 'memory', zones: ['*'], label: 'fallback'},
		{type: 'memory', zones: ['lan.vpn', '*.lan.vpn'], label: 'lan'},
		{type: 'memory', zones: ['*.dev.lan.vpn'], label: 'dev'},
	];
	const reg = new DnsProviderRegistry(rules);
	assert.equal(reg.pickFor('svc.lan.vpn')?.label, 'lan');
	assert.equal(reg.pickFor('app.dev.lan.vpn')?.label, 'dev');
	assert.equal(reg.pickFor('other.example.com')?.label, 'fallback');
	assert.equal(reg.pickFor('lan.vpn')?.label, 'lan');
});

test('dispatcher: hasProviderFor — true only when a rule matches', () => {
	const reg = new DnsProviderRegistry([{type: 'memory', zones: ['lan.vpn']}]);
	assert.equal(reg.hasProviderFor('svc.lan.vpn'), true);
	assert.equal(reg.hasProviderFor('svc.other.com'), false);
});

test('dispatcher: strips _acme-challenge. prefix before matching', () => {
	const reg = new DnsProviderRegistry([{type: 'memory', zones: ['lan.vpn']}]);
	assert.equal(reg.hasProviderFor('_acme-challenge.svc.lan.vpn'), true);
});

test('buildChallengeName: handles wildcard identifiers', () => {
	assert.equal(buildChallengeName('foo.lan', false), '_acme-challenge.foo.lan');
	assert.equal(buildChallengeName('*.foo.lan', true), '_acme-challenge.foo.lan');
});

/* ─── memory provider ─── */

test('memory provider: place/cleanup is idempotent', async () => {
	const p = memoryProvider('m');
	await p.place({name: '_acme-challenge.x', value: 'v1'});
	await p.place({name: '_acme-challenge.x', value: 'v1'});
	assert.equal(p.records.get('_acme-challenge.x')!.size, 1);
	await p.cleanup({name: '_acme-challenge.x', value: 'nonexistent'}); // no-op
	await p.cleanup({name: '_acme-challenge.x', value: 'v1'});
	assert.equal(p.records.has('_acme-challenge.x'), false);
});

/* ─── worker integration ─── */

function seedOrder(opts: {placement?: 'client' | 'server-managed'; identifier?: string}) {
	const acct = repos.insertAccount('{"kty":"EC"}', `tp-${Math.random()}`, null);
	const identifier = opts.identifier ?? 'svc.lan.vpn';
	const order = repos.insertOrder({
		accountId: acct.id,
		identifiers: [{type: 'dns', value: identifier}],
		notBefore: null, notAfter: null, ttlSec: 600,
		dnsPlacement: opts.placement ?? 'client',
	});
	const authz = repos.insertAuthz(order.id, {type: 'dns', value: identifier}, 600);
	const challenge = repos.insertChallenge(authz.id, 'dns-01', 'token-' + Math.random().toString(36).slice(2));
	repos.queueChallenge(challenge.id);
	return {acct, order, authz, challenge};
}

test('worker: server-managed challenge places TXT before validation', async () => {
	const provider = memoryProvider('lan');
	const reg = new DnsProviderRegistry([{type: 'memory', zones: ['lan.vpn']}]);
	reg.registerMemory('mem-lan.vpn', provider);

	const {challenge, acct} = seedOrder({placement: 'server-managed'});
	const worker = new Worker(repos, fakeConfig(), () => acct.jwk_thumbprint, reg);
	// Drive a single runOne by reaching into the private API.
	await (worker as any).runOne(challenge.id);

	// Provider should now hold the TXT for this challenge.
	const value = dns01TxtValue(challenge.token, acct.jwk_thumbprint);
	const recName = '_acme-challenge.svc.lan.vpn';
	assert.equal(provider.records.get(recName)?.has(value), true, 'TXT was published');
	const placements = repos.listPlacementsForChallenge(challenge.id);
	assert.equal(placements.length, 1, 'one open placement recorded');
	assert.equal(placements[0]!.record_name, recName);
});

test('worker: server-managed challenge with no provider for zone → invalid', async () => {
	// Configured providers only cover lan.vpn — request comes for example.com.
	const reg = new DnsProviderRegistry([{type: 'memory', zones: ['lan.vpn']}]);
	const {challenge, acct} = seedOrder({placement: 'server-managed', identifier: 'svc.example.com'});
	// (We bypass the routes-level pre-check by inserting the order directly
	// with placement='server-managed'. The worker should still defensively
	// fail with secutor:noDnsProvider rather than silently retry.)
	const worker = new Worker(repos, fakeConfig(), () => acct.jwk_thumbprint, reg);
	await (worker as any).runOne(challenge.id);

	const c = repos.getChallenge(challenge.id)!;
	assert.equal(c.status, 'invalid');
	const err = JSON.parse(c.error_json!);
	assert.equal(err.type, 'secutor:noDnsProvider');
});

test('worker: cleanup-on-restart sweeps stale placements', async () => {
	const provider = memoryProvider('lan');
	const reg = new DnsProviderRegistry([{type: 'memory', zones: ['lan.vpn']}]);
	reg.registerMemory('mem-lan.vpn', provider);

	// Pretend a previous run left two TXT records behind.
	const {challenge: c1} = seedOrder({placement: 'server-managed', identifier: 'a.lan.vpn'});
	const {challenge: c2} = seedOrder({placement: 'server-managed', identifier: 'b.lan.vpn'});
	await provider.place({name: '_acme-challenge.a.lan.vpn', value: 'old-1'});
	await provider.place({name: '_acme-challenge.b.lan.vpn', value: 'old-2'});
	repos.insertPlacement({
		challengeId: c1.id, recordName: '_acme-challenge.a.lan.vpn', recordValue: 'old-1', providerLabel: 'lan',
	});
	repos.insertPlacement({
		challengeId: c2.id, recordName: '_acme-challenge.b.lan.vpn', recordValue: 'old-2', providerLabel: 'lan',
	});

	const worker = new Worker(repos, fakeConfig(), () => null, reg);
	await (worker as any).sweepStalePlacementsOnStartup();

	// Provider records gone, placements marked cleaned.
	assert.equal(provider.records.size, 0, 'all stale TXTs removed');
	const open = repos.listOpenPlacements();
	assert.equal(open.length, 0, 'placements marked cleaned in DB');
});

test('worker: client-mode (non-server-managed) does not publish TXTs', async () => {
	const provider = memoryProvider('lan');
	const reg = new DnsProviderRegistry([{type: 'memory', zones: ['lan.vpn']}]);
	reg.registerMemory('mem-lan.vpn', provider);

	const {challenge, acct} = seedOrder({placement: 'client'});
	const worker = new Worker(repos, fakeConfig(), () => acct.jwk_thumbprint, reg);
	await (worker as any).runOne(challenge.id);
	assert.equal(provider.records.size, 0, 'client-mode never asks server to publish');
});
