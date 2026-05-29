import {test, before, after, beforeEach} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
	buildRootCa,
	buildIntermediateCa,
	buildLeafCert,
} from '../src/certs/core.js';
import {createContext, deleteContext, listContexts} from '../src/storage/contextStore.js';
import {openContext, closeContext, getCurrentSession} from '../src/storage/db.js';
import {certRepo, sshKeyRepo, profileRepo} from '../src/storage/repos.js';
import {
	exportCert,
	exportCertSubtree,
	exportSshKey,
	exportProfile,
	importBundle,
	fingerprintOfPem,
} from '../src/transfer/repoBridge.js';
import {buildPlainBundle, parseBundle} from '../src/transfer/keyBundle.js';

let tmpHome: string;

before(() => {
	tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'secutor-bridge-'));
	process.env.SECUTOR_HOME = tmpHome;
});

after(() => {
	try {
		closeContext();
	} catch {}
	try {
		fs.rmSync(tmpHome, {recursive: true, force: true});
	} catch {}
});

beforeEach(() => {
	// Wipe contexts so each test starts from scratch. We don't reset SECUTOR_HOME
	// since the lazy paths re-read it on every call.
	try {
		closeContext();
	} catch {}
	for (const c of listContexts()) {
		deleteContext(c.name);
	}
});

function seedCa(): {certPem: string; keyPem: string; fp: string} {
	const ca = buildRootCa({
		subject: {commonName: 'bridge-root'},
		validityDays: 365,
		algorithm: 'ecdsa-p256',
	});
	return {certPem: ca.certPem, keyPem: ca.keyPem, fp: fingerprintOfPem(ca.certPem)};
}

function seedLeafUnder(parent: {certPem: string; keyPem: string}): {
	certPem: string;
	keyPem: string;
	fp: string;
} {
	const leaf = buildLeafCert({
		type: 'server',
		subject: {commonName: 'svc.bridge'},
		validityDays: 90,
		sans: ['svc.bridge', 'www.bridge'],
		algorithm: 'ed25519',
		ca: {certPem: parent.certPem, keyPem: parent.keyPem},
	});
	return {certPem: leaf.certPem, keyPem: leaf.keyPem, fp: fingerprintOfPem(leaf.certPem)};
}

function insertCa(name: string, ca: {certPem: string; keyPem: string; fp: string}): number {
	return certRepo.insert({
		name,
		type: 'ca',
		common_name: 'bridge-root',
		organization: null,
		issuer_id: null,
		serial: '1',
		not_before: new Date().toISOString(),
		not_after: new Date(Date.now() + 365 * 86400_000).toISOString(),
		san: null,
		cert_pem: ca.certPem,
		key_pem: ca.keyPem,
		fingerprint: ca.fp,
	});
}

function insertLeaf(
	name: string,
	leaf: {certPem: string; keyPem: string; fp: string},
	issuerId: number | null,
): number {
	return certRepo.insert({
		name,
		type: 'server',
		common_name: 'svc.bridge',
		organization: null,
		issuer_id: issuerId,
		serial: '1',
		not_before: new Date().toISOString(),
		not_after: new Date(Date.now() + 90 * 86400_000).toISOString(),
		san: JSON.stringify(['svc.bridge']),
		cert_pem: leaf.certPem,
		key_pem: leaf.keyPem,
		fingerprint: leaf.fp,
	});
}

/* ────────────────────────── leaf export/import ────────────────────────── */

test('leaf round-trip: source → bundle → destination', () => {
	createContext({name: 'src'});
	openContext('src', null);
	const ca = seedCa();
	const caId = insertCa('root', ca);
	const leaf = seedLeafUnder(ca);
	insertLeaf('mainleaf', leaf, caId);

	const {manifest, payload} = exportCert(
		certRepo.findByName('mainleaf')!.id,
		{contextName: 'src'},
	);
	const buf = buildPlainBundle(manifest, payload);
	closeContext();

	createContext({name: 'dst'});
	openContext('dst', null);
	const summary = importBundle(parseBundle(buf));
	assert.equal(summary.inserted.length, 1);
	assert.equal(summary.duplicates.length, 0);
	const got = certRepo.findByName('mainleaf');
	assert.ok(got, 'leaf inserted under suggested name');
	assert.equal(got!.fingerprint, leaf.fp);
	assert.equal(got!.cert_pem, leaf.certPem);
	assert.equal(got!.key_pem, leaf.keyPem);
});

test('leaf with includeParents bundles the chain and importer materializes the CA', () => {
	createContext({name: 'src'});
	openContext('src', null);
	const ca = seedCa();
	const caId = insertCa('root', ca);
	const leaf = seedLeafUnder(ca);
	insertLeaf('chained', leaf, caId);

	const {manifest, payload} = exportCert(certRepo.findByName('chained')!.id, {
		contextName: 'src',
		includeParents: true,
	});
	assert.equal(
		manifest.items.filter(i => i.role === 'parent').length,
		1,
		'one parent in items',
	);
	closeContext();

	createContext({name: 'dst'});
	openContext('dst', null);
	const summary = importBundle(parseBundle(buildPlainBundle(manifest, payload)));
	// Inserted: 1 parent CA + 1 leaf
	assert.equal(summary.inserted.filter(r => r.kind === 'cert').length, 2);
	const importedCa = certRepo.list().find(r => r.fingerprint === ca.fp);
	const importedLeaf = certRepo.findByName('chained');
	assert.ok(importedCa, 'parent imported');
	assert.ok(importedLeaf, 'leaf imported');
	assert.equal(importedLeaf!.issuer_id, importedCa!.id, 'issuer relink worked');
	assert.equal(summary.issuerRelinks >= 1, true);
});

test('leaf import without parent bundle: issuer relink kicks in if CA already lives in target', () => {
	createContext({name: 'src'});
	openContext('src', null);
	const ca = seedCa();
	const caId = insertCa('root', ca);
	const leaf = seedLeafUnder(ca);
	insertLeaf('relink-leaf', leaf, caId);

	const {manifest, payload} = exportCert(certRepo.findByName('relink-leaf')!.id, {
		contextName: 'src',
		includeParents: false,
	});
	closeContext();

	createContext({name: 'dst'});
	openContext('dst', null);
	// Pre-seed the CA on the destination side.
	const dstCaId = insertCa('root-on-dst', ca);
	const summary = importBundle(parseBundle(buildPlainBundle(manifest, payload)));
	assert.equal(summary.issuerRelinks, 1);
	const importedLeaf = certRepo.findByName('relink-leaf');
	assert.equal(importedLeaf!.issuer_id, dstCaId);
});

/* ────────────────────────── duplicates ────────────────────────── */

test('duplicate fingerprint is detected and skipped', () => {
	createContext({name: 'src'});
	openContext('src', null);
	const ca = seedCa();
	const caId = insertCa('root', ca);
	const leaf = seedLeafUnder(ca);
	insertLeaf('dupleaf', leaf, caId);
	const {manifest, payload} = exportCert(certRepo.findByName('dupleaf')!.id, {
		contextName: 'src',
	});
	closeContext();

	createContext({name: 'dst'});
	openContext('dst', null);
	// Pre-seed the exact same cert+key. Importer must not insert a second row.
	insertLeaf('preexisting', leaf, null);
	const summary = importBundle(parseBundle(buildPlainBundle(manifest, payload)));
	assert.equal(summary.inserted.length, 0);
	assert.equal(summary.duplicates.length, 1);
	assert.equal(summary.duplicates[0]!.fingerprint, leaf.fp);
	assert.equal(summary.duplicates[0]!.name, 'preexisting');
});

test('duplicate cert: fills in missing key_pem from bundle', () => {
	createContext({name: 'src'});
	openContext('src', null);
	const ca = seedCa();
	const caId = insertCa('root', ca);
	const leaf = seedLeafUnder(ca);
	insertLeaf('hasleaf', leaf, caId);
	const {manifest, payload} = exportCert(certRepo.findByName('hasleaf')!.id, {
		contextName: 'src',
	});
	closeContext();

	createContext({name: 'dst'});
	openContext('dst', null);
	// Pre-seed the same cert WITHOUT the private key.
	const id = insertLeaf('keyless', {certPem: leaf.certPem, keyPem: '', fp: leaf.fp}, null);
	assert.equal(certRepo.findById(id)!.key_pem, '');
	const summary = importBundle(parseBundle(buildPlainBundle(manifest, payload)));
	assert.equal(summary.updated.length, 1);
	assert.equal(certRepo.findById(id)!.key_pem, leaf.keyPem);
});

/* ────────────────────────── name collisions ────────────────────────── */

test('name collision is resolved by suffix and reported as a conflict', () => {
	createContext({name: 'src'});
	openContext('src', null);
	const ca1 = seedCa();
	insertCa('shared-name', ca1);
	const ca2 = {
		...buildRootCa({subject: {commonName: 'other-root'}, validityDays: 365, algorithm: 'ed25519'}),
	};
	const ca2Pack = {certPem: ca2.certPem, keyPem: ca2.keyPem, fp: fingerprintOfPem(ca2.certPem)};
	// Export the second one.
	const id = insertCa('source-only', ca2Pack);
	const {manifest, payload} = exportCert(id, {contextName: 'src'});
	// Force the manifest name to collide with what destination already has.
	manifest.name = 'shared-name';
	closeContext();

	createContext({name: 'dst'});
	openContext('dst', null);
	// Pre-seed a DIFFERENT CA under that name.
	insertCa('shared-name', ca1);
	const summary = importBundle(parseBundle(buildPlainBundle(manifest, payload)));
	assert.equal(summary.inserted.length, 1);
	assert.equal(summary.inserted[0]!.name, 'shared-name-2');
	assert.equal(summary.conflicts.length, 1);
	assert.match(summary.conflicts[0]!.reason, /name in use/);
});

/* ────────────────────────── subtree ────────────────────────── */

test('subtree of depth 3 round-trips with issuer chain intact', () => {
	createContext({name: 'src'});
	openContext('src', null);
	const root = seedCa();
	const rootId = insertCa('root', root);
	const inter = buildIntermediateCa({
		subject: {commonName: 'mid'},
		validityDays: 365,
		algorithm: 'ecdsa-p256',
		ca: {certPem: root.certPem, keyPem: root.keyPem},
	});
	const interPack = {certPem: inter.certPem, keyPem: inter.keyPem, fp: fingerprintOfPem(inter.certPem)};
	const interId = certRepo.insert({
		name: 'mid',
		type: 'ca',
		common_name: 'mid',
		organization: null,
		issuer_id: rootId,
		serial: '2',
		not_before: inter.notBefore.toISOString(),
		not_after: inter.notAfter.toISOString(),
		san: null,
		cert_pem: interPack.certPem,
		key_pem: interPack.keyPem,
		fingerprint: interPack.fp,
	});
	const leaf = seedLeafUnder(interPack);
	insertLeaf('leaf-under-mid', leaf, interId);

	const {manifest, payload} = exportCertSubtree(rootId, {contextName: 'src'});
	assert.equal(manifest.kind, 'subtree');
	assert.equal(manifest.links?.subtreeFingerprints?.length, 3);
	closeContext();

	createContext({name: 'dst'});
	openContext('dst', null);
	const summary = importBundle(parseBundle(buildPlainBundle(manifest, payload)));
	assert.equal(summary.inserted.filter(r => r.kind === 'cert').length, 3);
	const dstRoot = certRepo.list().find(r => r.fingerprint === root.fp)!;
	const dstInter = certRepo.list().find(r => r.fingerprint === interPack.fp)!;
	const dstLeaf = certRepo.list().find(r => r.fingerprint === leaf.fp)!;
	assert.equal(dstInter.issuer_id, dstRoot.id);
	assert.equal(dstLeaf.issuer_id, dstInter.id);
	assert.equal(dstLeaf.key_pem, leaf.keyPem);
});

/* ────────────────────────── ssh ────────────────────────── */

test('SSH key round-trip preserves wire format and algorithm', () => {
	createContext({name: 'src'});
	openContext('src', null);
	const id = sshKeyRepo.insert({
		name: 'deploy',
		algorithm: 'ssh-ed25519',
		comment: 'deploy@host',
		public_key: 'ssh-ed25519 AAAAC3Nz... deploy@host\n',
		private_key: '-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n',
		encrypted: 0,
		fingerprint: 'SHA256:abc123',
	});
	const {manifest, payload} = exportSshKey(id, {contextName: 'src'});
	closeContext();

	createContext({name: 'dst'});
	openContext('dst', null);
	const summary = importBundle(parseBundle(buildPlainBundle(manifest, payload)));
	assert.equal(summary.inserted.length, 1);
	assert.equal(summary.inserted[0]!.kind, 'ssh');
	const row = sshKeyRepo.findByName('deploy');
	assert.ok(row);
	assert.equal(row!.algorithm, 'ssh-ed25519');
	assert.equal(row!.comment, 'deploy@host');
	assert.equal(row!.fingerprint, 'SHA256:abc123');
	assert.match(row!.public_key, /^ssh-ed25519/);
	assert.match(row!.private_key, /OPENSSH PRIVATE KEY/);
});

test('SSH key duplicate by fingerprint is skipped', () => {
	createContext({name: 'src'});
	openContext('src', null);
	const id = sshKeyRepo.insert({
		name: 'deploy',
		algorithm: 'ssh-ed25519',
		comment: null,
		public_key: 'p',
		private_key: 'k',
		encrypted: 0,
		fingerprint: 'SHA256:dup',
	});
	const {manifest, payload} = exportSshKey(id, {contextName: 'src'});
	closeContext();

	createContext({name: 'dst'});
	openContext('dst', null);
	sshKeyRepo.insert({
		name: 'pre',
		algorithm: 'ssh-ed25519',
		comment: null,
		public_key: 'p',
		private_key: 'k',
		encrypted: 0,
		fingerprint: 'SHA256:dup',
	});
	const summary = importBundle(parseBundle(buildPlainBundle(manifest, payload)));
	assert.equal(summary.duplicates.length, 1);
	assert.equal(summary.inserted.length, 0);
});

/* ────────────────────────── profiles ────────────────────────── */

test('profile round-trip carries P12 DER in payload and links to the cert', () => {
	createContext({name: 'src'});
	openContext('src', null);
	const ca = seedCa();
	const caId = insertCa('root', ca);
	const leaf = seedLeafUnder(ca);
	const leafId = insertLeaf('p12leaf', leaf, caId);
	const fakeDer = Buffer.from('not-a-real-p12-but-binary-enough-for-this-test'.repeat(20));
	const pid = profileRepo.insert({
		name: 'svc-bundle',
		cert_id: leafId,
		format: 'p12',
		friendly_name: 'Svc Bundle',
		data: fakeDer,
	});
	const {manifest, payload} = exportProfile(pid, {contextName: 'src'});
	assert.equal(payload.equals(fakeDer), true);
	closeContext();

	createContext({name: 'dst'});
	openContext('dst', null);
	// Pre-seed the cert (profile FK depends on it).
	insertLeaf('p12leaf-on-dst', leaf, null);
	const summary = importBundle(parseBundle(buildPlainBundle(manifest, payload)));
	assert.equal(summary.inserted.length, 1);
	const profiles = profileRepo.list();
	assert.equal(profiles.length, 1);
	assert.equal(profiles[0]!.name, 'svc-bundle');
	assert.equal(profiles[0]!.friendly_name, 'Svc Bundle');
	assert.equal(profiles[0]!.data.equals(fakeDer), true);
});

test('profile import fails cleanly when target lacks the referenced cert', () => {
	createContext({name: 'src'});
	openContext('src', null);
	const ca = seedCa();
	const caId = insertCa('root', ca);
	const leaf = seedLeafUnder(ca);
	const leafId = insertLeaf('p12leaf', leaf, caId);
	const pid = profileRepo.insert({
		name: 'svc-bundle',
		cert_id: leafId,
		format: 'p12',
		friendly_name: null,
		data: Buffer.from('xxx'),
	});
	const {manifest, payload} = exportProfile(pid, {contextName: 'src'});
	closeContext();

	createContext({name: 'dst'});
	openContext('dst', null);
	assert.throws(
		() => importBundle(parseBundle(buildPlainBundle(manifest, payload))),
		/not present/,
	);
});

/* ────────────────────────── integrity ────────────────────────── */

test('mismatched fingerprint in manifest meta is rejected', () => {
	createContext({name: 'src'});
	openContext('src', null);
	const ca = seedCa();
	const caId = insertCa('root', ca);
	const leaf = seedLeafUnder(ca);
	insertLeaf('lf', leaf, caId);
	const {manifest, payload} = exportCert(certRepo.findByName('lf')!.id, {
		contextName: 'src',
	});
	// Corrupt the meta fingerprint.
	manifest.items[0]!.meta!.fingerprint = 'ff'.repeat(32);
	closeContext();

	createContext({name: 'dst'});
	openContext('dst', null);
	assert.throws(
		() => importBundle(parseBundle(buildPlainBundle(manifest, payload))),
		/integrity check failed/,
	);
});

test('importing leaves no half-state when an item triggers an error', () => {
	createContext({name: 'src'});
	openContext('src', null);
	const ca = seedCa();
	const caId = insertCa('root', ca);
	const leaf = seedLeafUnder(ca);
	insertLeaf('lf-tx', leaf, caId);
	const {manifest, payload} = exportCert(certRepo.findByName('lf-tx')!.id, {
		contextName: 'src',
		includeParents: true,
	});
	// Tamper with the LEAF's fingerprint AFTER the parent, so the importer
	// inserts the parent first and then bails. Without a transaction the
	// parent would survive; with the transaction wrapping the whole import
	// we expect rollback.
	manifest.items[0]!.meta!.fingerprint = 'ff'.repeat(32);
	closeContext();

	createContext({name: 'dst'});
	openContext('dst', null);
	const before = certRepo.list().length;
	assert.throws(() => importBundle(parseBundle(buildPlainBundle(manifest, payload))));
	const after = certRepo.list().length;
	assert.equal(after, before, 'transaction rolled back, parent insert undone');
});
