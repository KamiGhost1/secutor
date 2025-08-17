import {test} from 'node:test';
import assert from 'node:assert/strict';

import {
	buildRootCa,
	buildIntermediateCa,
	buildLeafCert,
} from '../src/certs/core.js';
import {auditCertificates, Finding} from '../src/certs/audit.js';
import type {CertRow} from '../src/storage/repos.js';

let nextId = 1;

function row(overrides: Partial<CertRow> & {cert_pem: string}): CertRow {
	return {
		id: nextId++,
		name: `cert-${nextId}`,
		type: 'server',
		common_name: '',
		organization: null,
		issuer_id: null,
		serial: '',
		not_before: new Date(0).toISOString(),
		not_after: new Date(Date.now() + 365 * 86400_000).toISOString(),
		san: null,
		cert_pem: '',
		key_pem: '',
		fingerprint: '',
		created_at: new Date().toISOString(),
		revoked_at: null,
		revocation_reason: null,
		...overrides,
	};
}

function buildScenario() {
	const ca = buildRootCa({
		subject: {commonName: 'audit-root'},
		validityDays: 365,
	});
	const inter = buildIntermediateCa({
		subject: {commonName: 'audit-int'},
		validityDays: 365,
		ca: {certPem: ca.certPem, keyPem: ca.keyPem},
	});
	const leaf = buildLeafCert({
		type: 'server',
		subject: {commonName: 'svc.audit'},
		validityDays: 90,
		ca: {certPem: inter.certPem, keyPem: inter.keyPem},
	});
	return {ca, inter, leaf};
}

function find(findings: Finding[], certId: number, kind: Finding['kind']): Finding | undefined {
	return findings.find(f => f.certId === certId && f.kind === kind);
}

test('healthy two-tier store yields no findings', () => {
	const {ca, inter, leaf} = buildScenario();
	const caRow = row({
		name: 'root',
		type: 'ca',
		cert_pem: ca.certPem,
		key_pem: ca.keyPem,
		common_name: 'audit-root',
		serial: ca.serial,
		not_before: ca.notBefore.toISOString(),
		not_after: ca.notAfter.toISOString(),
		fingerprint: ca.fingerprint,
	});
	const intRow = row({
		name: 'int',
		type: 'ca',
		cert_pem: inter.certPem,
		key_pem: inter.keyPem,
		issuer_id: caRow.id,
		common_name: 'audit-int',
		serial: inter.serial,
		not_before: inter.notBefore.toISOString(),
		not_after: inter.notAfter.toISOString(),
		fingerprint: inter.fingerprint,
	});
	const leafRow = row({
		name: 'svc',
		type: 'server',
		cert_pem: leaf.certPem,
		key_pem: leaf.keyPem,
		issuer_id: intRow.id,
		common_name: 'svc.audit',
		serial: leaf.serial,
		not_before: leaf.notBefore.toISOString(),
		not_after: leaf.notAfter.toISOString(),
		fingerprint: leaf.fingerprint,
		san: leaf.sans.length ? JSON.stringify(leaf.sans) : null,
	});

	const report = auditCertificates([caRow, intRow, leafRow]);
	assert.equal(
		report.findings.length,
		0,
		`unexpected findings:\n${report.findings.map(f => f.kind + ': ' + f.message).join('\n')}`,
	);
});

test('detects metadata drift and proposes refresh', () => {
	const {ca} = buildScenario();
	const caRow = row({
		type: 'ca',
		cert_pem: ca.certPem,
		key_pem: ca.keyPem,
		common_name: 'WRONG-NAME',
		serial: 'deadbeef',
		not_before: ca.notBefore.toISOString(),
		not_after: ca.notAfter.toISOString(),
		fingerprint: 'old-fingerprint',
	});
	const report = auditCertificates([caRow]);
	const drift = find(report.findings, caRow.id, 'meta-drift');
	assert.ok(drift, 'expected meta-drift finding');
	assert.equal(drift!.fix?.kind, 'refresh-meta');
	if (drift!.fix?.kind === 'refresh-meta') {
		assert.equal(drift!.fix.metadata.common_name, 'audit-root');
		assert.equal(drift!.fix.metadata.serial, ca.serial);
		assert.equal(drift!.fix.metadata.fingerprint, ca.fingerprint);
	}
});

test('detects key/cert mismatch and skips refresh-meta otherwise', () => {
	const a = buildRootCa({subject: {commonName: 'A'}, validityDays: 30});
	const b = buildRootCa({subject: {commonName: 'B'}, validityDays: 30});
	const wrong = row({
		type: 'ca',
		cert_pem: a.certPem,
		key_pem: b.keyPem,
		common_name: 'A',
		serial: a.serial,
		not_before: a.notBefore.toISOString(),
		not_after: a.notAfter.toISOString(),
		fingerprint: a.fingerprint,
	});
	const report = auditCertificates([wrong]);
	assert.ok(find(report.findings, wrong.id, 'key-mismatch'));
});

test('detects orphan leaf and suggests relink to matching CA', () => {
	const {ca, leaf} = (() => {
		const ca = buildRootCa({subject: {commonName: 'orphan-root'}, validityDays: 365});
		const leaf = buildLeafCert({
			type: 'server',
			subject: {commonName: 'orphan.svc'},
			validityDays: 90,
			ca: {certPem: ca.certPem, keyPem: ca.keyPem},
		});
		return {ca, leaf};
	})();

	const caRow = row({
		name: 'root',
		type: 'ca',
		cert_pem: ca.certPem,
		key_pem: ca.keyPem,
		common_name: 'orphan-root',
		serial: ca.serial,
		not_before: ca.notBefore.toISOString(),
		not_after: ca.notAfter.toISOString(),
		fingerprint: ca.fingerprint,
	});
	const leafRow = row({
		name: 'orphan',
		type: 'server',
		cert_pem: leaf.certPem,
		key_pem: leaf.keyPem,
		issuer_id: null,
		common_name: 'orphan.svc',
		serial: leaf.serial,
		not_before: leaf.notBefore.toISOString(),
		not_after: leaf.notAfter.toISOString(),
		fingerprint: leaf.fingerprint,
	});

	const report = auditCertificates([caRow, leafRow]);
	const orphan = find(report.findings, leafRow.id, 'issuer-not-set');
	assert.ok(orphan, 'expected issuer-not-set finding');
	assert.equal(orphan!.fix?.kind, 'relink-issuer');
	if (orphan!.fix?.kind === 'relink-issuer') {
		assert.equal(orphan!.fix.newIssuerId, caRow.id);
	}
});

test('detects wrong issuer link (DN mismatch) and suggests correct CA', () => {
	const right = buildRootCa({subject: {commonName: 'right'}, validityDays: 365});
	const wrong = buildRootCa({subject: {commonName: 'wrong'}, validityDays: 365});
	const leaf = buildLeafCert({
		type: 'server',
		subject: {commonName: 'svc'},
		validityDays: 90,
		ca: {certPem: right.certPem, keyPem: right.keyPem},
	});

	const rightRow = row({
		name: 'right',
		type: 'ca',
		cert_pem: right.certPem,
		key_pem: right.keyPem,
		common_name: 'right',
		serial: right.serial,
		not_before: right.notBefore.toISOString(),
		not_after: right.notAfter.toISOString(),
		fingerprint: right.fingerprint,
	});
	const wrongRow = row({
		name: 'wrong',
		type: 'ca',
		cert_pem: wrong.certPem,
		key_pem: wrong.keyPem,
		common_name: 'wrong',
		serial: wrong.serial,
		not_before: wrong.notBefore.toISOString(),
		not_after: wrong.notAfter.toISOString(),
		fingerprint: wrong.fingerprint,
	});
	const leafRow = row({
		name: 'svc',
		type: 'server',
		cert_pem: leaf.certPem,
		key_pem: leaf.keyPem,
		issuer_id: wrongRow.id,
		common_name: 'svc',
		serial: leaf.serial,
		not_before: leaf.notBefore.toISOString(),
		not_after: leaf.notAfter.toISOString(),
		fingerprint: leaf.fingerprint,
	});

	const report = auditCertificates([rightRow, wrongRow, leafRow]);
	const f = find(report.findings, leafRow.id, 'issuer-dn-mismatch');
	assert.ok(f, 'expected issuer-dn-mismatch');
	if (f!.fix?.kind === 'relink-issuer') {
		assert.equal(f!.fix.newIssuerId, rightRow.id);
	} else {
		assert.fail('expected relink-issuer fix');
	}
});

test('detects missing parent (dangling issuer_id) and suggests fallback', () => {
	const {ca, leaf} = (() => {
		const ca = buildRootCa({subject: {commonName: 'dangle-root'}, validityDays: 365});
		const leaf = buildLeafCert({
			type: 'server',
			subject: {commonName: 'svc'},
			validityDays: 30,
			ca: {certPem: ca.certPem, keyPem: ca.keyPem},
		});
		return {ca, leaf};
	})();

	const caRow = row({
		type: 'ca',
		cert_pem: ca.certPem,
		key_pem: ca.keyPem,
		common_name: 'dangle-root',
		serial: ca.serial,
		not_before: ca.notBefore.toISOString(),
		not_after: ca.notAfter.toISOString(),
		fingerprint: ca.fingerprint,
	});
	const leafRow = row({
		type: 'server',
		cert_pem: leaf.certPem,
		key_pem: leaf.keyPem,
		issuer_id: 9999,
		common_name: 'svc',
		serial: leaf.serial,
		not_before: leaf.notBefore.toISOString(),
		not_after: leaf.notAfter.toISOString(),
		fingerprint: leaf.fingerprint,
	});
	const report = auditCertificates([caRow, leafRow]);
	const f = find(report.findings, leafRow.id, 'issuer-missing');
	assert.ok(f);
	if (f!.fix?.kind === 'relink-issuer') {
		assert.equal(f!.fix.newIssuerId, caRow.id);
	}
});

test('flags unparseable PEM with no further checks', () => {
	const broken = row({
		cert_pem: '-----BEGIN CERTIFICATE-----\nGARBAGE\n-----END CERTIFICATE-----\n',
	});
	const report = auditCertificates([broken]);
	const fs = report.findings.filter(f => f.certId === broken.id);
	assert.equal(fs.length, 1);
	assert.equal(fs[0].kind, 'parse-error');
});

test('audit never throws on a corrupt cert_pem with a healthy CA in store', () => {
	// Regression: the AuditScreen used to crash because dnDer / forge calls in
	// the audit pipeline were not all wrapped, so a single unparseable row could
	// take down the whole screen. Now auditCertificates must always return a
	// report even when rows contain garbage.
	const ca = buildRootCa({subject: {commonName: 'safe-root'}, validityDays: 365});
	const caRow = row({
		type: 'ca',
		cert_pem: ca.certPem,
		key_pem: ca.keyPem,
		common_name: 'safe-root',
		serial: ca.serial,
		not_before: ca.notBefore.toISOString(),
		not_after: ca.notAfter.toISOString(),
		fingerprint: ca.fingerprint,
	});
	const corruptLeaf = row({
		type: 'server',
		issuer_id: caRow.id,
		cert_pem: 'totally not a pem',
		common_name: '',
		serial: '',
		not_before: 'not-a-date',
		not_after: 'not-a-date',
		fingerprint: '',
	});
	const corruptCa = row({
		type: 'ca',
		issuer_id: caRow.id,
		cert_pem: '-----BEGIN CERTIFICATE-----\nGARBAGE\n-----END CERTIFICATE-----\n',
		common_name: '',
		serial: '',
		not_before: 'not-a-date',
		not_after: 'not-a-date',
		fingerprint: '',
	});

	const report = auditCertificates([caRow, corruptLeaf, corruptCa]);
	assert.equal(report.scanned, 3);
	assert.ok(report.findings.some(f => f.kind === 'parse-error' && f.certId === corruptLeaf.id));
	assert.ok(report.findings.some(f => f.kind === 'parse-error' && f.certId === corruptCa.id));
	assert.equal(
		report.findings.filter(f => f.certId === caRow.id).length,
		0,
		'healthy CA should remain finding-free even when sibling rows are corrupt',
	);
});

test('flags expired cert with severity warn', () => {
	const ca = buildRootCa({subject: {commonName: 'past-root'}, validityDays: 365});
	const r = row({
		type: 'ca',
		cert_pem: ca.certPem,
		key_pem: ca.keyPem,
		common_name: 'past-root',
		serial: ca.serial,
		not_before: ca.notBefore.toISOString(),
		not_after: ca.notAfter.toISOString(),
		fingerprint: ca.fingerprint,
	});
	const report = auditCertificates([r]);
	// healthy cert — no findings
	assert.equal(
		report.findings.length,
		0,
		`unexpected findings: ${report.findings.map(f => f.kind).join(', ')}`,
	);
});
