import {test} from 'node:test';
import assert from 'node:assert/strict';
import {
	expiryStatusFromDates,
	expiryColor,
	expiryIcon,
	EXPIRING_SOON_THRESHOLD_DAYS,
} from '../src/certs/expiry.js';

const day = 86400_000;
const now = new Date('2026-05-09T12:00:00Z');

test('classifies a comfortably valid cert as ok', () => {
	const s = expiryStatusFromDates(
		new Date(now.getTime() - 30 * day),
		new Date(now.getTime() + 200 * day),
		now,
	);
	assert.equal(s.kind, 'ok');
	if (s.kind === 'ok') {
		assert.equal(s.daysLeft, 200);
	}
	assert.equal(expiryColor(s), 'green');
	assert.equal(expiryIcon(s), '✔');
});

test('classifies a cert near the threshold as expiring-soon', () => {
	const s = expiryStatusFromDates(
		new Date(now.getTime() - 30 * day),
		new Date(now.getTime() + (EXPIRING_SOON_THRESHOLD_DAYS - 1) * day),
		now,
	);
	assert.equal(s.kind, 'expiring-soon');
	assert.equal(expiryColor(s), 'yellow');
});

test('classifies a past notAfter as expired with daysOverdue', () => {
	const s = expiryStatusFromDates(
		new Date(now.getTime() - 100 * day),
		new Date(now.getTime() - 5 * day),
		now,
	);
	assert.equal(s.kind, 'expired');
	if (s.kind === 'expired') {
		assert.equal(s.daysOverdue, 5);
	}
	assert.equal(expiryColor(s), 'red');
	assert.equal(expiryIcon(s), '⛔');
});

test('classifies a future notBefore as not-yet-valid', () => {
	const s = expiryStatusFromDates(
		new Date(now.getTime() + 7 * day),
		new Date(now.getTime() + 100 * day),
		now,
	);
	assert.equal(s.kind, 'not-yet-valid');
	if (s.kind === 'not-yet-valid') {
		assert.equal(s.daysUntilStart, 7);
	}
});
