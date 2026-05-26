import {CertRow} from '../storage/repos.js';

export type ExpiryStatus =
	| {kind: 'expired'; daysOverdue: number}
	| {kind: 'expiring-soon'; daysLeft: number}
	| {kind: 'not-yet-valid'; daysUntilStart: number}
	| {kind: 'ok'; daysLeft: number};

export const EXPIRING_SOON_THRESHOLD_DAYS = 30;

const MS_PER_DAY = 24 * 3600 * 1000;

export function expiryStatusFromDates(
	notBefore: Date,
	notAfter: Date,
	now: Date = new Date(),
): ExpiryStatus {
	const t = now.getTime();
	if (t < notBefore.getTime()) {
		return {
			kind: 'not-yet-valid',
			daysUntilStart: Math.ceil((notBefore.getTime() - t) / MS_PER_DAY),
		};
	}
	if (t > notAfter.getTime()) {
		return {
			kind: 'expired',
			daysOverdue: Math.ceil((t - notAfter.getTime()) / MS_PER_DAY),
		};
	}
	const daysLeft = Math.floor((notAfter.getTime() - t) / MS_PER_DAY);
	if (daysLeft <= EXPIRING_SOON_THRESHOLD_DAYS) {
		return {kind: 'expiring-soon', daysLeft};
	}
	return {kind: 'ok', daysLeft};
}

export function expiryStatusOfRow(row: CertRow, now: Date = new Date()): ExpiryStatus {
	const nb = new Date(row.not_before);
	const na = new Date(row.not_after);
	return expiryStatusFromDates(nb, na, now);
}

export function expiryColor(status: ExpiryStatus): 'red' | 'yellow' | 'green' | 'gray' {
	if (status.kind === 'expired') return 'red';
	if (status.kind === 'expiring-soon') return 'yellow';
	if (status.kind === 'not-yet-valid') return 'gray';
	return 'green';
}

export function expiryIcon(status: ExpiryStatus): string {
	if (status.kind === 'expired') return '⛔';
	if (status.kind === 'expiring-soon') return '⚠';
	if (status.kind === 'not-yet-valid') return '⏳';
	return '✔';
}
