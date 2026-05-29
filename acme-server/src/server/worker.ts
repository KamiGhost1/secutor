// Background worker. Polls processing-state challenges, validates them, and
// flips their parent authorization + order accordingly.
//
// For server-managed DNS-01 challenges (the `secutor.dnsPlacement = "server-
// managed"` extension on newOrder), this worker also:
//   * publishes the TXT record before validating (via DnsProviderRegistry),
//   * cleans it up on terminal outcomes (valid / invalid),
//   * sweeps stale placements on startup so a crash mid-flight doesn't
//     leave a TXT in the zone forever.

import type {Repos} from './repos.js';
import type {Config} from './config.js';
import type {DnsProviderRegistry} from './dnsProviders.js';
import {buildChallengeName} from './dnsProviders.js';
import {validateDns01, validateHttp01, dns01TxtValue} from './challenges.js';
import {nowIso, isoPlus} from './util.js';

const RETRY_DELAYS_MS = [3_000, 5_000, 10_000, 30_000, 60_000, 120_000];
const MAX_ATTEMPTS = RETRY_DELAYS_MS.length;

export class Worker {
	private timer: NodeJS.Timeout | null = null;
	private running = false;

	constructor(
		private repos: Repos,
		private config: Config,
		private getAccountThumbprint: (accountId: string) => string | null,
		private dnsRegistry?: DnsProviderRegistry,
	) {}

	start(): void {
		if (this.timer) return;
		// Cleanup-on-restart: any placements we left behind get torn down so
		// the DNS zone stays clean even after a crash. Done before the first
		// tick so we never re-publish on top of stale records.
		this.sweepStalePlacementsOnStartup().catch(() => {
			/* swallowed — logging happens via audit */
		});
		this.timer = setInterval(() => {
			if (this.running) return;
			this.running = true;
			this.tick().finally(() => (this.running = false));
		}, 1_500);
	}

	stop(): void {
		if (this.timer) clearInterval(this.timer);
		this.timer = null;
	}

	private async sweepStalePlacementsOnStartup(): Promise<void> {
		const open = this.repos.listOpenPlacements();
		if (!open.length || !this.dnsRegistry) return;
		for (const p of open) {
			// We don't know the provider object; the dispatcher will give us
			// the right one based on the record name.
			const trimmed = p.record_name.startsWith('_acme-challenge.')
				? p.record_name.slice('_acme-challenge.'.length)
				: p.record_name;
			const prov = this.dnsRegistry.pickFor(trimmed);
			if (!prov) continue;
			try {
				await prov.cleanup({name: p.record_name, value: p.record_value});
			} catch {
				/* idempotent providers tolerate this */
			}
			this.repos.markPlacementCleaned(p.id);
			this.repos.audit({
				actorType: 'system',
				action: 'dns.cleanup.recovery',
				target: p.challenge_id,
				details: {name: p.record_name, provider: p.provider_label},
			});
		}
	}

	private async tick(): Promise<void> {
		const due = this.repos.dueChallenges(nowIso(), 20);
		for (const c of due) {
			await this.runOne(c.id);
		}
		this.repos.purgeNonces();
	}

	private async runOne(challengeId: string): Promise<void> {
		const c = this.repos.getChallenge(challengeId);
		if (!c || c.status !== 'processing') return;
		const authz = this.repos.getAuthz(c.authz_id);
		if (!authz) return;
		const orderRow = this.repos.db
			.prepare('SELECT account_id, dns_placement FROM orders WHERE id=?')
			.get(authz.order_id) as {account_id: string; dns_placement: string | null} | undefined;
		if (!orderRow) return;
		const thumbprint = this.getAccountThumbprint(orderRow.account_id);
		if (!thumbprint) return;
		const serverManaged =
			orderRow.dns_placement === 'server-managed' && c.type === 'dns-01' && !!this.dnsRegistry;

		// Server-managed: publish TXT before validating, idempotently. If place()
		// throws, the challenge fails immediately with a clear secutor-prefixed
		// problem type — no point retrying a provider that's broken.
		if (serverManaged) {
			const already = this.repos.listPlacementsForChallenge(c.id);
			if (already.length === 0) {
				const value = dns01TxtValue(c.token, thumbprint);
				const recordName = buildChallengeName(authz.identifier_value, !!authz.wildcard);
				const prov = this.dnsRegistry!.pickFor(authz.identifier_value);
				if (!prov) {
					return this.markInvalid(c.id, authz, {
						type: 'secutor:noDnsProvider',
						detail: `no provider for "${authz.identifier_value}"`,
					});
				}
				try {
					await prov.place({name: recordName, value});
					this.repos.insertPlacement({
						challengeId: c.id,
						recordName,
						recordValue: value,
						providerLabel: prov.label,
					});
					this.repos.audit({
						actorType: 'system',
						action: 'dns.place',
						target: c.id,
						details: {name: recordName, provider: prov.label},
					});
				} catch (e: any) {
					return this.markInvalid(c.id, authz, {
						type: 'secutor:dnsProviderError',
						detail: `place: ${e?.message ?? e}`,
					});
				}
			}
		}

		let result;
		try {
			if (c.type === 'dns-01') {
				result = await validateDns01({
					identifier: authz.identifier_value,
					wildcard: !!authz.wildcard,
					token: c.token,
					accountThumbprint: thumbprint,
					resolvers: this.config.resolvers,
				});
			} else {
				result = await validateHttp01({
					identifier: authz.identifier_value,
					token: c.token,
					accountThumbprint: thumbprint,
					port: this.config.challenges.http01Port,
				});
			}
		} catch (e: any) {
			result = {ok: false, detail: `Validator threw: ${e?.message ?? e}`};
		}

		const attempts = c.attempts + 1;
		if (result.ok) {
			this.repos.setChallengeResult(c.id, 'valid', null, nowIso(), null, attempts);
			this.repos.setAuthzStatus(authz.id, 'valid');
			this.repos.audit({
				actorType: 'system',
				action: 'challenge.valid',
				target: c.id,
				details: {type: c.type, identifier: authz.identifier_value},
			});
			if (serverManaged) await this.cleanupPlacementsFor(c.id);
			this.maybePromoteOrder(authz.order_id);
		} else if (attempts >= MAX_ATTEMPTS) {
			const err = {
				type: 'urn:ietf:params:acme:error:incorrectResponse',
				detail: result.detail ?? 'validation failed',
			};
			this.markInvalid(c.id, authz, err);
			if (serverManaged) await this.cleanupPlacementsFor(c.id);
		} else {
			const next = isoPlus(RETRY_DELAYS_MS[attempts - 1]!);
			this.repos.setChallengeResult(c.id, 'processing', null, null, next, attempts);
		}
	}

	private markInvalid(challengeId: string, authz: {id: string; order_id: string}, err: object): void {
		this.repos.setChallengeResult(challengeId, 'invalid', err, null, null, MAX_ATTEMPTS);
		this.repos.setAuthzStatus(authz.id, 'invalid');
		this.repos.setOrderStatus(authz.order_id, 'invalid', err);
		this.repos.audit({
			actorType: 'system',
			action: 'challenge.invalid',
			target: challengeId,
			details: err,
		});
	}

	private async cleanupPlacementsFor(challengeId: string): Promise<void> {
		if (!this.dnsRegistry) return;
		for (const p of this.repos.listPlacementsForChallenge(challengeId)) {
			const trimmed = p.record_name.startsWith('_acme-challenge.')
				? p.record_name.slice('_acme-challenge.'.length)
				: p.record_name;
			const prov = this.dnsRegistry.pickFor(trimmed);
			if (!prov) continue;
			try {
				await prov.cleanup({name: p.record_name, value: p.record_value});
			} catch {
				/* providers are idempotent */
			}
			this.repos.markPlacementCleaned(p.id);
			this.repos.audit({
				actorType: 'system',
				action: 'dns.cleanup',
				target: challengeId,
				details: {name: p.record_name, provider: p.provider_label},
			});
		}
	}

	private maybePromoteOrder(orderId: string): void {
		const authzs = this.repos.listAuthzByOrder(orderId);
		if (authzs.every(a => a.status === 'valid')) {
			const o = this.repos.getOrder(orderId);
			if (o && o.status === 'pending') {
				this.repos.setOrderStatus(orderId, 'ready');
			}
		}
	}
}
