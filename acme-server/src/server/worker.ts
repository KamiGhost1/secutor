// Background worker. Polls processing-state challenges, validates them, and
// flips their parent authorization + order accordingly.

import type {Repos} from './repos.js';
import type {Config} from './config.js';
import {validateDns01, validateHttp01} from './challenges.js';
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
	) {}

	start(): void {
		if (this.timer) return;
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
		const order = this.repos.db
			.prepare('SELECT account_id FROM orders WHERE id=?')
			.get(authz.order_id) as {account_id: string} | undefined;
		if (!order) return;
		const thumbprint = this.getAccountThumbprint(order.account_id);
		if (!thumbprint) return;

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
			this.maybePromoteOrder(authz.order_id);
		} else if (attempts >= MAX_ATTEMPTS) {
			const err = {
				type: 'urn:ietf:params:acme:error:incorrectResponse',
				detail: result.detail ?? 'validation failed',
			};
			this.repos.setChallengeResult(c.id, 'invalid', err, null, null, attempts);
			this.repos.setAuthzStatus(authz.id, 'invalid');
			this.repos.setOrderStatus(authz.order_id, 'invalid', err);
			this.repos.audit({
				actorType: 'system',
				action: 'challenge.invalid',
				target: c.id,
				details: err,
			});
		} else {
			const next = isoPlus(RETRY_DELAYS_MS[attempts - 1]!);
			this.repos.setChallengeResult(c.id, 'processing', null, null, next, attempts);
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
