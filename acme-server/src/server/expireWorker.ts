// Background tick that promotes overdue ACME orders and authorizations into
// the 'expired' state, so admin/stats endpoints (and the regular ACME poll
// loop) see them correctly. Cheap WHERE-clause updates running on a fixed
// interval; safe to run alongside the regular challenge worker.

import type {Repos} from './repos.js';

export class ExpireWorker {
	private timer: NodeJS.Timeout | null = null;

	constructor(private repos: Repos, private intervalMs = 60_000) {}

	start(): void {
		if (this.timer) return;
		// Fire immediately so a freshly-restarted server doesn't show stale
		// 'pending' rows that should have expired during the downtime.
		this.tick();
		this.timer = setInterval(() => this.tick(), this.intervalMs);
		// Don't keep the process alive just for this tick.
		this.timer.unref?.();
	}

	stop(): void {
		if (this.timer) clearInterval(this.timer);
		this.timer = null;
	}

	tick(): {orders: number; authz: number} {
		try {
			const orders = this.repos.expireDueOrders();
			const authz = this.repos.expireDueAuthz();
			return {orders, authz};
		} catch {
			return {orders: 0, authz: 0};
		}
	}
}
