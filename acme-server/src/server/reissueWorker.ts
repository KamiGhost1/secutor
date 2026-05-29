// Background worker that re-signs existing leaf certificates with the
// currently-active CA key. Used after a CA promote so leaves whose chain
// included the now-superseded intermediate get fresh signatures.
//
// Strategy: keep the client's public key (SPKI) and SANs/CN/validity from
// the existing cert, swap in the new CA-signed bytes. Same row id, new
// `pem` + `serial_hex`. Clients fetching `GET /cert/:id` immediately see
// the new bytes; for ARI-aware clients, /renewalInfo will return a "renew
// now" hint until they pull the update.
//
// Rate-limit: simple token-bucket-ish — we wait `1000/ratePerSec` ms
// between items. Cheap, predictable, no extra deps.

import crypto from 'crypto';
import type {Repos, ReissueJobRow} from './repos.js';
import type {CaMaterial} from './contextLoader.js';
import {issueLeaf} from './signer.js';

export type ReissueScope = 'all-active' | 'by-account' | 'by-identifier-pattern';

export type StartJobOpts = {
	scope: ReissueScope;
	accountIds?: string[];
	identifierPattern?: string;
	ratePerSec?: number;
	actorFp?: string | null;
};

export class ReissueWorker {
	private timer: NodeJS.Timeout | null = null;
	private running = new Set<string>(); // job ids currently being driven
	private cancelled = new Set<string>();

	constructor(
		private repos: Repos,
		private ca: CaMaterial, // live reference — Object.assign'd by promote
	) {}

	start(): void {
		if (this.timer) return;
		this.timer = setInterval(() => this.tick(), 1000);
		this.timer.unref?.();
	}

	stop(): void {
		if (this.timer) clearInterval(this.timer);
		this.timer = null;
	}

	cancel(jobId: string): boolean {
		const job = this.repos.getReissueJob(jobId);
		if (!job || job.status !== 'running') return false;
		this.cancelled.add(jobId);
		this.repos.finishReissueJob(jobId, 'cancelled');
		return true;
	}

	/** Create the job + persist items. Returns the job row immediately;
	 * processing happens in the background on subsequent ticks. */
	startJob(opts: StartJobOpts): ReissueJobRow {
		const ratePerSec = Math.max(1, Math.min(opts.ratePerSec ?? 10, 200));
		const targets = this.collectTargets(opts);
		return this.repos.createReissueJob({
			scope: opts.scope,
			params: {
				accountIds: opts.accountIds,
				identifierPattern: opts.identifierPattern,
			},
			ratePerSec,
			certIds: targets.map(c => c.id),
			actorFp: opts.actorFp ?? null,
		});
	}

	private collectTargets(opts: StartJobOpts) {
		if (opts.scope === 'all-active') return this.repos.listActiveCerts();
		if (opts.scope === 'by-account') {
			const ids = opts.accountIds ?? [];
			const out = [];
			for (const a of ids) out.push(...this.repos.listActiveCertsForAccount(a));
			return out;
		}
		// by-identifier-pattern — match identifier_value in authorizations →
		// the issuing order → the cert. We approximate by filtering listActiveCerts
		// by examining each cert's order's authz identifiers.
		const pat = (opts.identifierPattern ?? '*').toLowerCase();
		const all = this.repos.listActiveCerts();
		return all.filter(c => {
			const authz = this.repos.db
				.prepare(
					`SELECT identifier_value, wildcard FROM authorizations WHERE order_id=?`,
				)
				.all(c.order_id) as Array<{identifier_value: string; wildcard: number}>;
			return authz.some(a => identifierMatches(a.identifier_value, !!a.wildcard, pat));
		});
	}

	async tick(): Promise<void> {
		const jobs = this.repos.listReissueJobs({status: 'running'});
		for (const j of jobs) {
			if (this.running.has(j.id) || this.cancelled.has(j.id)) continue;
			this.running.add(j.id);
			this.driveJob(j).finally(() => this.running.delete(j.id));
		}
	}

	private async driveJob(job: ReissueJobRow): Promise<void> {
		const delayMs = Math.floor(1000 / job.rate_per_sec);
		const pending = this.repos.listReissueJobItems(job.id, 'pending');
		if (!pending.length) {
			this.repos.finishReissueJob(job.id, 'done');
			return;
		}
		for (const item of pending) {
			if (this.cancelled.has(job.id)) return;
			try {
				this.resignOne(item.cert_id);
				this.repos.updateReissueItem(item.id, 'done');
				this.repos.incReissueJobCounter(job.id, 'done');
				this.repos.audit({
					actorType: 'system',
					action: 'cert.resign',
					target: item.cert_id,
					details: {job_id: job.id},
				});
			} catch (e: any) {
				this.repos.updateReissueItem(item.id, 'failed', String(e?.message ?? e));
				this.repos.incReissueJobCounter(job.id, 'failed');
			}
			if (delayMs > 0) await new Promise(r => setTimeout(r, delayMs));
		}
		// Finalize status
		const fresh = this.repos.getReissueJob(job.id);
		if (fresh && fresh.status === 'running') {
			this.repos.finishReissueJob(
				job.id,
				fresh.failed > 0 && fresh.done === 0 ? 'failed' : 'done',
			);
		}
	}

	private resignOne(certId: string): void {
		const row = this.repos.getCert(certId);
		if (!row) throw new Error(`cert ${certId} disappeared`);
		const cert = new crypto.X509Certificate(row.pem);
		// Extract SPKI as PEM — the client's public key, preserved across resign.
		const spkiPem = cert.publicKey.export({type: 'spki', format: 'pem'}) as string;
		// SANs come back as the comma-separated string "DNS:foo.lan, DNS:bar.lan"
		const sans = (cert.subjectAltName ?? '')
			.split(',')
			.map(s => s.trim())
			.filter(s => s.startsWith('DNS:'))
			.map(s => s.slice('DNS:'.length));
		const cn = subjectCN(cert.subject);
		const notBefore = new Date(cert.validFrom);
		const notAfter = new Date(cert.validTo);

		const out = issueLeaf({
			caCertPem: this.ca.certPem,
			caKeyPem: this.ca.keyPem,
			subjectPublicKeyPem: spkiPem,
			commonName: cn,
			sans,
			notBefore,
			notAfter,
		});
		this.repos.replaceCertPem(row.id, {
			pem: out.certPem,
			serialHex: out.serialHex,
			notBefore: out.notBefore.toISOString(),
			notAfter: out.notAfter.toISOString(),
		});
	}
}

function subjectCN(subject: string): string {
	// `subject` is "CN=foo.lan\nO=Acme" or just "CN=foo.lan" depending on platform.
	const lines = subject.split(/[\n,]/).map(s => s.trim());
	for (const l of lines) {
		if (/^CN=/i.test(l)) return l.slice(3).trim();
	}
	return '';
}

function identifierMatches(value: string, wildcard: boolean, pattern: string): boolean {
	const v = (wildcard ? '*.' + value : value).toLowerCase();
	if (pattern === '*') return true;
	if (pattern.startsWith('*.')) {
		const suf = pattern.slice(2);
		return v === suf || v.endsWith('.' + suf);
	}
	return v === pattern;
}
