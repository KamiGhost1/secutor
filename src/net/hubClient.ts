// Minimal mTLS-aware HTTPS client for talking to a hub's admin API.
// Two layered guarantees beyond standard https.request:
//
//   1. Pin: rejectUnauthorized:false, then verify the peer cert SHA-256
//      against the hub's recorded fingerprint. This makes the system trust
//      store irrelevant; only the on-disk pin matters.
//   2. Identity: the resolved client cert + key are attached to every
//      request. Encrypted-key prompting happens upstream in TUI/CLI; this
//      module only consumes already-plaintext PEMs.

import crypto from 'crypto';
import https from 'https';
import type {TLSSocket} from 'tls';
import {URL} from 'url';
import type {Hub} from '../storage/hubStore.js';
import type {ResolvedIdentity} from './clientIdentity.js';

export type HubRequest = {
	method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
	path: string; // already URL-escaped
	body?: any; // serialized as JSON when present
	headers?: Record<string, string>;
	timeoutMs?: number;
};

export type HubResponse<T = any> = {
	status: number;
	body: T;
	headers: Record<string, string | string[] | undefined>;
};

export class HubError extends Error {
	constructor(public code: string, message: string, public status?: number) {
		super(message);
		this.name = 'HubError';
	}
}

export type HubClientHandle = {
	hub: Hub;
	request<T = any>(req: HubRequest): Promise<HubResponse<T>>;
	close(): void;
};

export function makeHubClient(hub: Hub, identity: ResolvedIdentity): HubClientHandle {
	const base = new URL(hub.baseUrl);
	const wantFp = hub.serverFingerprint.toLowerCase();

	// We need a fresh agent per (hub, identity) tuple so socket reuse doesn't
	// accidentally span pins. Cheap: agent only holds a few sockets.
	const agent = new https.Agent({
		keepAlive: true,
		rejectUnauthorized: false, // we pin instead
		cert: identity.certPem,
		key: identity.keyPem,
	});

	function request<T>(opts: HubRequest): Promise<HubResponse<T>> {
		const data = opts.body != null ? Buffer.from(JSON.stringify(opts.body)) : null;
		const headers: Record<string, string> = {
			accept: 'application/json',
			...(opts.headers ?? {}),
		};
		if (data) {
			headers['content-type'] = 'application/json';
			headers['content-length'] = String(data.length);
		}
		return new Promise<HubResponse<T>>((resolve, reject) => {
			const r = https.request(
				{
					agent,
					method: opts.method,
					host: base.hostname,
					port: base.port ? parseInt(base.port, 10) : 443,
					path: joinPath(base.pathname, opts.path),
					servername: base.hostname,
					headers,
					timeout: opts.timeoutMs ?? 10_000,
				},
				res => {
					const chunks: Buffer[] = [];
					res.on('data', c => chunks.push(c));
					res.on('end', () => {
						const text = Buffer.concat(chunks).toString('utf8');
						let body: any = text;
						try {
							body = text ? JSON.parse(text) : null;
						} catch {
							/* leave as text */
						}
						resolve({
							status: res.statusCode ?? 0,
							body: body as T,
							headers: res.headers,
						});
					});
				},
			);
			r.on('socket', sock => {
				sock.on('secureConnect', () => {
					try {
						const tls = sock as TLSSocket;
						const peer = tls.getPeerCertificate(true);
						if (!peer || !peer.raw) {
							r.destroy(new HubError('no-peer-cert', 'server did not present a certificate'));
							return;
						}
						const fp = crypto.createHash('sha256').update(peer.raw).digest('hex');
						if (fp !== wantFp) {
							r.destroy(
								new HubError(
									'cert-pin-mismatch',
									`server cert fingerprint ${fp.slice(0, 12)}… ≠ pinned ${wantFp.slice(0, 12)}…`,
								),
							);
						}
					} catch (e) {
						r.destroy(e as Error);
					}
				});
			});
			r.on('timeout', () => {
				r.destroy(new HubError('timeout', `request to ${base.host}${opts.path} timed out`));
			});
			r.on('error', err => {
				if (err instanceof HubError) return reject(err);
				const code = (err as any).code as string | undefined;
				reject(new HubError(code ?? 'request-failed', err.message ?? String(err)));
			});
			if (data) r.write(data);
			r.end();
		});
	}

	return {
		hub,
		request,
		close: () => agent.destroy(),
	};
}

function joinPath(base: string, p: string): string {
	const b = base.endsWith('/') ? base.slice(0, -1) : base;
	const s = p.startsWith('/') ? p : `/${p}`;
	return b + s;
}

/**
 * One-shot anonymous TLS to fetch the server's cert and compute its
 * fingerprint. Used during AddHub flow (TOFU). Does NOT send a client cert.
 */
export function probeServerFingerprint(baseUrl: string, timeoutMs = 5000): Promise<string> {
	const base = new URL(baseUrl);
	return new Promise((resolve, reject) => {
		const r = https.request(
			{
				method: 'GET',
				host: base.hostname,
				port: base.port ? parseInt(base.port, 10) : 443,
				path: '/admin/v1/auth-policy', // intentionally a path that may 404; we only need the handshake
				servername: base.hostname,
				rejectUnauthorized: false,
				timeout: timeoutMs,
			},
			res => {
				try {
					const tls = res.socket as TLSSocket;
					const peer = tls.getPeerCertificate(true);
					if (!peer?.raw) return reject(new HubError('no-peer-cert', 'no server cert'));
					const fp = crypto.createHash('sha256').update(peer.raw).digest('hex');
					res.resume();
					res.on('end', () => resolve(fp));
				} catch (e) {
					reject(e);
				}
			},
		);
		r.on('timeout', () => r.destroy(new HubError('timeout', 'probe timed out')));
		r.on('error', err => reject(new HubError('probe-failed', err.message)));
		r.end();
	});
}
