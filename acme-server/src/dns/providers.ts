// Shared DNS-01 record placement strategies. Same interface drives the
// client-side "place a TXT before validation" path and the server-side
// "publish TXT for clients who asked for server-managed DNS" path
// (acme-server/src/server/dnsProviders.ts).
//
// A provider is just `{place, cleanup}` operating on a (fqdn, value) tuple.
// Both ops are idempotent — `place` may be called twice and `cleanup`
// must succeed on a record that doesn't exist (used during restart recovery).

import {execFile, spawn} from 'child_process';
import fs from 'fs';

export type DnsRecord = {
	/** Full DNS name with no trailing dot, e.g. _acme-challenge.foo.lan */
	name: string;
	/** TXT value (base64url of SHA-256(token + . + thumbprint), per RFC 8555 §8.4) */
	value: string;
};

export type DnsProvider = {
	place(rec: DnsRecord): Promise<void>;
	cleanup(rec: DnsRecord): Promise<void>;
	/** Name used in logs / audit. */
	label: string;
};

/* ─────────────────── rfc2136 (BIND nsupdate) ─────────────────── */

export type Rfc2136Opts = {
	server: string;
	zone: string;
	keyFile: string;
	ttl?: number;
	nsupdatePath?: string;
};

export function rfc2136Provider(opts: Rfc2136Opts): DnsProvider {
	if (!fs.existsSync(opts.keyFile)) {
		throw new Error(`rfc2136Provider: key file not found: ${opts.keyFile}`);
	}
	const bin = opts.nsupdatePath ?? 'nsupdate';
	const ttl = opts.ttl ?? 60;
	const zone = opts.zone.endsWith('.') ? opts.zone : opts.zone + '.';

	const runUpdate = (commands: string[]): Promise<void> =>
		new Promise((resolve, reject) => {
			const args = ['-k', opts.keyFile, '-v'];
			const proc = spawn(bin, args, {stdio: ['pipe', 'pipe', 'pipe']});
			let stderr = '';
			proc.stderr.on('data', d => (stderr += d.toString()));
			proc.on('error', err => reject(new Error(`nsupdate failed to start: ${err.message}`)));
			proc.on('close', code => {
				if (code === 0) resolve();
				else reject(new Error(`nsupdate exited ${code}: ${stderr.trim()}`));
			});
			const script = [`server ${opts.server}`, `zone ${zone}`, ...commands, 'send', ''].join('\n');
			proc.stdin.write(script);
			proc.stdin.end();
		});

	return {
		label: `rfc2136(${opts.server} ${zone})`,
		async place({name, value}) {
			const fqdn = name.endsWith('.') ? name : name + '.';
			await runUpdate([`update add ${fqdn} ${ttl} TXT "${value}"`]);
			// Best-effort: wait one TTL for propagation on secondaries.
			await new Promise(r => setTimeout(r, Math.min(ttl, 5) * 1000));
		},
		async cleanup({name, value}) {
			const fqdn = name.endsWith('.') ? name : name + '.';
			try {
				// Delete only this specific record value — other concurrent challenges
				// for the same FQDN keep working.
				await runUpdate([`update delete ${fqdn} TXT "${value}"`]);
			} catch (err: any) {
				// nsupdate returning REFUSED/NOTAUTH on a missing record is acceptable
				// for cleanup-on-restart. Bubble other failures.
				const msg = String(err?.message ?? err);
				if (!/NXRRSET|NXDOMAIN|REFUSED/.test(msg)) throw err;
			}
		},
	};
}

/* ─────────────────── script ─────────────────── */

/**
 * Run an external script with env vars ACME_ACTION (place|cleanup),
 * ACME_RECORD_NAME, ACME_RECORD_VALUE. Cheap escape hatch for
 * cloud-provider CLIs without writing a TypeScript plugin.
 */
export function scriptProvider(scriptPath: string): DnsProvider {
	const run = (action: 'place' | 'cleanup', name: string, value: string): Promise<void> =>
		new Promise((resolve, reject) => {
			execFile(
				scriptPath,
				[],
				{
					env: {
						...process.env,
						ACME_ACTION: action,
						ACME_RECORD_NAME: name,
						ACME_RECORD_VALUE: value,
					},
				},
				(err, _stdout, stderr) => {
					if (err) reject(new Error(`${scriptPath} ${action}: ${err.message} ${stderr || ''}`.trim()));
					else resolve();
				},
			);
		});
	return {
		label: `script(${scriptPath})`,
		place: ({name, value}) => run('place', name, value),
		cleanup: ({name, value}) => run('cleanup', name, value),
	};
}

/* ─────────────────── in-memory (tests + manual fallback) ─────────────────── */

/**
 * Trivial provider that keeps records in a Map. Used by tests to simulate
 * a DNS world without spawning processes, and by `auto-dns mode = false`
 * sanity checks.
 */
export function memoryProvider(label = 'memory'): DnsProvider & {
	readonly records: Map<string, Set<string>>;
} {
	const records = new Map<string, Set<string>>();
	return {
		label,
		records,
		async place({name, value}) {
			const set = records.get(name) ?? new Set<string>();
			set.add(value);
			records.set(name, set);
		},
		async cleanup({name, value}) {
			const set = records.get(name);
			if (!set) return; // idempotent
			set.delete(value);
			if (set.size === 0) records.delete(name);
		},
	};
}
