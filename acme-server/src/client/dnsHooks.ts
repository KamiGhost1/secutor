// DNS-01 record placement strategies. Each "hook" knows how to publish and
// later remove a TXT record. v1 ships with `manual` (prompt the operator) and
// `script` (run an arbitrary shell command). RFC 2136 / cloud providers can be
// added by implementing the same interface.

import {execFile, spawn} from 'child_process';
import {createInterface} from 'readline';
import fs from 'fs';

export type DnsHook = {
	place(opts: {name: string; value: string}): Promise<void>;
	cleanup(opts: {name: string; value: string}): Promise<void>;
};

export const manualHook: DnsHook = {
	async place({name, value}) {
		console.log(`\n  ↪ Please publish a TXT record:`);
		console.log(`      Name:  ${name}`);
		console.log(`      Value: ${value}\n`);
		await waitForEnter('   Press Enter when the record is live (and DNS propagation done)... ');
	},
	async cleanup({name}) {
		console.log(`\n  ↪ You may now remove TXT record at ${name}`);
	},
};

function waitForEnter(prompt: string): Promise<void> {
	return new Promise(resolve => {
		const rl = createInterface({input: process.stdin, output: process.stdout});
		rl.question(prompt, () => {
			rl.close();
			resolve();
		});
	});
}

/**
 * Runs an arbitrary script with these env vars:
 *   ACME_ACTION=place|cleanup
 *   ACME_RECORD_NAME=<full name, e.g. _acme-challenge.foo.lan>
 *   ACME_RECORD_VALUE=<TXT value>
 *
 * Useful for wiring up nsupdate, cloud-provider CLIs, etc.
 */
/**
 * RFC 2136 dynamic update via `nsupdate`. Requires the `nsupdate` binary
 * (from bind-tools / bind9-utils / dnsutils package, depending on distro) and
 * a TSIG key file written in the BIND keyfile format:
 *
 *   key "acme-update." {
 *     algorithm hmac-sha256;
 *     secret "base64==";
 *   };
 *
 * Options:
 *   server:  DNS server IP that owns the zone (and accepts dynamic updates)
 *   zone:    the zone we're updating (e.g. "lan.")
 *   ttl:     TTL for the TXT record (default 60)
 *   keyFile: path to TSIG keyfile
 *   nsupdatePath: override binary (default: "nsupdate")
 */
export function rfc2136Hook(opts: {
	server: string;
	zone: string;
	keyFile: string;
	ttl?: number;
	nsupdatePath?: string;
}): DnsHook {
	if (!fs.existsSync(opts.keyFile)) {
		throw new Error(`rfc2136Hook: key file not found: ${opts.keyFile}`);
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
		async place({name, value}) {
			const fqdn = name.endsWith('.') ? name : name + '.';
			await runUpdate([`update add ${fqdn} ${ttl} TXT "${value}"`]);
			// Best-effort: wait one TTL for propagation on secondaries.
			await new Promise(r => setTimeout(r, Math.min(ttl, 5) * 1000));
		},
		async cleanup({name, value}) {
			const fqdn = name.endsWith('.') ? name : name + '.';
			// Remove only the specific record value (in case multiple TXTs coexist).
			await runUpdate([`update delete ${fqdn} TXT "${value}"`]);
		},
	};
}

export function scriptHook(scriptPath: string): DnsHook {
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
				(err, stdout, stderr) => {
					if (stdout) process.stdout.write(stdout);
					if (stderr) process.stderr.write(stderr);
					if (err) reject(new Error(`${scriptPath} (${action}) failed: ${err.message}`));
					else resolve();
				},
			);
		});
	return {
		place: ({name, value}) => run('place', name, value),
		cleanup: ({name, value}) => run('cleanup', name, value),
	};
}
