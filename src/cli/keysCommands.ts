// Non-interactive `secutor keys` subcommands — export, import, transfer.
// Pure CLI: they open a context, do their work, close it. The TUI uses the
// same underlying repoBridge / keyBundle modules.

import fs from 'fs';
import path from 'path';
import {
	buildPlainBundle,
	buildEncryptedBundle,
	parseBundle,
	isBundleFile,
	BundleManifest,
} from '../transfer/keyBundle.js';
import {
	exportCert,
	exportCertSubtree,
	exportSshKey,
	exportProfile,
	importBundle,
	ImportSummary,
} from '../transfer/repoBridge.js';
import {openContext, closeContext} from '../storage/db.js';
import {certRepo, sshKeyRepo, profileRepo} from '../storage/repos.js';
import {
	contextExists,
	getContextMeta,
	verifyContextPassword,
} from '../storage/contextStore.js';

/* ────────── argv parsing — minimal, mirrors commands.ts ────────── */

type ParsedArgs = {
	positional: string[];
	flags: Record<string, string | true>;
};

function parseArgs(argv: string[]): ParsedArgs {
	const positional: string[] = [];
	const flags: Record<string, string | true> = {};
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i]!;
		if (a === '--') {
			positional.push(...argv.slice(i + 1));
			break;
		}
		if (a.startsWith('--')) {
			const eq = a.indexOf('=');
			if (eq >= 0) {
				flags[a.slice(2, eq)] = a.slice(eq + 1);
			} else {
				const key = a.slice(2);
				const next = argv[i + 1];
				if (next != null && next !== '--' && !next.startsWith('--')) {
					flags[key] = next;
					i++;
				} else {
					flags[key] = true;
				}
			}
		} else {
			positional.push(a);
		}
	}
	return {positional, flags};
}

function getFlag(args: ParsedArgs, ...names: string[]): string | undefined {
	for (const n of names) {
		const v = args.flags[n];
		if (typeof v === 'string') return v;
	}
	return undefined;
}

function hasFlag(args: ParsedArgs, ...names: string[]): boolean {
	return names.some(n => args.flags[n] !== undefined);
}

class UsageError extends Error {}

let stdinConsumed = false;
function readStdinLine(): string {
	if (stdinConsumed) {
		throw new UsageError('Cannot read more than one password from stdin per invocation');
	}
	stdinConsumed = true;
	const chunks: Buffer[] = [];
	const buf = Buffer.alloc(4096);
	while (true) {
		let n: number;
		try {
			n = fs.readSync(0, buf, 0, buf.length, null);
		} catch (err: any) {
			if (err && err.code === 'EAGAIN') continue;
			throw err;
		}
		if (n <= 0) break;
		const slice = buf.subarray(0, n);
		const nl = slice.indexOf(0x0a);
		if (nl >= 0) {
			chunks.push(slice.subarray(0, nl));
			break;
		}
		chunks.push(Buffer.from(slice));
	}
	let line = Buffer.concat(chunks).toString('utf8');
	if (line.endsWith('\r')) line = line.slice(0, -1);
	return line;
}

function promptHidden(prompt: string): string {
	if (!process.stdin.isTTY) {
		throw new UsageError(
			`${prompt}: no TTY available; pass a password via flag or use the -stdin variant`,
		);
	}
	process.stderr.write(prompt);
	const fd = 0;
	const wasRaw = process.stdin.isRaw;
	if (!wasRaw) {
		try {
			process.stdin.setRawMode(true);
		} catch {}
	}
	const chars: string[] = [];
	const buf = Buffer.alloc(1);
	try {
		while (true) {
			const n = fs.readSync(fd, buf, 0, 1, null);
			if (n <= 0) break;
			const c = buf[0]!;
			if (c === 0x0a || c === 0x0d) break;
			if (c === 0x03) {
				process.stderr.write('\n');
				process.exit(130);
			}
			if (c === 0x7f || c === 0x08) {
				if (chars.length > 0) chars.pop();
				continue;
			}
			chars.push(String.fromCharCode(c));
		}
	} finally {
		if (!wasRaw) {
			try {
				process.stdin.setRawMode(false);
			} catch {}
		}
		process.stderr.write('\n');
	}
	return chars.join('');
}

function resolveOptionalPassword(
	flagValue: string | undefined,
	stdin: boolean,
	label: string,
): string | null {
	if (flagValue !== undefined) return flagValue;
	if (stdin) return readStdinLine();
	return null;
}

function resolveContextPassword(
	contextName: string,
	flagValue: string | undefined,
	stdin: boolean,
): string | null {
	const meta = getContextMeta(contextName);
	if (!meta) throw new UsageError(`Context "${contextName}" not found`);
	if (!meta.encrypted) return null;
	let pw = resolveOptionalPassword(flagValue, stdin, `Password for "${contextName}"`);
	if (pw == null) pw = promptHidden(`Password for "${contextName}": `);
	if (!verifyContextPassword(contextName, pw)) {
		throw new UsageError(`Incorrect password for context "${contextName}"`);
	}
	return pw;
}

function openCtx(
	contextName: string,
	pwFlag: string | undefined,
	pwStdin: boolean,
): void {
	if (!contextExists(contextName)) {
		throw new UsageError(`Context "${contextName}" does not exist`);
	}
	const pw = resolveContextPassword(contextName, pwFlag, pwStdin);
	openContext(contextName, pw);
}

/* ────────── help text ────────── */

export const KEYS_HELP = `Usage:
  secutor keys export <name>     [--kind cert|ssh|profile] [options]
  secutor keys import <file.skb> [options]
  secutor keys transfer <name>   --from <ctxA> --to <ctxB> [options]

Common options:
  --context <name>             Context to read from (export) or write to (import).
                               Required for export/import. For transfer use --from/--to.
  --context-password <pw>      Pass the context password literally.
  --context-password-stdin     Read the context password from stdin (one line).

export:
  --kind cert|ssh|profile      What to export (default: cert).
  --out <path>                 Output file (default: <name>.skb in cwd).
  --subtree                    For a CA cert: include all descendants.
  --include-parents            For a leaf: include the issuer chain.
  --encrypt                    Wrap the bundle in a password-encrypted envelope.
  --bundle-password <pw>       Password for the envelope. Prompted if --encrypt and absent.
  --bundle-password-stdin      Read the envelope password from stdin.

import:
  --rename <name>              Override the manifest's primary name.
  --overwrite-key              Replace an existing private key in the target on duplicate.
  --bundle-password <pw>       Required if the bundle is encrypted.
  --bundle-password-stdin      Read the envelope password from stdin.

transfer:
  --from <ctxA>                Source context (uses --from-password / --from-password-stdin).
  --to <ctxB>                  Destination context (uses --to-password / --to-password-stdin).
  --kind cert|ssh|profile      What to transfer (default: cert).
  --subtree                    For CA: transfer the full subtree.
  --include-parents            For leaf: also carry the issuer chain.
  --rename <name>              Override the bundled primary name on insert.
  --overwrite-key              Replace target's empty/existing key on duplicate.

Exit codes:
  0 — success
  2 — usage error / I/O / wrong password / not found

Examples:
  # Export a leaf cert + its chain to ./mysvc.skb, encrypted with a passphrase.
  secutor keys export mysvc --context prod --include-parents --encrypt

  # Transfer an SSH key from dev to ops, asking for both contexts' passwords.
  secutor keys transfer deploy --from dev --to ops --kind ssh

  # Import a previously-exported bundle, renaming the primary entity.
  secutor keys import ./mysvc.skb --context ops --rename mysvc-2026
`;

/* ────────── helpers ────────── */

function defaultOutPath(name: string): string {
	const safe = name.replace(/[^a-zA-Z0-9._-]/g, '_');
	const stamp = new Date().toISOString().slice(0, 10);
	return path.resolve(`${safe}-${stamp}.skb`);
}

function findEntityId(name: string, kind: 'cert' | 'ssh' | 'profile'): number {
	if (kind === 'cert') {
		const row = certRepo.findByName(name);
		if (!row) throw new UsageError(`No certificate named "${name}" in context`);
		return row.id;
	}
	if (kind === 'ssh') {
		const row = sshKeyRepo.findByName(name);
		if (!row) throw new UsageError(`No SSH key named "${name}" in context`);
		return row.id;
	}
	if (kind === 'profile') {
		const row = profileRepo.list().find(p => p.name === name);
		if (!row) throw new UsageError(`No profile named "${name}" in context`);
		return row.id;
	}
	throw new UsageError(`Unknown kind: ${kind}`);
}

function buildBundleForEntity(
	name: string,
	kind: 'cert' | 'ssh' | 'profile',
	contextName: string,
	flags: {subtree?: boolean; includeParents?: boolean},
): {manifest: BundleManifest; payload: Buffer} {
	const id = findEntityId(name, kind);
	if (kind === 'cert') {
		const row = certRepo.findById(id)!;
		if (flags.subtree) {
			if (row.type !== 'ca') {
				throw new UsageError(`--subtree only applies to CA certs; "${name}" is ${row.type}`);
			}
			return exportCertSubtree(id, {contextName});
		}
		return exportCert(id, {contextName, includeParents: flags.includeParents});
	}
	if (kind === 'ssh') return exportSshKey(id, {contextName});
	return exportProfile(id, {contextName});
}

function bundleToBytes(
	manifest: BundleManifest,
	payload: Buffer,
	encryptOpts: {encrypt: boolean; password?: string},
): Buffer {
	if (encryptOpts.encrypt) {
		if (!encryptOpts.password) {
			throw new UsageError('Encryption requested but no password supplied');
		}
		return buildEncryptedBundle(manifest, payload, encryptOpts.password);
	}
	return buildPlainBundle(manifest, payload);
}

function summaryToString(s: ImportSummary): string {
	const lines: string[] = [];
	for (const r of s.inserted) {
		lines.push(`inserted ${r.kind} "${r.name}"${r.fingerprint ? ` (${r.fingerprint.slice(0, 12)}…)` : ''}`);
	}
	for (const r of s.updated) {
		lines.push(`updated  ${r.kind} "${r.name}" (filled in private key)`);
	}
	for (const r of s.duplicates) {
		lines.push(`skipped  ${r.kind} "${r.name}" (already present, same fingerprint)`);
	}
	for (const c of s.conflicts) {
		lines.push(`note     ${c.reason}`);
	}
	if (s.issuerRelinks) {
		lines.push(`relinked ${s.issuerRelinks} issuer reference${s.issuerRelinks > 1 ? 's' : ''}`);
	}
	return lines.join('\n');
}

/* ────────── command bodies ────────── */

async function cmdExport(args: ParsedArgs): Promise<number> {
	const name = args.positional[1];
	if (!name) throw new UsageError('Usage: secutor keys export <name> [options]');
	const contextName = getFlag(args, 'context');
	if (!contextName) throw new UsageError('--context is required');

	const kind = (getFlag(args, 'kind') ?? 'cert') as 'cert' | 'ssh' | 'profile';
	if (!['cert', 'ssh', 'profile'].includes(kind)) {
		throw new UsageError(`Unknown --kind: ${kind}`);
	}
	const subtree = !!args.flags['subtree'];
	const includeParents = !!args.flags['include-parents'];
	const encrypt = !!args.flags['encrypt'];
	const out = getFlag(args, 'out') ?? defaultOutPath(name);

	openCtx(contextName, getFlag(args, 'context-password'), hasFlag(args, 'context-password-stdin'));
	let manifest: BundleManifest;
	let payload: Buffer;
	try {
		const built = buildBundleForEntity(name, kind, contextName, {subtree, includeParents});
		manifest = built.manifest;
		payload = built.payload;
	} finally {
		closeContext();
	}

	let bundlePw: string | undefined;
	if (encrypt) {
		bundlePw =
			resolveOptionalPassword(
				getFlag(args, 'bundle-password'),
				hasFlag(args, 'bundle-password-stdin'),
				'Bundle password',
			) ?? promptHidden('Bundle password: ');
		if (!bundlePw) throw new UsageError('Empty bundle password rejected');
		const confirm =
			args.flags['bundle-password'] !== undefined ||
			args.flags['bundle-password-stdin'] !== undefined
				? bundlePw
				: promptHidden('Confirm bundle password: ');
		if (confirm !== bundlePw) throw new UsageError('Passwords do not match');
	}

	const bytes = bundleToBytes(manifest, payload, {encrypt, password: bundlePw});
	fs.writeFileSync(out, bytes, {mode: 0o600});
	process.stdout.write(
		`wrote ${kind} bundle "${name}" → ${out} (${bytes.length} bytes, ${
			encrypt ? 'encrypted' : 'plain'
		})\n`,
	);
	return 0;
}

async function cmdImport(args: ParsedArgs): Promise<number> {
	const filePath = args.positional[1];
	if (!filePath) throw new UsageError('Usage: secutor keys import <file.skb> [options]');
	const contextName = getFlag(args, 'context');
	if (!contextName) throw new UsageError('--context is required');

	const buf = fs.readFileSync(filePath);
	if (!isBundleFile(buf)) {
		throw new UsageError(`Not a secutor key bundle: ${filePath}`);
	}

	let bundlePw: string | undefined;
	// Quick variant peek: byte 10 = 0x45 means encrypted.
	if (buf[10] === 0x45) {
		bundlePw =
			resolveOptionalPassword(
				getFlag(args, 'bundle-password'),
				hasFlag(args, 'bundle-password-stdin'),
				'Bundle password',
			) ?? promptHidden('Bundle password: ');
	}
	const parsed = parseBundle(buf, bundlePw);

	openCtx(contextName, getFlag(args, 'context-password'), hasFlag(args, 'context-password-stdin'));
	let summary: ImportSummary;
	try {
		summary = importBundle(parsed, {
			rename: getFlag(args, 'rename'),
			overwriteKey: !!args.flags['overwrite-key'],
		});
	} finally {
		closeContext();
	}

	process.stdout.write(summaryToString(summary) + '\n');
	return 0;
}

async function cmdTransfer(args: ParsedArgs): Promise<number> {
	const name = args.positional[1];
	if (!name) throw new UsageError('Usage: secutor keys transfer <name> --from <ctx> --to <ctx>');
	const from = getFlag(args, 'from');
	const to = getFlag(args, 'to');
	if (!from || !to) throw new UsageError('--from and --to are required');
	if (from === to) throw new UsageError('--from and --to must be different contexts');

	const kind = (getFlag(args, 'kind') ?? 'cert') as 'cert' | 'ssh' | 'profile';
	const subtree = !!args.flags['subtree'];
	const includeParents = !!args.flags['include-parents'];

	openCtx(from, getFlag(args, 'from-password'), hasFlag(args, 'from-password-stdin'));
	let manifest: BundleManifest;
	let payload: Buffer;
	try {
		const built = buildBundleForEntity(name, kind, from, {subtree, includeParents});
		manifest = built.manifest;
		payload = built.payload;
	} finally {
		closeContext();
	}

	openCtx(to, getFlag(args, 'to-password'), hasFlag(args, 'to-password-stdin'));
	let summary: ImportSummary;
	try {
		summary = importBundle(
			{manifest, payload, encrypted: false},
			{rename: getFlag(args, 'rename'), overwriteKey: !!args.flags['overwrite-key']},
		);
	} finally {
		closeContext();
	}

	process.stdout.write(`transferred "${name}" ${from} → ${to}\n${summaryToString(summary)}\n`);
	return 0;
}

/* ────────── dispatcher ────────── */

export function isKeysCommand(argv: string[]): boolean {
	return argv[0] === 'keys';
}

export async function runKeysCommand(argv: string[]): Promise<number> {
	const args = parseArgs(argv);
	const sub = args.positional[0];
	const askedHelp = args.flags['help'] === true || args.flags['h'] === true;
	if (!sub || askedHelp) {
		process.stdout.write(KEYS_HELP);
		return askedHelp ? 0 : 2;
	}
	try {
		if (sub === 'export') return await cmdExport(args);
		if (sub === 'import') return await cmdImport(args);
		if (sub === 'transfer') return await cmdTransfer(args);
		throw new UsageError(`Unknown subcommand: keys ${sub}`);
	} catch (err: any) {
		try {
			closeContext();
		} catch {}
		if (err instanceof UsageError) {
			process.stderr.write(`error: ${err.message}\n`);
			return 2;
		}
		process.stderr.write(`error: ${err?.message ?? err}\n`);
		return 2;
	}
}
