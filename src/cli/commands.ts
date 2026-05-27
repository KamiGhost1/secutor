import fs from 'fs';
import path from 'path';
import {
	signFile,
	manifestToJson,
	buildSignatureBundle,
	manifestFromJson,
	parseSignatureBundle,
	verifyBuffer,
	SignatureManifest,
	VerifyResult,
} from '../certs/signing.js';
import {isEncryptedKey} from '../certs/keys.js';
import {certRepo} from '../storage/repos.js';
import {openContext, closeContext} from '../storage/db.js';
import {
	contextExists,
	getContextMeta,
	verifyContextPassword,
} from '../storage/contextStore.js';

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
		} else if (a.startsWith('-') && a.length > 1) {
			const key = a.slice(1);
			const next = argv[i + 1];
			if (next != null && next !== '--' && !next.startsWith('--')) {
				flags[key] = next;
				i++;
			} else {
				flags[key] = true;
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
		throw new UsageError(
			'Cannot read more than one password from stdin in a single invocation',
		);
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
				// Ctrl-C
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

type PasswordSpec = {
	label: string;
	value?: string;
	stdin?: boolean;
	required: boolean;
};

function resolvePassword(spec: PasswordSpec): string | null {
	if (spec.value !== undefined) return spec.value;
	if (spec.stdin) return readStdinLine();
	if (!spec.required) return null;
	return promptHidden(`${spec.label}: `);
}

function resolveOptionalPassword(spec: PasswordSpec): string | null {
	if (spec.value !== undefined) return spec.value;
	if (spec.stdin) return readStdinLine();
	if (spec.required && process.stdin.isTTY) return promptHidden(`${spec.label}: `);
	if (spec.required) {
		throw new UsageError(
			`${spec.label}: no TTY available; pass a password via flag or use the -stdin variant`,
		);
	}
	return null;
}

type SourceFromContext = {
	kind: 'context';
	contextName: string;
	certName: string;
	contextPassword: PasswordSpec;
	keyPassword: PasswordSpec;
};

type SourceFromFiles = {
	kind: 'files';
	keyFile: string;
	certFile?: string;
	keyPassword: PasswordSpec;
};

function readPasswordFlags(
	args: ParsedArgs,
	prefix: string,
	label: string,
): PasswordSpec {
	const value = getFlag(args, `${prefix}-password`);
	const stdin = hasFlag(args, `${prefix}-password-stdin`);
	return {label, value, stdin, required: true};
}

function openContextSession(
	contextName: string,
	contextPassword: PasswordSpec,
): void {
	if (!contextExists(contextName)) {
		throw new UsageError(`Context "${contextName}" does not exist`);
	}
	const meta = getContextMeta(contextName);
	if (!meta) throw new UsageError(`Context "${contextName}" has no metadata`);
	let pw: string | null = null;
	if (meta.encrypted) {
		pw = resolvePassword({...contextPassword, required: true});
		if (!verifyContextPassword(contextName, pw ?? '')) {
			throw new UsageError(`Incorrect password for context "${contextName}"`);
		}
	}
	openContext(contextName, pw);
}

function loadSignerFromContext(certName: string): {
	certPem: string;
	keyPem: string;
	commonName: string;
} {
	const row = certRepo.findByName(certName);
	if (!row) {
		throw new UsageError(`Certificate "${certName}" not found in context`);
	}
	if (!row.key_pem) {
		throw new UsageError(`Certificate "${certName}" has no private key`);
	}
	return {certPem: row.cert_pem, keyPem: row.key_pem, commonName: row.common_name};
}

function loadCertFromContext(certName: string): string {
	const row = certRepo.findByName(certName);
	if (!row) {
		throw new UsageError(`Certificate "${certName}" not found in context`);
	}
	return row.cert_pem;
}

function readPemFile(p: string, what: string): string {
	let buf: Buffer;
	try {
		buf = fs.readFileSync(p);
	} catch (err: any) {
		throw new UsageError(`Cannot read ${what} from "${p}": ${err?.message ?? err}`);
	}
	return buf.toString('utf8');
}

const BUNDLE_MAGIC = Buffer.from('SECUTORSIG\x01', 'utf8');

function looksLikeBundle(buf: Buffer): boolean {
	return (
		buf.length >= BUNDLE_MAGIC.length &&
		buf.subarray(0, BUNDLE_MAGIC.length).equals(BUNDLE_MAGIC)
	);
}

// ----------------------------- sign command -----------------------------

export const SIGN_HELP = `Usage:
  secutor sign <file> [options]

Output options:
  -o, --out <path>           Output path
                             (default: <file>.sig for detached, <file>.secsig for bundle)
  -m, --mode <detached|bundle>   Signature mode (default: detached)

Signer from context:
  --context <name>           Open this context to look up the signer
  --cert <name>              Certificate name within the context
  --context-password <pw>    Pass the context password literally
  --context-password-stdin   Read the context password from stdin (one line)
  --key-password <pw>        Password for the stored encrypted private key
  --key-password-stdin       Read the key password from stdin
  (When neither --*-password nor --*-password-stdin is supplied for an
   encrypted source, the password is prompted on the TTY.)

Signer from files:
  --key-file <path>          PKCS#8 PEM private key
  --cert-file <path>         (optional) PEM cert to embed in the manifest
  --key-password <pw>        Password for the encrypted private key
  --key-password-stdin       Read the key password from stdin

The signer must be sourced either from a context (--context + --cert) or
from files (--key-file [+ --cert-file]). The two modes cannot be combined.

Exit codes:
  0  signed successfully
  2  usage or IO error`;

export async function runSignCommand(argv: string[]): Promise<number> {
	const args = parseArgs(argv);
	if (hasFlag(args, 'h', 'help')) {
		process.stdout.write(SIGN_HELP + '\n');
		return 0;
	}

	const file = args.positional[0];
	if (!file) throw new UsageError('Missing <file> to sign');
	if (!fs.existsSync(file)) {
		throw new UsageError(`File not found: ${file}`);
	}

	const mode = (getFlag(args, 'm', 'mode') ?? 'detached').toLowerCase();
	if (mode !== 'detached' && mode !== 'bundle') {
		throw new UsageError(`Invalid --mode "${mode}" (expected detached|bundle)`);
	}

	const defaultOut =
		mode === 'detached' ? `${file}.sig` : `${file}.secsig`;
	const outPath = getFlag(args, 'o', 'out') ?? defaultOut;

	const useContext = hasFlag(args, 'context') || hasFlag(args, 'cert');
	const useFiles = hasFlag(args, 'key-file');
	if (useContext && useFiles) {
		throw new UsageError(
			'Choose one signer source: --context + --cert OR --key-file',
		);
	}
	if (!useContext && !useFiles) {
		throw new UsageError(
			'No signer source given. Use --context + --cert, or --key-file',
		);
	}

	let certPem: string | null = null;
	let keyPem: string;
	let commonName: string | undefined;

	if (useContext) {
		const contextName = getFlag(args, 'context');
		const certName = getFlag(args, 'cert');
		if (!contextName) throw new UsageError('--context is required');
		if (!certName) throw new UsageError('--cert is required');

		const ctxPw = readPasswordFlags(args, 'context', 'Context password');
		openContextSession(contextName, ctxPw);
		try {
			const s = loadSignerFromContext(certName);
			certPem = s.certPem;
			keyPem = s.keyPem;
			commonName = s.commonName;
		} catch (err) {
			closeContext();
			throw err;
		}
	} else {
		const keyFile = getFlag(args, 'key-file')!;
		keyPem = readPemFile(keyFile, 'private key');
		const certFile = getFlag(args, 'cert-file');
		if (certFile) certPem = readPemFile(certFile, 'certificate');
	}

	const keyPwSpec: PasswordSpec = {
		label: 'Private key password',
		value: getFlag(args, 'key-password'),
		stdin: hasFlag(args, 'key-password-stdin'),
		required: isEncryptedKey(keyPem),
	};
	const keyPassword = keyPwSpec.required ? resolvePassword(keyPwSpec) : null;

	try {
		const manifest = signFile(file, {
			privateKeyPem: keyPem,
			keyPassword: keyPassword ?? null,
			certPem: certPem ?? null,
			commonName: commonName ?? null,
		});

		fs.mkdirSync(path.dirname(path.resolve(outPath)), {recursive: true});
		if (mode === 'detached') {
			fs.writeFileSync(outPath, manifestToJson(manifest));
		} else {
			const data = fs.readFileSync(file);
			const bundle = buildSignatureBundle(data, manifest);
			fs.writeFileSync(outPath, bundle);
		}
		process.stdout.write(`Signed: ${file}\n`);
		process.stdout.write(`Wrote:  ${outPath}\n`);
		if (manifest.signer?.fingerprint) {
			process.stdout.write(`Signer fingerprint: ${manifest.signer.fingerprint}\n`);
		}
		return 0;
	} finally {
		if (useContext) closeContext();
	}
}

// ----------------------------- verify command -----------------------------

export const VERIFY_HELP = `Usage:
  secutor verify <file> [options]

Signature input:
  -s, --sig <path>           Detached signature path
                             (default: <file>.sig; ignored when <file> is a bundle)

Default verifier:
  The signer certificate baked into the manifest is used unless one of the
  override sources below is supplied.

Verifier override — from files:
  --signer-file <path>       Cert PEM or SPKI public-key PEM
  --fingerprint <hex>        Pin the signer's SHA-256 fingerprint (hex)

Verifier override — from a context:
  --context <name>           Open this context to look up the signer
  --cert <name>              Certificate name within the context
  --context-password <pw>    Pass the context password literally
  --context-password-stdin   Read the context password from stdin

Exit codes:
  0  signature is valid
  1  signature is invalid (wrong, mismatched, expired data, etc.)
  2  usage or IO error`;

export async function runVerifyCommand(argv: string[]): Promise<number> {
	const args = parseArgs(argv);
	if (hasFlag(args, 'h', 'help')) {
		process.stdout.write(VERIFY_HELP + '\n');
		return 0;
	}

	const file = args.positional[0];
	if (!file) throw new UsageError('Missing <file> to verify');
	if (!fs.existsSync(file)) {
		throw new UsageError(`File not found: ${file}`);
	}

	const fileBuf = fs.readFileSync(file);
	const isBundle = looksLikeBundle(fileBuf);

	let manifest: SignatureManifest;
	let data: Buffer;
	let sigPath: string | null = null;

	if (isBundle) {
		const parsed = parseSignatureBundle(fileBuf);
		manifest = parsed.manifest;
		data = parsed.data;
	} else {
		sigPath = getFlag(args, 's', 'sig') ?? `${file}.sig`;
		if (!fs.existsSync(sigPath)) {
			throw new UsageError(`Signature file not found: ${sigPath}`);
		}
		try {
			manifest = manifestFromJson(fs.readFileSync(sigPath, 'utf8'));
		} catch (err: any) {
			throw new UsageError(
				`Cannot parse signature manifest at "${sigPath}": ${err?.message ?? err}`,
			);
		}
		data = fileBuf;
	}

	let expectedSignerPem: string | null = null;
	let contextOpened = false;

	const useContextVerifier =
		hasFlag(args, 'context') || hasFlag(args, 'cert');
	const signerFile = getFlag(args, 'signer-file');

	if (useContextVerifier && signerFile) {
		throw new UsageError(
			'Choose one verifier override: --signer-file OR --context + --cert',
		);
	}

	try {
		if (signerFile) {
			expectedSignerPem = readPemFile(signerFile, 'signer cert/key');
		} else if (useContextVerifier) {
			const contextName = getFlag(args, 'context');
			const certName = getFlag(args, 'cert');
			if (!contextName) throw new UsageError('--context is required');
			if (!certName) throw new UsageError('--cert is required');
			const ctxPw = readPasswordFlags(args, 'context', 'Context password');
			openContextSession(contextName, ctxPw);
			contextOpened = true;
			expectedSignerPem = loadCertFromContext(certName);
		}

		const fingerprint = getFlag(args, 'fingerprint') ?? null;

		const result: VerifyResult = verifyBuffer(data, manifest, {
			expectedSignerPem,
			expectedFingerprint: fingerprint,
		});

		if (result.ok) {
			process.stdout.write(`OK: signature is valid\n`);
			if (result.algorithm) {
				process.stdout.write(`Algorithm: ${result.algorithm}\n`);
			}
			if (result.signer?.commonName) {
				process.stdout.write(`Signer CN: ${result.signer.commonName}\n`);
			}
			if (result.signer?.fingerprint) {
				process.stdout.write(`Signer fingerprint: ${result.signer.fingerprint}\n`);
			}
			if (sigPath) process.stdout.write(`Signature: ${sigPath}\n`);
			if (isBundle) process.stdout.write(`(bundle mode)\n`);
			return 0;
		}

		process.stderr.write(`FAIL: ${result.reason ?? 'signature is not valid'}\n`);
		return 1;
	} finally {
		if (contextOpened) closeContext();
	}
}

// ----------------------------- dispatcher -----------------------------

export function isCliSubcommand(name: string | undefined): boolean {
	return name === 'sign' || name === 'verify';
}

export async function runCli(argv: string[]): Promise<number> {
	const [cmd, ...rest] = argv;
	try {
		if (cmd === 'sign') return await runSignCommand(rest);
		if (cmd === 'verify') return await runVerifyCommand(rest);
		throw new UsageError(`Unknown command: ${cmd}`);
	} catch (err: any) {
		if (err instanceof UsageError) {
			process.stderr.write(`error: ${err.message}\n`);
			return 2;
		}
		process.stderr.write(`error: ${err?.message ?? err}\n`);
		return 2;
	}
}
