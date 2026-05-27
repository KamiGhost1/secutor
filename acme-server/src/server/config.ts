import fs from 'fs';
import path from 'path';
import YAML from 'yaml';

export type ResolverRule = {
	zones: string[]; // glob-like: ["lan", "*.internal"] or ["*"] as default
	servers: string[]; // ["10.0.0.53", "10.0.0.54:53"]
};

export type Config = {
	listen: string; // "0.0.0.0:8443"
	baseUrl: string; // "https://acme.example/"
	contextDir: string; // path to ~/.secutor/contexts/<name>/
	contextPasswordFile: string | null;
	caCertName: string | null; // which "ca" row to use; null = first ca-type cert
	caKeyPasswordFile: string | null; // if CA private key itself is encrypted
	stateDb: string; // path to acme.db
	resolvers: ResolverRule[];
	challenges: {
		dns01: boolean;
		http01: boolean;
		http01Port: number; // server's outbound check uses this port on the target
	};
	leafValidityDays: number;
	nonceTtlSec: number;
	orderTtlSec: number;
	allowList?: {
		// If set, restrict identifiers globally (regardless of account).
		dnsPatterns: string[]; // e.g. ["*.lan", "*.vpn.local"]
	};
};

const DEFAULTS: Partial<Config> = {
	listen: '0.0.0.0:8443',
	stateDb: '/var/lib/secutor-acme/acme.db',
	resolvers: [{zones: ['*'], servers: ['1.1.1.1', '8.8.8.8']}],
	challenges: {dns01: true, http01: true, http01Port: 80},
	leafValidityDays: 90,
	nonceTtlSec: 600,
	orderTtlSec: 7 * 24 * 3600,
};

function readSecretFile(p: string | null): string | null {
	if (!p) return null;
	try {
		return fs.readFileSync(p, 'utf8').trim();
	} catch (e: any) {
		throw new Error(`Cannot read secret file ${p}: ${e?.message ?? e}`);
	}
}

export function loadConfig(): {config: Config; contextPassword: string | null; caKeyPassword: string | null} {
	const file = process.env.SECUTOR_ACME_CONFIG;
	let fromFile: Partial<Config> = {};
	if (file && fs.existsSync(file)) {
		const text = fs.readFileSync(file, 'utf8');
		fromFile = file.endsWith('.json') ? JSON.parse(text) : YAML.parse(text);
	}

	const cfg: Config = {
		...(DEFAULTS as Config),
		...fromFile,
		listen: process.env.SECUTOR_ACME_LISTEN ?? fromFile.listen ?? DEFAULTS.listen!,
		baseUrl: process.env.SECUTOR_ACME_BASE_URL ?? fromFile.baseUrl ?? '',
		contextDir: process.env.SECUTOR_CONTEXT_DIR ?? fromFile.contextDir ?? '',
		contextPasswordFile:
			process.env.SECUTOR_CONTEXT_PASSWORD_FILE ?? fromFile.contextPasswordFile ?? null,
		caCertName: process.env.SECUTOR_CA_CERT_NAME ?? fromFile.caCertName ?? null,
		caKeyPasswordFile:
			process.env.SECUTOR_CA_KEY_PASSWORD_FILE ?? fromFile.caKeyPasswordFile ?? null,
		stateDb: process.env.SECUTOR_ACME_DB ?? fromFile.stateDb ?? DEFAULTS.stateDb!,
		resolvers: fromFile.resolvers ?? DEFAULTS.resolvers!,
		challenges: {...DEFAULTS.challenges!, ...(fromFile.challenges ?? {})},
		leafValidityDays: fromFile.leafValidityDays ?? DEFAULTS.leafValidityDays!,
		nonceTtlSec: fromFile.nonceTtlSec ?? DEFAULTS.nonceTtlSec!,
		orderTtlSec: fromFile.orderTtlSec ?? DEFAULTS.orderTtlSec!,
		allowList: fromFile.allowList,
	};

	if (!cfg.baseUrl) throw new Error('SECUTOR_ACME_BASE_URL not set');
	if (!cfg.contextDir) throw new Error('SECUTOR_CONTEXT_DIR not set');
	if (!cfg.baseUrl.endsWith('/')) cfg.baseUrl += '/';

	// Ensure state DB dir exists.
	fs.mkdirSync(path.dirname(cfg.stateDb), {recursive: true});

	const contextPassword = readSecretFile(cfg.contextPasswordFile);
	const caKeyPassword = readSecretFile(cfg.caKeyPasswordFile);
	return {config: cfg, contextPassword, caKeyPassword};
}

export function parseListen(s: string): {host: string; port: number} {
	const m = /^(.+):(\d+)$/.exec(s);
	if (!m) throw new Error(`Bad listen address: ${s}`);
	return {host: m[1]!, port: parseInt(m[2]!, 10)};
}
