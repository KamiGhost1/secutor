import fs from 'fs';
import path from 'path';
import YAML from 'yaml';
import type {AdminConfig} from './admin/index.js';
import type {DnsProviderConfig} from './dnsProviders.js';

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
	// Optional TLS for the ACME endpoint itself. ACME RFC 8555 §6.1 requires
	// HTTPS, and most clients (lego/Traefik, certbot, acme.sh) refuse plain
	// HTTP directories. If both files are set, the server starts as HTTPS.
	// If both are unset, it stays plain HTTP (suitable behind an external
	// reverse proxy that terminates TLS).
	tls?: {
		certFile: string;
		keyFile: string;
	};
	// Optional admin API. When unset, no admin listener starts. When set, a
	// separate fastify instance is bound on admin.listen with mTLS-only auth.
	// See acme-server/src/server/admin/index.ts for the AdminConfig schema.
	admin?: AdminConfig;
	// Optional list of DNS providers. When set, clients can request
	// `secutor.dnsPlacement = "server-managed"` in newOrder and the server
	// publishes/cleans up TXT records on their behalf via the matching
	// provider. Without this list, server-managed orders are rejected.
	dnsProviders?: DnsProviderConfig[];
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

	// TLS — either both env vars are set (HTTPS), or both fromFile.tls fields
	// are set, or none at all (HTTP).
	const tlsCertEnv = process.env.SECUTOR_ACME_TLS_CERT;
	const tlsKeyEnv = process.env.SECUTOR_ACME_TLS_KEY;
	let tls: Config['tls'] | undefined;
	if (tlsCertEnv && tlsKeyEnv) {
		tls = {certFile: tlsCertEnv, keyFile: tlsKeyEnv};
	} else if (tlsCertEnv || tlsKeyEnv) {
		throw new Error(
			'SECUTOR_ACME_TLS_CERT and SECUTOR_ACME_TLS_KEY must be set together (or both unset)',
		);
	} else if (fromFile.tls?.certFile && fromFile.tls?.keyFile) {
		tls = fromFile.tls;
	} else if (fromFile.tls?.certFile || fromFile.tls?.keyFile) {
		throw new Error(
			'config.yaml: tls.certFile and tls.keyFile must be set together (or omit the tls block)',
		);
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
		tls,
		admin: fromFile.admin,
		dnsProviders: fromFile.dnsProviders,
	};

	if (!cfg.baseUrl) throw new Error('SECUTOR_ACME_BASE_URL not set');
	if (!cfg.contextDir) throw new Error('SECUTOR_CONTEXT_DIR not set');
	if (!cfg.baseUrl.endsWith('/')) cfg.baseUrl += '/';

	// Sanity check: if TLS is configured but baseUrl is http://, that's almost
	// certainly a misconfiguration that will confuse ACME clients (directory
	// returns http:// URLs while the server speaks HTTPS). Warn loudly.
	if (cfg.tls && cfg.baseUrl.startsWith('http://')) {
		console.warn(
			`[secutor-acme] tls is configured but baseUrl is "${cfg.baseUrl}" (http://). ` +
				`Clients will follow http:// URLs from /directory and fail to handshake. ` +
				`Set baseUrl to https://...`,
		);
	}
	if (!cfg.tls && cfg.baseUrl.startsWith('https://')) {
		console.warn(
			`[secutor-acme] baseUrl is "${cfg.baseUrl}" (https://) but no TLS configured ` +
				`in secutor itself. This is fine ONLY if an external reverse proxy terminates ` +
				`TLS in front of this server.`,
		);
	}

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
