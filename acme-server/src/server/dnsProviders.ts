// Server-side DNS-01 provider dispatcher. Looks up which provider owns a
// given identifier's zone (longest-match wins), constructs the provider on
// first use, and caches the instance. Server-managed DNS-01 (challenge
// publishing on behalf of the client) routes through here.
//
// Zone rules from config.dnsProviders are evaluated top-to-bottom. A rule
// with zones=['*'] is the default catch-all.

import {DnsProvider, rfc2136Provider, scriptProvider, memoryProvider} from '../dns/providers.js';

export type DnsProviderConfig =
	| {
			type: 'rfc2136';
			zones: string[];
			server: string;
			keyFile: string;
			ttl?: number;
			nsupdatePath?: string;
	  }
	| {
			type: 'script';
			zones: string[];
			path: string;
	  }
	| {
			type: 'memory'; // tests only
			zones: string[];
			label?: string;
	  };

export class DnsProviderRegistry {
	private cache = new Map<DnsProviderConfig, DnsProvider>();
	private memInstances = new Map<string, DnsProvider>();

	constructor(private rules: DnsProviderConfig[]) {}

	/** Returns the provider whose zones match `identifier`, or null. */
	pickFor(identifier: string): DnsProvider | null {
		const rule = matchRule(identifier, this.rules);
		if (!rule) return null;
		const cached = this.cache.get(rule);
		if (cached) return cached;
		const built = this.build(rule);
		this.cache.set(rule, built);
		return built;
	}

	/** True iff at least one rule matches. */
	hasProviderFor(identifier: string): boolean {
		return !!matchRule(identifier, this.rules);
	}

	/** For tests: pre-register a specific memory provider for a given label, so
	 * the test can inspect/spy on the same instance the dispatcher returns. */
	registerMemory(label: string, prov: DnsProvider): void {
		this.memInstances.set(label, prov);
	}

	private build(rule: DnsProviderConfig): DnsProvider {
		if (rule.type === 'rfc2136') {
			return rfc2136Provider({
				server: rule.server,
				zone: rule.zones[0] ?? '.',
				keyFile: rule.keyFile,
				ttl: rule.ttl,
				nsupdatePath: rule.nsupdatePath,
			});
		}
		if (rule.type === 'script') {
			return scriptProvider(rule.path);
		}
		// memory
		const label = rule.label ?? `mem-${rule.zones.join('|')}`;
		const existing = this.memInstances.get(label);
		if (existing) return existing;
		const fresh = memoryProvider(label);
		this.memInstances.set(label, fresh);
		return fresh;
	}
}

/**
 * Longest-zone-match. For DNS-01 the lookup name is `_acme-challenge.<id>`;
 * we strip that prefix here so providers can be configured by user-visible
 * domain ("lan.vpn", not "_acme-challenge.lan.vpn").
 */
function matchRule(identifier: string, rules: DnsProviderConfig[]): DnsProviderConfig | null {
	const candidates: Array<{rule: DnsProviderConfig; specificity: number}> = [];
	const id = stripAcmePrefix(identifier).toLowerCase();
	for (const rule of rules) {
		for (const z of rule.zones) {
			const spec = matchSpecificity(id, z.toLowerCase());
			if (spec >= 0) candidates.push({rule, specificity: spec});
		}
	}
	if (!candidates.length) return null;
	candidates.sort((a, b) => b.specificity - a.specificity);
	return candidates[0]!.rule;
}

function stripAcmePrefix(name: string): string {
	return name.startsWith('_acme-challenge.') ? name.slice('_acme-challenge.'.length) : name;
}

/**
 * Returns the number of matched characters (rough specificity proxy), or -1
 * if no match. Wildcards (`*` or `*.foo.lan`) match anything ending in the
 * suffix; bare names match exactly.
 */
function matchSpecificity(name: string, zone: string): number {
	if (zone === '*') return 0;
	if (zone.startsWith('*.')) {
		const suf = zone.slice(2);
		if (name === suf || name.endsWith('.' + suf)) return suf.length;
		return -1;
	}
	if (name === zone || name.endsWith('.' + zone)) return zone.length;
	return -1;
}

export function buildChallengeName(identifier: string, wildcard: boolean): string {
	const base = wildcard && identifier.startsWith('*.') ? identifier.slice(2) : identifier;
	return `_acme-challenge.${base}`;
}
