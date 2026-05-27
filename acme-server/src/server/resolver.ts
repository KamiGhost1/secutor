// Per-zone DNS resolution. Maps a queried name → the configured resolver
// server(s) for the zone that name belongs to.

import {Resolver} from 'dns/promises';
import type {ResolverRule} from './config.js';

function matchesZone(name: string, zone: string): boolean {
	if (zone === '*') return true;
	const n = name.toLowerCase().replace(/\.$/, '');
	const z = zone.toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
	return n === z || n.endsWith('.' + z);
}

function pickRule(name: string, rules: ResolverRule[]): ResolverRule {
	// Specific zones first, "*" fallback last.
	const specific = rules.filter(r => !r.zones.includes('*'));
	const fallback = rules.find(r => r.zones.includes('*'));
	for (const r of specific) {
		if (r.zones.some(z => matchesZone(name, z))) return r;
	}
	if (fallback) return fallback;
	throw new Error(`No DNS resolver configured for ${name}`);
}

function parseServer(s: string): {ip: string; port: number} {
	const m = /^\[?([^\]:]+)\]?(?::(\d+))?$/.exec(s);
	if (!m) throw new Error(`Bad resolver server: ${s}`);
	return {ip: m[1]!, port: m[2] ? parseInt(m[2]!, 10) : 53};
}

async function defaultResolveTxt(name: string, rules: ResolverRule[]): Promise<string[]> {
	const rule = pickRule(name, rules);
	const resolver = new Resolver();
	resolver.setServers(
		rule.servers.map(parseServer).map(s => (s.port === 53 ? s.ip : `${s.ip}:${s.port}`)),
	);
	try {
		const arr = await resolver.resolveTxt(name);
		return arr.map(chunks => chunks.join(''));
	} catch (e: any) {
		if (e?.code === 'ENODATA' || e?.code === 'ENOTFOUND') return [];
		throw e;
	}
}

type TxtResolver = (name: string, rules: ResolverRule[]) => Promise<string[]>;
let _impl: TxtResolver = defaultResolveTxt;

export function resolveTxt(name: string, rules: ResolverRule[]): Promise<string[]> {
	return _impl(name, rules);
}

/** Test hook: override the TXT resolver. */
export function setResolveTxtForTesting(fn: TxtResolver | null): void {
	_impl = fn ?? defaultResolveTxt;
}
