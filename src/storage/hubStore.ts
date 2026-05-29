// Registry of remote ACME hubs the TUI can connect to over mTLS.
// File: ~/.secutor/hubs.json. Schema is stable v1; new optional fields are
// added at the end, old TUIs ignore them.
//
// Why a dedicated file (not part of contexts/meta.json):
//   • Hubs aren't tied to a single context — a single laptop may admin
//     multiple hubs with the same client key from one of its contexts.
//   • Adding/removing a hub doesn't require touching any PKI material.

import fs from 'fs';
import path from 'path';
import {rootDir, ensureRoot} from './paths.js';

export type HubClientAuthContext = {
	kind: 'context';
	/** Which secutor context the client cert lives in. */
	context: string;
	/** Name of the certificate row (must be type=client). */
	certName: string;
	/** Cache decrypted key password for the session? Memory only, never disk. */
	rememberKeyPassword?: boolean;
};

export type HubClientAuthFile = {
	kind: 'file';
	/** Absolute path to a PEM cert. */
	certPath: string;
	/** Absolute path to a PEM private key (PKCS#8, may be encrypted). */
	keyPath: string;
	rememberKeyPassword?: boolean;
};

export type HubClientAuthKeystore = {
	kind: 'keystore';
	/** Name of an entry inside ~/.secutor/hubkeys/. */
	keystoreEntry: string;
	rememberKeyPassword?: boolean;
};

export type HubClientAuth = HubClientAuthContext | HubClientAuthFile | HubClientAuthKeystore;

export type Hub = {
	id: string;
	name: string;
	baseUrl: string;
	/** SHA-256 fingerprint of the server cert (hex, no colons). */
	serverFingerprint: string;
	clientAuth: HubClientAuth;
	addedAt: string;
	lastSeen?: string | null;
};

type HubsFile = {
	hubs: Hub[];
};

function hubsFile(): string {
	return path.join(rootDir(), 'hubs.json');
}

function readFile(): HubsFile {
	try {
		const raw = fs.readFileSync(hubsFile(), 'utf8');
		const parsed = JSON.parse(raw) as HubsFile;
		if (!parsed.hubs || !Array.isArray(parsed.hubs)) return {hubs: []};
		return parsed;
	} catch {
		return {hubs: []};
	}
}

function writeFile(f: HubsFile): void {
	ensureRoot();
	fs.writeFileSync(hubsFile(), JSON.stringify(f, null, 2), {mode: 0o600});
}

export function listHubs(): Hub[] {
	return readFile().hubs.slice().sort((a, b) => a.name.localeCompare(b.name));
}

export function findHub(id: string): Hub | null {
	return readFile().hubs.find(h => h.id === id) ?? null;
}

export function addHub(h: Omit<Hub, 'id' | 'addedAt'> & {id?: string}): Hub {
	const f = readFile();
	const id = h.id ?? `hub-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
	const hub: Hub = {...h, id, addedAt: new Date().toISOString()};
	if (f.hubs.some(x => x.id === id)) {
		throw new Error(`Hub with id "${id}" already exists`);
	}
	f.hubs.push(hub);
	writeFile(f);
	return hub;
}

export function updateHub(id: string, patch: Partial<Hub>): Hub {
	const f = readFile();
	const idx = f.hubs.findIndex(h => h.id === id);
	if (idx < 0) throw new Error(`Hub "${id}" not found`);
	f.hubs[idx] = {...f.hubs[idx]!, ...patch, id: f.hubs[idx]!.id};
	writeFile(f);
	return f.hubs[idx]!;
}

export function removeHub(id: string): void {
	const f = readFile();
	const before = f.hubs.length;
	f.hubs = f.hubs.filter(h => h.id !== id);
	if (f.hubs.length === before) return;
	writeFile(f);
}

export function touchLastSeen(id: string): void {
	try {
		updateHub(id, {lastSeen: new Date().toISOString()});
	} catch {
		/* hub may have been removed concurrently */
	}
}
