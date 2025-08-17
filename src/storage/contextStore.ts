import fs from 'fs';
import path from 'path';
import {
	CONTEXTS_DIR,
	META_FILE,
	contextDir,
	contextEncryptedFile,
	contextDbFile,
	contextMetaFile,
	ensureRoot,
} from './paths.js';
import {checkVerifier, makeVerifier} from './crypto.js';
import {migrateContextEncryption} from './db.js';

export type ContextMeta = {
	name: string;
	encrypted: boolean;
	createdAt: string;
	verifySalt?: string;
	verifyIters?: number;
	verifier?: string;
};

export type RootMeta = {
	currentContext: string | null;
};

function readJson<T>(p: string, def: T): T {
	try {
		return JSON.parse(fs.readFileSync(p, 'utf8')) as T;
	} catch {
		return def;
	}
}
function writeJson(p: string, v: unknown): void {
	fs.mkdirSync(path.dirname(p), {recursive: true});
	fs.writeFileSync(p, JSON.stringify(v, null, 2));
}

export function readRootMeta(): RootMeta {
	ensureRoot();
	return readJson<RootMeta>(META_FILE, {currentContext: null});
}
export function writeRootMeta(m: RootMeta): void {
	writeJson(META_FILE, m);
}

export function listContexts(): ContextMeta[] {
	ensureRoot();
	const out: ContextMeta[] = [];
	for (const entry of fs.readdirSync(CONTEXTS_DIR)) {
		const file = contextMetaFile(entry);
		if (fs.existsSync(file)) {
			const m = readJson<ContextMeta | null>(file, null);
			if (m) out.push(m);
		}
	}
	return out.sort((a, b) => a.name.localeCompare(b.name));
}

export function contextExists(name: string): boolean {
	return fs.existsSync(contextMetaFile(name));
}

export function getContextMeta(name: string): ContextMeta | null {
	const f = contextMetaFile(name);
	if (!fs.existsSync(f)) return null;
	return readJson<ContextMeta | null>(f, null);
}

export function saveContextMeta(meta: ContextMeta): void {
	writeJson(contextMetaFile(meta.name), meta);
}

export function createContext(opts: {
	name: string;
	password?: string;
}): ContextMeta {
	if (!/^[a-zA-Z0-9._-]+$/.test(opts.name)) {
		throw new Error('Invalid context name. Use letters, digits, ., _, -');
	}
	if (contextExists(opts.name)) {
		throw new Error(`Context "${opts.name}" already exists`);
	}
	fs.mkdirSync(contextDir(opts.name), {recursive: true});

	const meta: ContextMeta = {
		name: opts.name,
		encrypted: !!opts.password,
		createdAt: new Date().toISOString(),
	};

	if (opts.password) {
		const v = makeVerifier(opts.password);
		meta.verifySalt = v.salt;
		meta.verifyIters = v.iters;
		meta.verifier = v.verifier;
	}

	saveContextMeta(meta);
	return meta;
}

export function deleteContext(name: string): void {
	const dir = contextDir(name);
	if (!fs.existsSync(dir)) return;
	fs.rmSync(dir, {recursive: true, force: true});

	const root = readRootMeta();
	if (root.currentContext === name) {
		root.currentContext = null;
		writeRootMeta(root);
	}
}

export function verifyContextPassword(name: string, password: string): boolean {
	const meta = getContextMeta(name);
	if (!meta) return false;
	if (!meta.encrypted) return true;
	if (!meta.verifySalt || !meta.verifier || !meta.verifyIters) return false;
	return checkVerifier(password, meta.verifySalt, meta.verifyIters, meta.verifier);
}

export function setContextPassword(
	name: string,
	currentPassword: string | null,
	newPassword: string | null,
): void {
	const meta = getContextMeta(name);
	if (!meta) throw new Error(`Context "${name}" not found`);
	if (meta.encrypted && !verifyContextPassword(name, currentPassword || '')) {
		throw new Error('Current password incorrect');
	}
	migrateContextEncryption(name, currentPassword, newPassword);

	if (newPassword) {
		const v = makeVerifier(newPassword);
		meta.encrypted = true;
		meta.verifySalt = v.salt;
		meta.verifyIters = v.iters;
		meta.verifier = v.verifier;
	} else {
		meta.encrypted = false;
		delete meta.verifySalt;
		delete meta.verifyIters;
		delete meta.verifier;
	}
	saveContextMeta(meta);
}

export function exportContextPath(name: string): string {
	const meta = getContextMeta(name);
	if (!meta) throw new Error(`Context "${name}" not found`);
	return meta.encrypted ? contextEncryptedFile(name) : contextDbFile(name);
}
