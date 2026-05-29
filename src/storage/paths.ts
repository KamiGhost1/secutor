import path from 'path';
import os from 'os';
import fs from 'fs';

// Resolve SECUTOR_HOME lazily so tests can override `process.env.SECUTOR_HOME`
// before the first call without having to re-import storage modules. In
// production this evaluates exactly once because the env var doesn't change.
export function rootDir(): string {
	return process.env.SECUTOR_HOME || path.join(os.homedir(), '.secutor');
}

export function contextsDir(): string {
	return path.join(rootDir(), 'contexts');
}

export function metaFile(): string {
	return path.join(rootDir(), 'meta.json');
}

// NOTE: the old `ROOT_DIR`/`CONTEXTS_DIR`/`META_FILE` constants were removed
// in favour of the rootDir()/contextsDir()/metaFile() functions above. Always
// call the function — it makes tests that swap `process.env.SECUTOR_HOME`
// between contexts work without forking child processes.

export function ensureRoot(): void {
	fs.mkdirSync(rootDir(), {recursive: true});
	fs.mkdirSync(contextsDir(), {recursive: true});
}

export function contextDir(name: string): string {
	return path.join(contextsDir(), name);
}

export function contextDbFile(name: string): string {
	return path.join(contextDir(name), 'store.db');
}

export function contextEncryptedFile(name: string): string {
	return path.join(contextDir(name), 'store.enc');
}

export function contextMetaFile(name: string): string {
	return path.join(contextDir(name), 'context.json');
}
