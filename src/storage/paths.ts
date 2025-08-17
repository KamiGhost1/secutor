import path from 'path';
import os from 'os';
import fs from 'fs';

export const ROOT_DIR =
	process.env.SECUTOR_HOME || path.join(os.homedir(), '.secutor');

export const CONTEXTS_DIR = path.join(ROOT_DIR, 'contexts');
export const META_FILE = path.join(ROOT_DIR, 'meta.json');

export function ensureRoot(): void {
	fs.mkdirSync(ROOT_DIR, {recursive: true});
	fs.mkdirSync(CONTEXTS_DIR, {recursive: true});
}

export function contextDir(name: string): string {
	return path.join(CONTEXTS_DIR, name);
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
