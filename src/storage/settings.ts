import fs from 'fs';
import path from 'path';
import {rootDir, ensureRoot} from './paths.js';

export type Settings = {
	showWebConfigs: boolean;
};

const DEFAULTS: Settings = {
	showWebConfigs: false,
};

function settingsFile(): string {
	return path.join(rootDir(), 'settings.json');
}

export function readSettings(): Settings {
	try {
		const raw = JSON.parse(fs.readFileSync(settingsFile(), 'utf8'));
		return {...DEFAULTS, ...raw};
	} catch {
		return {...DEFAULTS};
	}
}

export function writeSettings(s: Settings): void {
	try {
		ensureRoot();
		fs.writeFileSync(settingsFile(), JSON.stringify(s, null, 2));
	} catch {}
}

export function updateSetting<K extends keyof Settings>(key: K, value: Settings[K]): Settings {
	const s = readSettings();
	s[key] = value;
	writeSettings(s);
	return s;
}
