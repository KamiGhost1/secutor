#!/usr/bin/env node
import React from 'react';
import {render} from 'ink';
import {App} from './app.js';
import {ensureRoot} from './storage/paths.js';
import {closeContext} from './storage/db.js';
import {createInputProxy, enableMouse, disableMouse} from './input/inputProxy.js';

ensureRoot();

const args = process.argv.slice(2);
if (args.includes('--help') || args.includes('-h')) {
	process.stdout.write(
		`secutor — interactive TUI certificate manager\n\n` +
			`Usage:\n  secutor            run interactive UI\n  secutor --help     show this help\n\n` +
			`Storage path: ~/.secutor (override with SECUTOR_HOME)\n`,
	);
	process.exit(0);
}

const stdinProxy = createInputProxy();
enableMouse();

const cleanup = () => {
	try {
		disableMouse();
	} catch {}
	try {
		closeContext();
	} catch {}
};

const {waitUntilExit, unmount} = render(<App onExit={() => unmount()} />, {
	stdin: stdinProxy,
	exitOnCtrlC: true,
});

waitUntilExit().then(() => {
	cleanup();
	process.exit(0);
});

process.on('SIGINT', () => {
	cleanup();
	unmount();
});
process.on('SIGTERM', () => {
	cleanup();
	unmount();
});
process.on('exit', () => {
	try {
		disableMouse();
	} catch {}
});
