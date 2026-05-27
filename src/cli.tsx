#!/usr/bin/env node
import React from 'react';
import {render} from 'ink';
import {App} from './app.js';
import {ensureRoot} from './storage/paths.js';
import {closeContext} from './storage/db.js';
import {createInputProxy, enableMouse, disableMouse} from './input/inputProxy.js';
import {VERSION} from './version.js';
import {isCliSubcommand, runCli, SIGN_HELP, VERIFY_HELP} from './cli/commands.js';

ensureRoot();

const args = process.argv.slice(2);
if (args.includes('--version') || args.includes('-v')) {
	process.stdout.write(`${VERSION}\n`);
	process.exit(0);
}
if (args[0] === '--help' || args[0] === '-h' || (args.length === 0 ? false : !isCliSubcommand(args[0]) && (args.includes('--help') || args.includes('-h')))) {
	process.stdout.write(
		`secutor v${VERSION} — interactive TUI certificate manager\n\n` +
			`Usage:\n` +
			`  secutor                       run interactive UI\n` +
			`  secutor sign <file> [opts]    sign a file (see 'secutor sign --help')\n` +
			`  secutor verify <file> [opts]  verify a signed file (see 'secutor verify --help')\n` +
			`  secutor --help                show this help\n` +
			`  secutor --version             print the version and exit\n\n` +
			`Storage path: ~/.secutor (override with SECUTOR_HOME)\n\n` +
			SIGN_HELP +
			`\n\n` +
			VERIFY_HELP +
			`\n`,
	);
	process.exit(0);
}

if (isCliSubcommand(args[0])) {
	runCli(args)
		.then(code => {
			try {
				closeContext();
			} catch {}
			process.exit(code);
		})
		.catch(err => {
			process.stderr.write(`error: ${err?.message ?? err}\n`);
			try {
				closeContext();
			} catch {}
			process.exit(2);
		});
	// Avoid falling through to Ink render.
} else {
	startInteractiveUi();
}

function startInteractiveUi() {
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
}
