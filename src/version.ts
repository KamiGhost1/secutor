import {createRequire} from 'node:module';

/**
 * Reads the running build's version straight from package.json — works both
 * during `tsx` dev runs (file at src/components/Header.tsx → ../../package.json)
 * and from the compiled artifact (dist/components/Header.js → ../../package.json),
 * because both resolve to the package root.
 */
const require = createRequire(import.meta.url);
let _version = 'dev';
try {
	const pkg = require('../package.json') as {version?: string};
	if (pkg.version) _version = pkg.version;
} catch {
	// Bundled / vendored elsewhere — fall back to "dev".
}

export const VERSION = _version;
