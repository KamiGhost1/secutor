import crypto from 'crypto';
import type {Repos} from './repos.js';
import {b64u} from './util.js';

export class NonceManager {
	constructor(private repos: Repos, private ttlSec: number) {}

	issue(): string {
		const value = b64u(crypto.randomBytes(16));
		this.repos.storeNonce(value, this.ttlSec);
		return value;
	}

	/** Returns true if nonce was valid and is now consumed. */
	consume(value: string): boolean {
		return this.repos.consumeNonce(value);
	}

	purge(): void {
		this.repos.purgeNonces();
	}
}
