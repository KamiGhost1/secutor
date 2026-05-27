// Centralised URL builder. baseUrl ends with "/".

export class Urls {
	constructor(public baseUrl: string) {}
	directory(): string {
		return this.baseUrl + 'directory';
	}
	newNonce(): string {
		return this.baseUrl + 'new-nonce';
	}
	newAccount(): string {
		return this.baseUrl + 'new-account';
	}
	newOrder(): string {
		return this.baseUrl + 'new-order';
	}
	revokeCert(): string {
		return this.baseUrl + 'revoke-cert';
	}
	keyChange(): string {
		return this.baseUrl + 'key-change';
	}
	account(id: string): string {
		return this.baseUrl + `acct/${id}`;
	}
	order(id: string): string {
		return this.baseUrl + `order/${id}`;
	}
	authz(id: string): string {
		return this.baseUrl + `authz/${id}`;
	}
	challenge(id: string): string {
		return this.baseUrl + `chall/${id}`;
	}
	finalize(orderId: string): string {
		return this.baseUrl + `order/${orderId}/finalize`;
	}
	cert(id: string): string {
		return this.baseUrl + `cert/${id}`;
	}

	/** Reverse: extract id from kid-style URL `${baseUrl}acct/<id>`. */
	parseAccountId(kid: string): string | null {
		const m = new RegExp('^' + escapeRe(this.baseUrl) + 'acct/([A-Z0-9]+)/?$').exec(kid);
		return m ? m[1]! : null;
	}
}

function escapeRe(s: string): string {
	return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
