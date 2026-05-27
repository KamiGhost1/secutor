// RFC 8555 §6.7 — Problem documents (RFC 7807).

export type ProblemType =
	| 'accountDoesNotExist'
	| 'alreadyRevoked'
	| 'badCSR'
	| 'badNonce'
	| 'badPublicKey'
	| 'badRevocationReason'
	| 'badSignatureAlgorithm'
	| 'caa'
	| 'compound'
	| 'connection'
	| 'dns'
	| 'externalAccountRequired'
	| 'incorrectResponse'
	| 'invalidContact'
	| 'malformed'
	| 'orderNotReady'
	| 'rateLimited'
	| 'rejectedIdentifier'
	| 'serverInternal'
	| 'tls'
	| 'unauthorized'
	| 'unsupportedContact'
	| 'unsupportedIdentifier'
	| 'userActionRequired';

export class AcmeError extends Error {
	type: ProblemType;
	status: number;
	detail: string;
	subproblems?: unknown[];

	constructor(type: ProblemType, detail: string, status = 400, subproblems?: unknown[]) {
		super(detail);
		this.type = type;
		this.status = status;
		this.detail = detail;
		this.subproblems = subproblems;
	}

	toProblem(): Record<string, unknown> {
		const p: Record<string, unknown> = {
			type: `urn:ietf:params:acme:error:${this.type}`,
			detail: this.detail,
			status: this.status,
		};
		if (this.subproblems) p.subproblems = this.subproblems;
		return p;
	}
}

export function problemContentType(): string {
	return 'application/problem+json';
}
