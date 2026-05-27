import type Database from 'better-sqlite3';
import {ulid} from 'ulid';
import {nowIso, isoPlus} from './util.js';

export type AccountRow = {
	id: string;
	jwk_thumbprint: string;
	jwk_json: string;
	contact_json: string | null;
	status: string;
	terms_agreed: number;
	allow_list_json: string | null;
	created_at: string;
};

export type OrderRow = {
	id: string;
	account_id: string;
	status: 'pending' | 'ready' | 'processing' | 'valid' | 'invalid';
	identifiers_json: string;
	not_before: string | null;
	not_after: string | null;
	expires_at: string;
	error_json: string | null;
	certificate_id: string | null;
	csr_der: Buffer | null;
	created_at: string;
};

export type AuthzRow = {
	id: string;
	order_id: string;
	identifier_type: string;
	identifier_value: string;
	wildcard: number;
	status: 'pending' | 'valid' | 'invalid' | 'expired' | 'revoked';
	expires_at: string;
	created_at: string;
};

export type ChallengeRow = {
	id: string;
	authz_id: string;
	type: 'dns-01' | 'http-01';
	token: string;
	status: 'pending' | 'processing' | 'valid' | 'invalid';
	validated_at: string | null;
	error_json: string | null;
	attempts: number;
	next_check_at: string | null;
	created_at: string;
};

export type CertRow = {
	id: string;
	order_id: string;
	account_id: string;
	serial_hex: string;
	pem: string;
	chain_pem: string;
	not_before: string;
	not_after: string;
	revoked: number;
	revoked_at: string | null;
	revocation_reason: number | null;
	issued_at: string;
};

export class Repos {
	constructor(public db: Database.Database) {}

	// ---- accounts ----
	insertAccount(jwkJson: string, thumbprint: string, contact: string[] | null): AccountRow {
		const row: AccountRow = {
			id: ulid(),
			jwk_thumbprint: thumbprint,
			jwk_json: jwkJson,
			contact_json: contact ? JSON.stringify(contact) : null,
			status: 'valid',
			terms_agreed: 1,
			allow_list_json: null,
			created_at: nowIso(),
		};
		this.db
			.prepare(
				`INSERT INTO accounts(id,jwk_thumbprint,jwk_json,contact_json,status,terms_agreed,allow_list_json,created_at)
				 VALUES(@id,@jwk_thumbprint,@jwk_json,@contact_json,@status,@terms_agreed,@allow_list_json,@created_at)`,
			)
			.run(row);
		return row;
	}
	getAccount(id: string): AccountRow | undefined {
		return this.db.prepare('SELECT * FROM accounts WHERE id=?').get(id) as AccountRow | undefined;
	}
	findAccountByThumbprint(tp: string): AccountRow | undefined {
		return this.db
			.prepare('SELECT * FROM accounts WHERE jwk_thumbprint=?')
			.get(tp) as AccountRow | undefined;
	}
	updateAccountStatus(id: string, status: string): void {
		this.db.prepare('UPDATE accounts SET status=? WHERE id=?').run(status, id);
	}

	// ---- orders ----
	insertOrder(opts: {
		accountId: string;
		identifiers: Array<{type: string; value: string}>;
		notBefore: string | null;
		notAfter: string | null;
		ttlSec: number;
	}): OrderRow {
		const row: OrderRow = {
			id: ulid(),
			account_id: opts.accountId,
			status: 'pending',
			identifiers_json: JSON.stringify(opts.identifiers),
			not_before: opts.notBefore,
			not_after: opts.notAfter,
			expires_at: isoPlus(opts.ttlSec * 1000),
			error_json: null,
			certificate_id: null,
			csr_der: null,
			created_at: nowIso(),
		};
		this.db
			.prepare(
				`INSERT INTO orders(id,account_id,status,identifiers_json,not_before,not_after,expires_at,error_json,certificate_id,csr_der,created_at)
				 VALUES(@id,@account_id,@status,@identifiers_json,@not_before,@not_after,@expires_at,@error_json,@certificate_id,@csr_der,@created_at)`,
			)
			.run(row);
		return row;
	}
	getOrder(id: string): OrderRow | undefined {
		return this.db.prepare('SELECT * FROM orders WHERE id=?').get(id) as OrderRow | undefined;
	}
	setOrderStatus(id: string, status: OrderRow['status'], err?: object): void {
		this.db
			.prepare('UPDATE orders SET status=?, error_json=? WHERE id=?')
			.run(status, err ? JSON.stringify(err) : null, id);
	}
	attachCertToOrder(id: string, certId: string, csrDer: Buffer): void {
		this.db
			.prepare('UPDATE orders SET certificate_id=?, csr_der=?, status=? WHERE id=?')
			.run(certId, csrDer, 'valid', id);
	}

	// ---- authz ----
	insertAuthz(orderId: string, identifier: {type: string; value: string}, ttlSec: number): AuthzRow {
		const wildcard = identifier.value.startsWith('*.') ? 1 : 0;
		const value = wildcard ? identifier.value.slice(2) : identifier.value;
		const row: AuthzRow = {
			id: ulid(),
			order_id: orderId,
			identifier_type: identifier.type,
			identifier_value: value,
			wildcard,
			status: 'pending',
			expires_at: isoPlus(ttlSec * 1000),
			created_at: nowIso(),
		};
		this.db
			.prepare(
				`INSERT INTO authorizations(id,order_id,identifier_type,identifier_value,wildcard,status,expires_at,created_at)
				 VALUES(@id,@order_id,@identifier_type,@identifier_value,@wildcard,@status,@expires_at,@created_at)`,
			)
			.run(row);
		return row;
	}
	getAuthz(id: string): AuthzRow | undefined {
		return this.db.prepare('SELECT * FROM authorizations WHERE id=?').get(id) as
			| AuthzRow
			| undefined;
	}
	listAuthzByOrder(orderId: string): AuthzRow[] {
		return this.db
			.prepare('SELECT * FROM authorizations WHERE order_id=?')
			.all(orderId) as AuthzRow[];
	}
	setAuthzStatus(id: string, status: AuthzRow['status']): void {
		this.db.prepare('UPDATE authorizations SET status=? WHERE id=?').run(status, id);
	}

	// ---- challenges ----
	insertChallenge(authzId: string, type: 'dns-01' | 'http-01', token: string): ChallengeRow {
		const row: ChallengeRow = {
			id: ulid(),
			authz_id: authzId,
			type,
			token,
			status: 'pending',
			validated_at: null,
			error_json: null,
			attempts: 0,
			next_check_at: null,
			created_at: nowIso(),
		};
		this.db
			.prepare(
				`INSERT INTO challenges(id,authz_id,type,token,status,validated_at,error_json,attempts,next_check_at,created_at)
				 VALUES(@id,@authz_id,@type,@token,@status,@validated_at,@error_json,@attempts,@next_check_at,@created_at)`,
			)
			.run(row);
		return row;
	}
	getChallenge(id: string): ChallengeRow | undefined {
		return this.db.prepare('SELECT * FROM challenges WHERE id=?').get(id) as
			| ChallengeRow
			| undefined;
	}
	listChallengesByAuthz(authzId: string): ChallengeRow[] {
		return this.db
			.prepare('SELECT * FROM challenges WHERE authz_id=?')
			.all(authzId) as ChallengeRow[];
	}
	queueChallenge(id: string): void {
		this.db
			.prepare(
				'UPDATE challenges SET status=?, next_check_at=? WHERE id=? AND status=?',
			)
			.run('processing', nowIso(), id, 'pending');
	}
	setChallengeResult(
		id: string,
		status: ChallengeRow['status'],
		err: object | null,
		validatedAt: string | null,
		nextCheck: string | null,
		attempts: number,
	): void {
		this.db
			.prepare(
				`UPDATE challenges SET status=?, error_json=?, validated_at=?, next_check_at=?, attempts=? WHERE id=?`,
			)
			.run(
				status,
				err ? JSON.stringify(err) : null,
				validatedAt,
				nextCheck,
				attempts,
				id,
			);
	}
	dueChallenges(now: string, limit = 50): ChallengeRow[] {
		return this.db
			.prepare(
				`SELECT * FROM challenges WHERE status='processing' AND (next_check_at IS NULL OR next_check_at <= ?) LIMIT ?`,
			)
			.all(now, limit) as ChallengeRow[];
	}

	// ---- nonces ----
	storeNonce(value: string, ttlSec: number): void {
		this.db
			.prepare('INSERT OR IGNORE INTO nonces(value, expires_at, created_at) VALUES(?,?,?)')
			.run(value, isoPlus(ttlSec * 1000), nowIso());
	}
	consumeNonce(value: string): boolean {
		const r = this.db.prepare('DELETE FROM nonces WHERE value=?').run(value);
		return r.changes > 0;
	}
	purgeNonces(): void {
		this.db.prepare('DELETE FROM nonces WHERE expires_at < ?').run(nowIso());
	}

	// ---- certificates ----
	insertCert(opts: {
		orderId: string;
		accountId: string;
		serialHex: string;
		pem: string;
		chainPem: string;
		notBefore: string;
		notAfter: string;
	}): CertRow {
		const row: CertRow = {
			id: ulid(),
			order_id: opts.orderId,
			account_id: opts.accountId,
			serial_hex: opts.serialHex,
			pem: opts.pem,
			chain_pem: opts.chainPem,
			not_before: opts.notBefore,
			not_after: opts.notAfter,
			revoked: 0,
			revoked_at: null,
			revocation_reason: null,
			issued_at: nowIso(),
		};
		this.db
			.prepare(
				`INSERT INTO certificates(id,order_id,account_id,serial_hex,pem,chain_pem,not_before,not_after,revoked,revoked_at,revocation_reason,issued_at)
				 VALUES(@id,@order_id,@account_id,@serial_hex,@pem,@chain_pem,@not_before,@not_after,@revoked,@revoked_at,@revocation_reason,@issued_at)`,
			)
			.run(row);
		return row;
	}
	getCert(id: string): CertRow | undefined {
		return this.db.prepare('SELECT * FROM certificates WHERE id=?').get(id) as CertRow | undefined;
	}
	getCertBySerial(serialHex: string): CertRow | undefined {
		return this.db.prepare('SELECT * FROM certificates WHERE serial_hex=?').get(serialHex) as
			| CertRow
			| undefined;
	}
	revokeCert(id: string, reason: number): void {
		this.db
			.prepare(
				'UPDATE certificates SET revoked=1, revoked_at=?, revocation_reason=? WHERE id=?',
			)
			.run(nowIso(), reason, id);
	}

	// ---- audit ----
	audit(opts: {
		actorType: 'account' | 'system' | 'admin';
		actorId?: string | null;
		action: string;
		target?: string | null;
		ip?: string | null;
		details?: object;
	}): void {
		this.db
			.prepare(
				`INSERT INTO audit_log(id,ts,actor_type,actor_id,action,target,ip,details_json)
				 VALUES(?,?,?,?,?,?,?,?)`,
			)
			.run(
				ulid(),
				nowIso(),
				opts.actorType,
				opts.actorId ?? null,
				opts.action,
				opts.target ?? null,
				opts.ip ?? null,
				opts.details ? JSON.stringify(opts.details) : null,
			);
	}
}
