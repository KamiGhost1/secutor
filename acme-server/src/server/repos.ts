import type Database from 'better-sqlite3';
import {ulid} from 'ulid';
import {nowIso, isoPlus} from './util.js';

export type AccountRow = {
	id: string;
	jwk_thumbprint: string;
	jwk_json: string;
	contact_json: string | null;
	status: string; // 'valid' | 'deactivated' | 'banned'
	terms_agreed: number;
	allow_list_json: string | null;
	created_at: string;
	deactivated_at?: string | null;
};

export type OrderStatus =
	| 'pending'
	| 'ready'
	| 'processing'
	| 'valid'
	| 'invalid'
	| 'expired';

export type OrderRow = {
	id: string;
	account_id: string;
	status: OrderStatus;
	identifiers_json: string;
	not_before: string | null;
	not_after: string | null;
	expires_at: string;
	error_json: string | null;
	certificate_id: string | null;
	csr_der: Buffer | null;
	created_at: string;
	dns_placement?: 'client' | 'server-managed' | null;
};

export type DnsPlacementRow = {
	id: string;
	challenge_id: string;
	record_name: string;
	record_value: string;
	provider_label: string;
	placed_at: string;
	cleaned_at: string | null;
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
	revoked_by?: string | null;
	revoke_event_id?: string | null;
	/** JSON array of dns identifiers (wildcards keep `*.` prefix). NULL on rows from
	 * pre-migration-0005 deployments — backfill runs once at startup. */
	identifiers_json?: string | null;
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
		dnsPlacement?: 'client' | 'server-managed';
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
			dns_placement: opts.dnsPlacement ?? 'client',
		};
		this.db
			.prepare(
				`INSERT INTO orders(id,account_id,status,identifiers_json,not_before,not_after,expires_at,error_json,certificate_id,csr_der,created_at,dns_placement)
				 VALUES(@id,@account_id,@status,@identifiers_json,@not_before,@not_after,@expires_at,@error_json,@certificate_id,@csr_der,@created_at,@dns_placement)`,
			)
			.run(row);
		return row;
	}
	getOrder(id: string): OrderRow | undefined {
		return this.db.prepare('SELECT * FROM orders WHERE id=?').get(id) as OrderRow | undefined;
	}
	setOrderStatus(id: string, status: OrderStatus, err?: object): void {
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
		/** Optional explicit identifiers. If omitted, the value is left NULL
		 * and reconstructed by the next listCertificates() call (or the
		 * 0005 backfill at startup). New writers — always pass it. */
		identifiers?: string[];
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
			identifiers_json: opts.identifiers ? JSON.stringify(opts.identifiers) : null,
		};
		this.db
			.prepare(
				`INSERT INTO certificates(id,order_id,account_id,serial_hex,pem,chain_pem,not_before,not_after,revoked,revoked_at,revocation_reason,issued_at,identifiers_json)
				 VALUES(@id,@order_id,@account_id,@serial_hex,@pem,@chain_pem,@not_before,@not_after,@revoked,@revoked_at,@revocation_reason,@issued_at,@identifiers_json)`,
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
	revokeCert(id: string, reason: number, by?: string, eventId?: string): void {
		this.db
			.prepare(
				`UPDATE certificates SET revoked=1, revoked_at=?, revocation_reason=?, revoked_by=?, revoke_event_id=?
				 WHERE id=?`,
			)
			.run(nowIso(), reason, by ?? null, eventId ?? null, id);
	}

	// ---- audit ----
	audit(opts: {
		actorType: 'account' | 'system' | 'admin';
		actorId?: string | null;
		action: string;
		target?: string | null;
		ip?: string | null;
		details?: object;
	}): string {
		const id = ulid();
		this.db
			.prepare(
				`INSERT INTO audit_log(id,ts,actor_type,actor_id,action,target,ip,details_json)
				 VALUES(?,?,?,?,?,?,?,?)`,
			)
			.run(
				id,
				nowIso(),
				opts.actorType,
				opts.actorId ?? null,
				opts.action,
				opts.target ?? null,
				opts.ip ?? null,
				opts.details ? JSON.stringify(opts.details) : null,
			);
		return id;
	}

	/* ──────────────────── admin-API helpers ──────────────────── */

	listAccounts(opts?: {limit?: number; offset?: number}): AccountRow[] {
		const limit = Math.min(opts?.limit ?? 200, 500);
		const offset = opts?.offset ?? 0;
		return this.db
			.prepare('SELECT * FROM accounts ORDER BY created_at DESC LIMIT ? OFFSET ?')
			.all(limit, offset) as AccountRow[];
	}

	updateAccount(id: string, patch: {status?: string; allowList?: string[] | null; contact?: string[] | null}): void {
		const sets: string[] = [];
		const args: any[] = [];
		if (patch.status !== undefined) {
			sets.push('status=?');
			args.push(patch.status);
			if (patch.status !== 'valid') {
				sets.push('deactivated_at=?');
				args.push(nowIso());
			} else {
				sets.push('deactivated_at=NULL');
			}
		}
		if (patch.allowList !== undefined) {
			sets.push('allow_list_json=?');
			args.push(patch.allowList ? JSON.stringify(patch.allowList) : null);
		}
		if (patch.contact !== undefined) {
			sets.push('contact_json=?');
			args.push(patch.contact ? JSON.stringify(patch.contact) : null);
		}
		if (!sets.length) return;
		args.push(id);
		this.db.prepare(`UPDATE accounts SET ${sets.join(', ')} WHERE id=?`).run(...args);
	}

	listCertificates(opts: {
		limit?: number;
		offset?: number;
		accountId?: string;
		revoked?: boolean;
		identifier?: string;
		issuedAfter?: string;
		issuedBefore?: string;
		expiresBefore?: string;
		serialHex?: string;
	}): Array<CertRow & {identifiers: string[]}> {
		const limit = Math.min(opts.limit ?? 100, 500);
		const offset = opts.offset ?? 0;
		const where: string[] = [];
		const args: any[] = [];
		if (opts.accountId) { where.push('account_id=?'); args.push(opts.accountId); }
		if (opts.revoked !== undefined) { where.push('revoked=?'); args.push(opts.revoked ? 1 : 0); }
		if (opts.issuedAfter) { where.push('issued_at>=?'); args.push(opts.issuedAfter); }
		if (opts.issuedBefore) { where.push('issued_at<?'); args.push(opts.issuedBefore); }
		if (opts.expiresBefore) { where.push('not_after<?'); args.push(opts.expiresBefore); }
		if (opts.serialHex) { where.push('serial_hex=?'); args.push(opts.serialHex); }
		if (opts.identifier) {
			// Substring-match on the JSON array. Quotes scope the match to a
			// single complete identifier — `?identifier=lan.vpn` does NOT
			// match `svc.lan.vpn` (only the exact value); use `*.lan.vpn`
			// explicitly to match a wildcard entry.
			where.push('identifiers_json LIKE ?');
			args.push(`%"${opts.identifier}"%`);
		}
		const sql =
			`SELECT * FROM certificates` +
			(where.length ? ` WHERE ${where.join(' AND ')}` : '') +
			` ORDER BY issued_at DESC LIMIT ? OFFSET ?`;
		args.push(limit, offset);
		const rows = this.db.prepare(sql).all(...args) as CertRow[];
		return rows.map(r => ({...r, identifiers: parseIdentifiers(r.identifiers_json)}));
	}

	/** Returns a row with `identifiers: string[]` (always present, possibly empty). */
	getCertWithIdentifiers(id: string): (CertRow & {identifiers: string[]}) | undefined {
		const row = this.getCert(id);
		if (!row) return undefined;
		return {...row, identifiers: parseIdentifiers(row.identifiers_json)};
	}

	listOrders(opts: {
		limit?: number;
		offset?: number;
		status?: OrderStatus;
		accountId?: string;
		since?: string;
		until?: string;
	}): OrderRow[] {
		const limit = Math.min(opts.limit ?? 100, 500);
		const offset = opts.offset ?? 0;
		const where: string[] = [];
		const args: any[] = [];
		if (opts.status) { where.push('status=?'); args.push(opts.status); }
		if (opts.accountId) { where.push('account_id=?'); args.push(opts.accountId); }
		if (opts.since) { where.push('created_at>=?'); args.push(opts.since); }
		if (opts.until) { where.push('created_at<?'); args.push(opts.until); }
		const sql =
			`SELECT * FROM orders` +
			(where.length ? ` WHERE ${where.join(' AND ')}` : '') +
			` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
		args.push(limit, offset);
		return this.db.prepare(sql).all(...args) as OrderRow[];
	}

	listAuditLog(opts: {
		limit?: number;
		offset?: number;
		action?: string;
		actorId?: string;
		target?: string;
		since?: string;
	}): Array<{
		id: string;
		ts: string;
		actor_type: string;
		actor_id: string | null;
		action: string;
		target: string | null;
		ip: string | null;
		details_json: string | null;
	}> {
		const limit = Math.min(opts.limit ?? 100, 500);
		const offset = opts.offset ?? 0;
		const where: string[] = [];
		const args: any[] = [];
		if (opts.action) { where.push('action=?'); args.push(opts.action); }
		if (opts.actorId) { where.push('actor_id=?'); args.push(opts.actorId); }
		if (opts.target) { where.push('target=?'); args.push(opts.target); }
		if (opts.since) { where.push('ts>=?'); args.push(opts.since); }
		const sql =
			`SELECT * FROM audit_log` +
			(where.length ? ` WHERE ${where.join(' AND ')}` : '') +
			` ORDER BY ts DESC LIMIT ? OFFSET ?`;
		args.push(limit, offset);
		return this.db.prepare(sql).all(...args) as any;
	}

	/* ──────────── stats ──────────── */

	countOrdersByStatus(opts: {since?: string; until?: string}): Record<OrderStatus, number> & {total: number} {
		const where: string[] = [];
		const args: any[] = [];
		if (opts.since) { where.push('created_at>=?'); args.push(opts.since); }
		if (opts.until) { where.push('created_at<?'); args.push(opts.until); }
		const w = where.length ? ` WHERE ${where.join(' AND ')}` : '';
		const rows = this.db
			.prepare(`SELECT status, COUNT(*) AS n FROM orders${w} GROUP BY status`)
			.all(...args) as Array<{status: OrderStatus; n: number}>;
		const out = {
			pending: 0, ready: 0, processing: 0, valid: 0, invalid: 0, expired: 0,
			total: 0,
		} as Record<OrderStatus, number> & {total: number};
		for (const r of rows) {
			out[r.status] = r.n;
			out.total += r.n;
		}
		return out;
	}

	bucketOrders(opts: {since?: string; until?: string; bucket: 'day' | 'hour'}): Array<{
		ts: string;
		total: number;
		valid: number;
		invalid: number;
		expired: number;
	}> {
		const fmt = opts.bucket === 'hour' ? '%Y-%m-%d %H:00' : '%Y-%m-%d';
		const where: string[] = [];
		const args: any[] = [];
		if (opts.since) { where.push('created_at>=?'); args.push(opts.since); }
		if (opts.until) { where.push('created_at<?'); args.push(opts.until); }
		const w = where.length ? ` WHERE ${where.join(' AND ')}` : '';
		return this.db
			.prepare(
				`SELECT strftime('${fmt}', created_at) AS ts,
				        COUNT(*) AS total,
				        SUM(CASE WHEN status='valid'   THEN 1 ELSE 0 END) AS valid,
				        SUM(CASE WHEN status='invalid' THEN 1 ELSE 0 END) AS invalid,
				        SUM(CASE WHEN status='expired' THEN 1 ELSE 0 END) AS expired
				   FROM orders${w}
				  GROUP BY ts ORDER BY ts ASC`,
			)
			.all(...args) as any;
	}

	failureBreakdown(opts: {since?: string; until?: string}): {
		totalInvalid: number;
		byProblemType: Array<{type: string; count: number}>;
		byChallengeType: Record<string, number>;
		topFailingIdentifiers: Array<{value: string; count: number}>;
	} {
		const where: string[] = [];
		const args: any[] = [];
		if (opts.since) { where.push('o.created_at>=?'); args.push(opts.since); }
		if (opts.until) { where.push('o.created_at<?'); args.push(opts.until); }
		const w = where.length ? ` AND ${where.join(' AND ')}` : '';
		const totalRow = this.db
			.prepare(`SELECT COUNT(*) AS n FROM orders o WHERE o.status='invalid'${w}`)
			.get(...args) as {n: number};

		// Problem types from orders.error_json.type. SQLite has json_extract.
		const probRows = this.db
			.prepare(
				`SELECT json_extract(o.error_json, '$.type') AS type, COUNT(*) AS n
				   FROM orders o WHERE o.status='invalid' AND o.error_json IS NOT NULL${w}
				  GROUP BY type ORDER BY n DESC LIMIT 20`,
			)
			.all(...args) as Array<{type: string | null; n: number}>;

		const chRows = this.db
			.prepare(
				`SELECT ch.type AS type, COUNT(*) AS n
				   FROM challenges ch
				   JOIN authorizations az ON az.id = ch.authz_id
				   JOIN orders o ON o.id = az.order_id
				  WHERE ch.status='invalid'${w}
				  GROUP BY ch.type`,
			)
			.all(...args) as Array<{type: string; n: number}>;

		const idRows = this.db
			.prepare(
				`SELECT az.identifier_value AS value, COUNT(*) AS n
				   FROM authorizations az
				   JOIN orders o ON o.id = az.order_id
				  WHERE az.status IN ('invalid','expired') AND o.status IN ('invalid','expired')${w}
				  GROUP BY az.identifier_value ORDER BY n DESC LIMIT 10`,
			)
			.all(...args) as Array<{value: string; n: number}>;

		const byChallengeType: Record<string, number> = {};
		for (const r of chRows) byChallengeType[r.type] = r.n;

		return {
			totalInvalid: totalRow.n,
			byProblemType: probRows
				.filter(r => r.type)
				.map(r => ({type: r.type as string, count: r.n})),
			byChallengeType,
			topFailingIdentifiers: idRows.map(r => ({value: r.value, count: r.n})),
		};
	}

	issuanceSeries(opts: {since?: string; until?: string; bucket: 'day' | 'hour'}): Array<{
		ts: string;
		issued: number;
		revoked: number;
	}> {
		const fmt = opts.bucket === 'hour' ? '%Y-%m-%d %H:00' : '%Y-%m-%d';
		const where: string[] = [];
		const args: any[] = [];
		if (opts.since) { where.push('issued_at>=?'); args.push(opts.since); }
		if (opts.until) { where.push('issued_at<?'); args.push(opts.until); }
		const w = where.length ? ` WHERE ${where.join(' AND ')}` : '';
		const issued = this.db
			.prepare(
				`SELECT strftime('${fmt}', issued_at) AS ts, COUNT(*) AS n
				   FROM certificates${w}
				  GROUP BY ts ORDER BY ts ASC`,
			)
			.all(...args) as Array<{ts: string; n: number}>;
		// Revoked uses revoked_at instead — separate query, then merge.
		const where2: string[] = ['revoked=1'];
		const args2: any[] = [];
		if (opts.since) { where2.push('revoked_at>=?'); args2.push(opts.since); }
		if (opts.until) { where2.push('revoked_at<?'); args2.push(opts.until); }
		const revoked = this.db
			.prepare(
				`SELECT strftime('${fmt}', revoked_at) AS ts, COUNT(*) AS n
				   FROM certificates WHERE ${where2.join(' AND ')}
				  GROUP BY ts ORDER BY ts ASC`,
			)
			.all(...args2) as Array<{ts: string; n: number}>;
		const merged = new Map<string, {ts: string; issued: number; revoked: number}>();
		for (const r of issued) merged.set(r.ts, {ts: r.ts, issued: r.n, revoked: 0});
		for (const r of revoked) {
			const e = merged.get(r.ts) ?? {ts: r.ts, issued: 0, revoked: 0};
			e.revoked = r.n;
			merged.set(r.ts, e);
		}
		return Array.from(merged.values()).sort((a, b) => (a.ts < b.ts ? -1 : 1));
	}

	/* ──────────── ban: list active certs for an account ──────────── */

	listActiveCertsForAccount(accountId: string): CertRow[] {
		return this.db
			.prepare(
				`SELECT * FROM certificates WHERE account_id=? AND revoked=0 AND not_after > ?`,
			)
			.all(accountId, nowIso()) as CertRow[];
	}

	listOpenOrdersForAccount(accountId: string): OrderRow[] {
		return this.db
			.prepare(
				`SELECT * FROM orders WHERE account_id=? AND status IN ('pending','ready','processing')`,
			)
			.all(accountId) as OrderRow[];
	}

	/* ──────────── expire-tick used by background worker ──────────── */

	expireDueOrders(): number {
		const r = this.db
			.prepare(
				`UPDATE orders SET status='expired'
				 WHERE status IN ('pending','ready','processing') AND expires_at < ?`,
			)
			.run(nowIso());
		return r.changes;
	}

	expireDueAuthz(): number {
		const r = this.db
			.prepare(
				`UPDATE authorizations SET status='expired'
				 WHERE status='pending' AND expires_at < ?`,
			)
			.run(nowIso());
		return r.changes;
	}

	/* ──────────── server-managed DNS placements ──────────── */

	insertPlacement(opts: {
		challengeId: string;
		recordName: string;
		recordValue: string;
		providerLabel: string;
	}): DnsPlacementRow {
		const row: DnsPlacementRow = {
			id: ulid(),
			challenge_id: opts.challengeId,
			record_name: opts.recordName,
			record_value: opts.recordValue,
			provider_label: opts.providerLabel,
			placed_at: nowIso(),
			cleaned_at: null,
		};
		this.db
			.prepare(
				`INSERT INTO dns_placements(id,challenge_id,record_name,record_value,provider_label,placed_at,cleaned_at)
				 VALUES(@id,@challenge_id,@record_name,@record_value,@provider_label,@placed_at,@cleaned_at)`,
			)
			.run(row);
		return row;
	}

	markPlacementCleaned(id: string): void {
		this.db.prepare('UPDATE dns_placements SET cleaned_at=? WHERE id=?').run(nowIso(), id);
	}

	listOpenPlacements(): DnsPlacementRow[] {
		return this.db
			.prepare('SELECT * FROM dns_placements WHERE cleaned_at IS NULL ORDER BY placed_at ASC')
			.all() as DnsPlacementRow[];
	}

	listPlacementsForChallenge(challengeId: string): DnsPlacementRow[] {
		return this.db
			.prepare(
				'SELECT * FROM dns_placements WHERE challenge_id=? AND cleaned_at IS NULL',
			)
			.all(challengeId) as DnsPlacementRow[];
	}

	/* ──────────── reissue jobs ──────────── */

	createReissueJob(opts: {
		scope: string;
		params: object;
		ratePerSec: number;
		certIds: string[];
		actorFp: string | null;
	}): ReissueJobRow {
		const id = ulid();
		const job: ReissueJobRow = {
			id,
			scope: opts.scope,
			params_json: JSON.stringify(opts.params),
			status: 'running',
			total: opts.certIds.length,
			done: 0,
			failed: 0,
			rate_per_sec: opts.ratePerSec,
			started_at: nowIso(),
			finished_at: null,
			actor_fp: opts.actorFp,
		};
		const insertJob = this.db.prepare(
			`INSERT INTO reissue_jobs(id,scope,params_json,status,total,done,failed,rate_per_sec,started_at,finished_at,actor_fp)
			 VALUES(@id,@scope,@params_json,@status,@total,@done,@failed,@rate_per_sec,@started_at,@finished_at,@actor_fp)`,
		);
		const insertItem = this.db.prepare(
			`INSERT INTO reissue_job_items(id,job_id,cert_id,status,error,finished_at)
			 VALUES(?,?,?,?,NULL,NULL)`,
		);
		this.db.transaction(() => {
			insertJob.run(job);
			for (const cid of opts.certIds) insertItem.run(ulid(), id, cid, 'pending');
		})();
		return job;
	}

	getReissueJob(id: string): ReissueJobRow | undefined {
		return this.db.prepare('SELECT * FROM reissue_jobs WHERE id=?').get(id) as
			| ReissueJobRow
			| undefined;
	}

	listReissueJobs(opts?: {limit?: number; status?: string}): ReissueJobRow[] {
		const lim = Math.min(opts?.limit ?? 50, 200);
		if (opts?.status) {
			return this.db
				.prepare('SELECT * FROM reissue_jobs WHERE status=? ORDER BY started_at DESC LIMIT ?')
				.all(opts.status, lim) as ReissueJobRow[];
		}
		return this.db
			.prepare('SELECT * FROM reissue_jobs ORDER BY started_at DESC LIMIT ?')
			.all(lim) as ReissueJobRow[];
	}

	listReissueJobItems(jobId: string, status?: string): ReissueJobItemRow[] {
		if (status) {
			return this.db
				.prepare('SELECT * FROM reissue_job_items WHERE job_id=? AND status=? ORDER BY id ASC')
				.all(jobId, status) as ReissueJobItemRow[];
		}
		return this.db
			.prepare('SELECT * FROM reissue_job_items WHERE job_id=? ORDER BY id ASC')
			.all(jobId) as ReissueJobItemRow[];
	}

	updateReissueItem(id: string, status: 'done' | 'failed', error?: string): void {
		this.db
			.prepare('UPDATE reissue_job_items SET status=?, error=?, finished_at=? WHERE id=?')
			.run(status, error ?? null, nowIso(), id);
	}

	incReissueJobCounter(jobId: string, field: 'done' | 'failed'): void {
		this.db.prepare(`UPDATE reissue_jobs SET ${field}=${field}+1 WHERE id=?`).run(jobId);
	}

	finishReissueJob(jobId: string, status: 'done' | 'failed' | 'cancelled'): void {
		this.db
			.prepare('UPDATE reissue_jobs SET status=?, finished_at=? WHERE id=?')
			.run(status, nowIso(), jobId);
	}

	/** Replace the PEM/serial/notBefore/notAfter of an existing cert row in place.
	 * Used after a successful resign — same cert row id, new bytes. */
	replaceCertPem(id: string, opts: {pem: string; serialHex: string; notBefore: string; notAfter: string}): void {
		this.db
			.prepare(
				`UPDATE certificates SET pem=?, serial_hex=?, not_before=?, not_after=? WHERE id=?`,
			)
			.run(opts.pem, opts.serialHex, opts.notBefore, opts.notAfter, id);
	}

	/** All non-revoked, non-expired certs — the default scope for reissue=all-active. */
	listActiveCerts(): CertRow[] {
		return this.db
			.prepare(
				`SELECT * FROM certificates WHERE revoked=0 AND not_after > ? ORDER BY issued_at ASC`,
			)
			.all(nowIso()) as CertRow[];
	}
}

export type ReissueJobRow = {
	id: string;
	scope: string;
	params_json: string | null;
	status: 'running' | 'done' | 'failed' | 'cancelled';
	total: number;
	done: number;
	failed: number;
	rate_per_sec: number;
	started_at: string;
	finished_at: string | null;
	actor_fp: string | null;
};

/** Parse the denormalised identifiers JSON column safely. */
export function parseIdentifiers(raw: string | null | undefined): string[] {
	if (!raw) return [];
	try {
		const v = JSON.parse(raw);
		return Array.isArray(v) ? v.filter((s): s is string => typeof s === 'string') : [];
	} catch {
		return [];
	}
}

export type ReissueJobItemRow = {
	id: string;
	job_id: string;
	cert_id: string;
	status: 'pending' | 'done' | 'failed';
	error: string | null;
	finished_at: string | null;
};
