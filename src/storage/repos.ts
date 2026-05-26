import {getDb, persist} from './db.js';

export type CertType = 'ca' | 'server' | 'client';

export type CertRow = {
	id: number;
	name: string;
	type: CertType;
	common_name: string;
	organization: string | null;
	issuer_id: number | null;
	serial: string;
	not_before: string;
	not_after: string;
	san: string | null;
	cert_pem: string;
	key_pem: string;
	fingerprint: string;
	created_at: string;
	revoked_at: string | null;
	revocation_reason: string | null;
};

export type ProfileRow = {
	id: number;
	name: string;
	cert_id: number;
	format: string;
	friendly_name: string | null;
	data: Buffer;
	created_at: string;
};

export const certRepo = {
	insert(row: Omit<CertRow, 'id' | 'created_at' | 'revoked_at' | 'revocation_reason'>): number {
		const db = getDb();
		const stmt = db.prepare(`
			INSERT INTO certificates
				(name, type, common_name, organization, issuer_id, serial,
				 not_before, not_after, san, cert_pem, key_pem, fingerprint, created_at)
			VALUES
				(@name, @type, @common_name, @organization, @issuer_id, @serial,
				 @not_before, @not_after, @san, @cert_pem, @key_pem, @fingerprint, @created_at)
		`);
		const info = stmt.run({
			...row,
			created_at: new Date().toISOString(),
		});
		persist();
		return Number(info.lastInsertRowid);
	},

	list(filter?: {type?: CertType}): CertRow[] {
		const db = getDb();
		if (filter?.type) {
			return db
				.prepare('SELECT * FROM certificates WHERE type = ? ORDER BY created_at DESC')
				.all(filter.type) as CertRow[];
		}
		return db
			.prepare('SELECT * FROM certificates ORDER BY type, created_at DESC')
			.all() as CertRow[];
	},

	findById(id: number): CertRow | null {
		const db = getDb();
		return (db
			.prepare('SELECT * FROM certificates WHERE id = ?')
			.get(id) as CertRow | undefined) || null;
	},

	findByName(name: string): CertRow | null {
		const db = getDb();
		return (db
			.prepare('SELECT * FROM certificates WHERE name = ?')
			.get(name) as CertRow | undefined) || null;
	},

	findBySni(sni: string): CertRow[] {
		const db = getDb();
		const all = db
			.prepare(
				`SELECT * FROM certificates WHERE type = 'server' AND
				 (common_name = ? OR san LIKE ?)`,
			)
			.all(sni, `%"${sni}"%`) as CertRow[];
		return all;
	},

	delete(id: number): void {
		const db = getDb();
		db.prepare('DELETE FROM certificates WHERE id = ?').run(id);
		persist();
	},

	relinkIssuer(id: number, newIssuerId: number | null): void {
		const db = getDb();
		db.prepare('UPDATE certificates SET issuer_id = ? WHERE id = ?').run(
			newIssuerId,
			id,
		);
		persist();
	},

	refreshMeta(
		id: number,
		meta: {
			common_name: string;
			organization: string | null;
			serial: string;
			not_before: string;
			not_after: string;
			san: string | null;
			fingerprint: string;
		},
	): void {
		const db = getDb();
		db.prepare(
			`UPDATE certificates
			 SET common_name = @common_name,
			     organization = @organization,
			     serial = @serial,
			     not_before = @not_before,
			     not_after = @not_after,
			     san = @san,
			     fingerprint = @fingerprint
			 WHERE id = @id`,
		).run({...meta, id});
		persist();
	},

	replaceCert(
		id: number,
		row: {
			cert_pem: string;
			issuer_id: number | null;
			serial: string;
			not_before: string;
			not_after: string;
			fingerprint: string;
		},
	): void {
		const db = getDb();
		db.prepare(
			`UPDATE certificates
			 SET cert_pem = @cert_pem,
			     issuer_id = @issuer_id,
			     serial = @serial,
			     not_before = @not_before,
			     not_after = @not_after,
			     fingerprint = @fingerprint,
			     revoked_at = NULL,
			     revocation_reason = NULL
			 WHERE id = @id`,
		).run({...row, id});
		persist();
	},

	revoke(id: number, reason: string | null): void {
		const db = getDb();
		db.prepare(
			'UPDATE certificates SET revoked_at = ?, revocation_reason = ? WHERE id = ?',
		).run(new Date().toISOString(), reason, id);
		persist();
	},

	unrevoke(id: number): void {
		const db = getDb();
		db.prepare(
			'UPDATE certificates SET revoked_at = NULL, revocation_reason = NULL WHERE id = ?',
		).run(id);
		persist();
	},

	listIssuedBy(issuerId: number): CertRow[] {
		const db = getDb();
		return db
			.prepare(
				'SELECT * FROM certificates WHERE issuer_id = ? ORDER BY created_at DESC',
			)
			.all(issuerId) as CertRow[];
	},

	listRevokedBy(issuerId: number): CertRow[] {
		const db = getDb();
		return db
			.prepare(
				'SELECT * FROM certificates WHERE issuer_id = ? AND revoked_at IS NOT NULL ORDER BY revoked_at DESC',
			)
			.all(issuerId) as CertRow[];
	},
};

export type SshKeyRow = {
	id: number;
	name: string;
	algorithm: string;
	comment: string | null;
	public_key: string;
	private_key: string;
	encrypted: number; // 0 or 1
	fingerprint: string;
	created_at: string;
};

export const sshKeyRepo = {
	insert(row: Omit<SshKeyRow, 'id' | 'created_at'>): number {
		const db = getDb();
		const stmt = db.prepare(`
			INSERT INTO ssh_keys
				(name, algorithm, comment, public_key, private_key, encrypted, fingerprint, created_at)
			VALUES
				(@name, @algorithm, @comment, @public_key, @private_key, @encrypted, @fingerprint, @created_at)
		`);
		const info = stmt.run({
			...row,
			created_at: new Date().toISOString(),
		});
		persist();
		return Number(info.lastInsertRowid);
	},

	list(): SshKeyRow[] {
		const db = getDb();
		return db.prepare('SELECT * FROM ssh_keys ORDER BY created_at DESC').all() as SshKeyRow[];
	},

	findById(id: number): SshKeyRow | null {
		const db = getDb();
		return (db.prepare('SELECT * FROM ssh_keys WHERE id = ?').get(id) as SshKeyRow | undefined) || null;
	},

	findByName(name: string): SshKeyRow | null {
		const db = getDb();
		return (db.prepare('SELECT * FROM ssh_keys WHERE name = ?').get(name) as SshKeyRow | undefined) || null;
	},

	delete(id: number): void {
		const db = getDb();
		db.prepare('DELETE FROM ssh_keys WHERE id = ?').run(id);
		persist();
	},

	rename(id: number, newName: string): void {
		const db = getDb();
		db.prepare('UPDATE ssh_keys SET name = ? WHERE id = ?').run(newName, id);
		persist();
	},
};

export const profileRepo = {
	insert(row: Omit<ProfileRow, 'id' | 'created_at'>): number {
		const db = getDb();
		const stmt = db.prepare(`
			INSERT INTO profiles (name, cert_id, format, friendly_name, data, created_at)
			VALUES (@name, @cert_id, @format, @friendly_name, @data, @created_at)
		`);
		const info = stmt.run({
			...row,
			created_at: new Date().toISOString(),
		});
		persist();
		return Number(info.lastInsertRowid);
	},

	list(): ProfileRow[] {
		const db = getDb();
		return db
			.prepare('SELECT * FROM profiles ORDER BY created_at DESC')
			.all() as ProfileRow[];
	},

	findById(id: number): ProfileRow | null {
		const db = getDb();
		return (db
			.prepare('SELECT * FROM profiles WHERE id = ?')
			.get(id) as ProfileRow | undefined) || null;
	},

	findByCertId(certId: number): ProfileRow[] {
		const db = getDb();
		return db
			.prepare('SELECT * FROM profiles WHERE cert_id = ? ORDER BY created_at DESC')
			.all(certId) as ProfileRow[];
	},

	delete(id: number): void {
		const db = getDb();
		db.prepare('DELETE FROM profiles WHERE id = ?').run(id);
		persist();
	},
};
