import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';
import {
	KeyAlgorithm,
	generateKey,
	encryptPrivateKey,
	decryptPrivateKey,
	detectPrivateKeyAlgorithm,
	isEncryptedKey,
} from '../certs/keys.js';

/**
 * SSH-supported key algorithms. X25519 is **not** an SSH key algorithm —
 * X25519 in SSH appears only as a curve for key-exchange (curve25519-sha256),
 * not as a user identity key. Identity keys are Ed25519, RSA, or ECDSA.
 */
export type SshKeyAlgorithm =
	| 'ssh-ed25519'
	| 'ssh-rsa-2048'
	| 'ssh-rsa-3072'
	| 'ssh-rsa-4096'
	| 'ssh-ecdsa-p256'
	| 'ssh-ecdsa-p384';

const SSH_TO_CERT: Record<SshKeyAlgorithm, KeyAlgorithm> = {
	'ssh-ed25519': 'ed25519',
	'ssh-rsa-2048': 'rsa-2048',
	'ssh-rsa-3072': 'rsa-3072',
	'ssh-rsa-4096': 'rsa-4096',
	'ssh-ecdsa-p256': 'ecdsa-p256',
	'ssh-ecdsa-p384': 'ecdsa-p384',
};

export type GeneratedSshKey = {
	algorithm: SshKeyAlgorithm;
	/** PKCS#8 PEM (possibly encrypted if a passphrase was supplied). */
	privateKeyPem: string;
	/** Single-line OpenSSH public key (e.g. "ssh-ed25519 AAAA... comment"). */
	publicKeyOpenssh: string;
	/** RFC 4716-style SHA-256 fingerprint, e.g. "SHA256:abcd…" */
	fingerprintSha256: string;
};

export type GenerateSshKeyOptions = {
	algorithm: SshKeyAlgorithm;
	comment?: string;
	/** If set, the returned private key is encrypted (PKCS#8 / AES-256-CBC). */
	passphrase?: string | null;
};

export function generateSshKey(opts: GenerateSshKeyOptions): GeneratedSshKey {
	const baseAlg = SSH_TO_CERT[opts.algorithm];
	if (!baseAlg) throw new Error(`Unsupported SSH algorithm: ${opts.algorithm}`);
	const k = generateKey(baseAlg);
	const publicKeyOpenssh = formatOpenSshPublic(k.publicKeyPem, opts.comment);
	const fingerprintSha256 = sshFingerprintSha256(publicKeyOpenssh);
	let priv = k.privateKeyPem;
	if (opts.passphrase) priv = encryptPrivateKey(priv, opts.passphrase);
	return {
		algorithm: opts.algorithm,
		privateKeyPem: priv,
		publicKeyOpenssh,
		fingerprintSha256,
	};
}

/**
 * Re-derive the OpenSSH single-line public-key string from a private-key PEM
 * (optionally encrypted). Used when you have only a stored private key and
 * want to regenerate the .pub.
 */
export function publicFromPrivate(
	privateKeyPem: string,
	passphrase: string | null,
	comment?: string,
): string {
	const plain = isEncryptedKey(privateKeyPem)
		? decryptPrivateKey(privateKeyPem, passphrase)
		: privateKeyPem;
	const pub = crypto.createPublicKey(plain);
	const pubPem = pub.export({type: 'spki', format: 'pem'}) as string;
	return formatOpenSshPublic(pubPem, comment);
}

export function detectSshAlgorithmOf(privateKeyPem: string, passphrase?: string | null): SshKeyAlgorithm {
	const baseAlg = detectPrivateKeyAlgorithm(privateKeyPem, passphrase ?? null);
	for (const [ssh, base] of Object.entries(SSH_TO_CERT)) {
		if (base === baseAlg) return ssh as SshKeyAlgorithm;
	}
	throw new Error(`Cannot map algorithm ${baseAlg} to an SSH identity type`);
}

// ---------- OpenSSH public-key encoding ----------

/** Format an SSH wire-string: 4-byte BE length + bytes. */
function sshString(buf: Buffer): Buffer {
	const len = Buffer.alloc(4);
	len.writeUInt32BE(buf.length, 0);
	return Buffer.concat([len, buf]);
}
/** Format an SSH mpint: BE 2's-complement, prepend 0x00 if MSB is set. */
function sshMpint(bytes: Buffer): Buffer {
	let b = bytes;
	// strip leading zeros (canonicalise) but keep one if needed for sign
	let i = 0;
	while (i < b.length - 1 && b[i] === 0) i++;
	b = b.subarray(i);
	if (b[0]! & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
	return sshString(b);
}

function b64urlToBuf(s: string): Buffer {
	return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

/**
 * Build the OpenSSH one-line public-key encoding for any RSA/Ed25519/ECDSA
 * SPKI PEM. Form: `<algo> <base64-blob> [comment]`.
 */
export function formatOpenSshPublic(publicKeyPem: string, comment?: string): string {
	const pub = crypto.createPublicKey(publicKeyPem);
	const jwk = pub.export({format: 'jwk'}) as any;
	let algoName: string;
	let blob: Buffer;

	if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
		algoName = 'ssh-ed25519';
		const x = b64urlToBuf(jwk.x);
		blob = Buffer.concat([sshString(Buffer.from(algoName)), sshString(x)]);
	} else if (jwk.kty === 'RSA') {
		algoName = 'ssh-rsa';
		const n = b64urlToBuf(jwk.n);
		const e = b64urlToBuf(jwk.e);
		blob = Buffer.concat([sshString(Buffer.from(algoName)), sshMpint(e), sshMpint(n)]);
	} else if (jwk.kty === 'EC') {
		const curve = jwk.crv;
		let curveName: string;
		let sshCurve: string;
		if (curve === 'P-256') {
			curveName = 'nistp256';
			sshCurve = 'nistp256';
			algoName = 'ecdsa-sha2-nistp256';
		} else if (curve === 'P-384') {
			curveName = 'nistp384';
			sshCurve = 'nistp384';
			algoName = 'ecdsa-sha2-nistp384';
		} else {
			throw new Error(`Unsupported EC curve for SSH: ${curve}`);
		}
		const x = b64urlToBuf(jwk.x);
		const y = b64urlToBuf(jwk.y);
		const fieldLen = curveName === 'nistp256' ? 32 : 48;
		const point = Buffer.concat([
			Buffer.from([0x04]),
			padLeft(x, fieldLen),
			padLeft(y, fieldLen),
		]);
		blob = Buffer.concat([
			sshString(Buffer.from(algoName)),
			sshString(Buffer.from(sshCurve)),
			sshString(point),
		]);
	} else {
		throw new Error(`Unsupported key type for SSH: ${jwk.kty}/${jwk.crv ?? ''}`);
	}

	const line = `${algoName} ${blob.toString('base64')}`;
	return comment ? `${line} ${comment}` : line;
}

function padLeft(b: Buffer, len: number): Buffer {
	if (b.length === len) return b;
	if (b.length > len) {
		// strip leading zero(s) from base64url-decoded value
		let i = 0;
		while (i < b.length - len && b[i] === 0) i++;
		const stripped = b.subarray(i);
		if (stripped.length === len) return stripped;
		throw new Error(`EC coord wrong size: have ${b.length}, need ${len}`);
	}
	return Buffer.concat([Buffer.alloc(len - b.length, 0), b]);
}

/** Compute the standard OpenSSH SHA-256 fingerprint of a public-key line. */
export function sshFingerprintSha256(publicKeyOpenssh: string): string {
	const parts = publicKeyOpenssh.trim().split(/\s+/);
	const blobB64 = parts[1];
	if (!blobB64) throw new Error('Malformed OpenSSH public key');
	const blob = Buffer.from(blobB64, 'base64');
	const digest = crypto.createHash('sha256').update(blob).digest('base64');
	// OpenSSH strips trailing "=" padding from fingerprint base64.
	return 'SHA256:' + digest.replace(/=+$/, '');
}

// ---------- OpenSSH private-key encoding ----------

/**
 * Render a private key in the OpenSSH v1 format (the `BEGIN OPENSSH PRIVATE
 * KEY` envelope produced by `ssh-keygen` 6.5+). PKCS#8 is fine for many tools
 * but `ssh-keygen` refuses to read PKCS#8 Ed25519 keys — and many SSH agents
 * are similarly picky — so for ~/.ssh export we always emit OpenSSH format.
 *
 * Unencrypted only. Pass through `ssh-keygen -p` (or our own helper) to add a
 * passphrase if you need at-rest encryption on disk.
 */
export function toOpenSshPrivateKey(plainPem: string, comment: string = ''): string {
	const pub = crypto.createPublicKey(plainPem);
	const priv = crypto.createPrivateKey(plainPem);
	const jwkPub = pub.export({format: 'jwk'}) as any;
	const jwkPriv = priv.export({format: 'jwk'}) as any;

	let pubBlob: Buffer;
	let privFields: Buffer;
	let algoName: string;

	if (jwkPub.kty === 'OKP' && jwkPub.crv === 'Ed25519') {
		algoName = 'ssh-ed25519';
		const pubKey = b64urlToBuf(jwkPub.x);
		const privKey = b64urlToBuf(jwkPriv.d);
		pubBlob = Buffer.concat([sshString(Buffer.from(algoName)), sshString(pubKey)]);
		privFields = Buffer.concat([
			sshString(pubKey),
			sshString(Buffer.concat([privKey, pubKey])), // 64-byte combined seed||pub
		]);
	} else if (jwkPub.kty === 'RSA') {
		algoName = 'ssh-rsa';
		const n = b64urlToBuf(jwkPub.n);
		const e = b64urlToBuf(jwkPub.e);
		const d = b64urlToBuf(jwkPriv.d);
		const p = b64urlToBuf(jwkPriv.p);
		const q = b64urlToBuf(jwkPriv.q);
		const iqmp = b64urlToBuf(jwkPriv.qi);
		pubBlob = Buffer.concat([sshString(Buffer.from(algoName)), sshMpint(e), sshMpint(n)]);
		privFields = Buffer.concat([
			sshMpint(n),
			sshMpint(e),
			sshMpint(d),
			sshMpint(iqmp),
			sshMpint(p),
			sshMpint(q),
		]);
	} else if (jwkPub.kty === 'EC') {
		const curve = jwkPub.crv;
		const curveName = curve === 'P-256' ? 'nistp256' : 'nistp384';
		algoName = curve === 'P-256' ? 'ecdsa-sha2-nistp256' : 'ecdsa-sha2-nistp384';
		const fieldLen = curve === 'P-256' ? 32 : 48;
		const x = padLeft(b64urlToBuf(jwkPub.x), fieldLen);
		const y = padLeft(b64urlToBuf(jwkPub.y), fieldLen);
		const point = Buffer.concat([Buffer.from([0x04]), x, y]);
		const d = b64urlToBuf(jwkPriv.d);
		pubBlob = Buffer.concat([
			sshString(Buffer.from(algoName)),
			sshString(Buffer.from(curveName)),
			sshString(point),
		]);
		privFields = Buffer.concat([
			sshString(Buffer.from(curveName)),
			sshString(point),
			sshMpint(d),
		]);
	} else {
		throw new Error(`Unsupported key type for OpenSSH private export: ${jwkPub.kty}`);
	}

	// Random "check" integer that appears twice — used by openssh to verify
	// decryption worked. For unencrypted keys it's purely structural.
	const check = crypto.randomBytes(4);
	const commentBuf = Buffer.from(comment ?? '', 'utf8');
	let privSection = Buffer.concat([
		check,
		check,
		sshString(Buffer.from(algoName)),
		privFields,
		sshString(commentBuf),
	]);

	// Pad to a multiple of the cipher block size (1 byte for "none" cipher).
	// OpenSSH still requires *some* padding to detect truncation: bytes are
	// 1, 2, 3, … such that the total reaches the next block boundary.
	const blockSize = 8; // openssh always pads to at least 8 even for "none"
	const padNeeded = (blockSize - (privSection.length % blockSize)) % blockSize;
	if (padNeeded > 0) {
		const pad = Buffer.alloc(padNeeded);
		for (let i = 0; i < padNeeded; i++) pad[i] = i + 1;
		privSection = Buffer.concat([privSection, pad]);
	}

	const magic = Buffer.from('openssh-key-v1\x00', 'utf8');
	const body = Buffer.concat([
		magic,
		sshString(Buffer.from('none')),  // ciphername
		sshString(Buffer.from('none')),  // kdfname
		sshString(Buffer.alloc(0)),       // kdfoptions
		uint32(1),                        // number of keys
		sshString(pubBlob),
		sshString(privSection),
	]);

	const b64 = body.toString('base64');
	// Wrap at 70 chars like openssh does.
	const wrapped = b64.match(/.{1,70}/g)!.join('\n');
	return `-----BEGIN OPENSSH PRIVATE KEY-----\n${wrapped}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

function uint32(n: number): Buffer {
	const b = Buffer.alloc(4);
	b.writeUInt32BE(n, 0);
	return b;
}

// ---------- File-system export (~/.ssh) ----------

export type ExportToSshFolderOptions = {
	name: string;
	privateKeyPem: string;
	publicKeyOpenssh: string;
	/** Override target dir (defaults to ~/.ssh, or $HOME/.ssh). */
	dir?: string;
	/** If true and the target file exists, throw instead of overwriting. */
	noOverwrite?: boolean;
	/**
	 * Passphrase for the stored private key — required if `privateKeyPem` is
	 * encrypted. The key is always written to disk *unencrypted* in OpenSSH
	 * format so `ssh` and `ssh-agent` accept it. Set `keepEncrypted: true` to
	 * write the original encrypted PKCS#8 instead.
	 */
	passphrase?: string | null;
	/** Optional comment to embed in the OpenSSH private key. */
	comment?: string;
	/** Skip OpenSSH conversion; write the PEM as-is (encrypted included). */
	keepEncrypted?: boolean;
};

export type ExportedSshFiles = {
	privateKeyPath: string;
	publicKeyPath: string;
};

/**
 * Write a key pair to ~/.ssh/<name> and ~/.ssh/<name>.pub with secure perms.
 * By default the private key is converted to OpenSSH v1 format so all SSH
 * tools (including ssh-keygen for Ed25519) can read it. Returns the absolute
 * paths written.
 */
export function exportToSshFolder(opts: ExportToSshFolderOptions): ExportedSshFiles {
	const dir = opts.dir ?? path.join(os.homedir(), '.ssh');
	fs.mkdirSync(dir, {recursive: true, mode: 0o700});
	if (process.platform !== 'win32') {
		try {
			fs.chmodSync(dir, 0o700);
		} catch {}
	}
	const privPath = path.join(dir, opts.name);
	const pubPath = path.join(dir, `${opts.name}.pub`);
	if (opts.noOverwrite) {
		if (fs.existsSync(privPath)) throw new Error(`Refusing to overwrite ${privPath}`);
		if (fs.existsSync(pubPath)) throw new Error(`Refusing to overwrite ${pubPath}`);
	}

	let privateBody: string;
	if (opts.keepEncrypted) {
		privateBody = opts.privateKeyPem;
	} else {
		const plain = isEncryptedKey(opts.privateKeyPem)
			? decryptPrivateKey(opts.privateKeyPem, opts.passphrase ?? null)
			: opts.privateKeyPem;
		privateBody = toOpenSshPrivateKey(plain, opts.comment ?? '');
	}

	fs.writeFileSync(privPath, privateBody, {mode: 0o600});
	fs.writeFileSync(pubPath, opts.publicKeyOpenssh + '\n', {mode: 0o644});
	return {privateKeyPath: privPath, publicKeyPath: pubPath};
}
