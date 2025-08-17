import crypto from 'crypto';

const MAGIC = Buffer.from('CMGR1', 'utf8');
const KDF_ITERS = 200_000;
const KEY_LEN = 32;
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;

export function deriveKey(password: string, salt: Buffer, iters = KDF_ITERS): Buffer {
	return crypto.pbkdf2Sync(password, salt, iters, KEY_LEN, 'sha256');
}

export function encryptBuffer(plain: Buffer, password: string): Buffer {
	const salt = crypto.randomBytes(SALT_LEN);
	const iv = crypto.randomBytes(IV_LEN);
	const key = deriveKey(password, salt);
	const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
	const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
	const tag = cipher.getAuthTag();
	const iters = Buffer.alloc(4);
	iters.writeUInt32BE(KDF_ITERS, 0);
	return Buffer.concat([MAGIC, iters, salt, iv, tag, enc]);
}

export function decryptBuffer(blob: Buffer, password: string): Buffer {
	if (!blob.subarray(0, MAGIC.length).equals(MAGIC)) {
		throw new Error('Invalid encrypted file: bad magic');
	}
	let off = MAGIC.length;
	const iters = blob.readUInt32BE(off);
	off += 4;
	const salt = blob.subarray(off, off + SALT_LEN);
	off += SALT_LEN;
	const iv = blob.subarray(off, off + IV_LEN);
	off += IV_LEN;
	const tag = blob.subarray(off, off + TAG_LEN);
	off += TAG_LEN;
	const enc = blob.subarray(off);
	const key = deriveKey(password, salt, iters);
	const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
	decipher.setAuthTag(tag);
	try {
		return Buffer.concat([decipher.update(enc), decipher.final()]);
	} catch {
		throw new Error('Invalid password or corrupted data');
	}
}

export function makeVerifier(password: string): {
	salt: string;
	iters: number;
	verifier: string;
} {
	const salt = crypto.randomBytes(SALT_LEN);
	const key = deriveKey(password, salt);
	const verifier = crypto
		.createHmac('sha256', key)
		.update('secutor-verify')
		.digest('hex');
	return {salt: salt.toString('hex'), iters: KDF_ITERS, verifier};
}

export function checkVerifier(
	password: string,
	salt: string,
	iters: number,
	verifier: string,
): boolean {
	const key = deriveKey(password, Buffer.from(salt, 'hex'), iters);
	const calc = crypto
		.createHmac('sha256', key)
		.update('secutor-verify')
		.digest('hex');
	return crypto.timingSafeEqual(Buffer.from(calc), Buffer.from(verifier));
}
