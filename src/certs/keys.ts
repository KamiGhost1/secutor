import crypto from 'crypto';

export type KeyAlgorithm =
	| 'rsa-2048'
	| 'rsa-3072'
	| 'rsa-4096'
	| 'ecdsa-p256'
	| 'ecdsa-p384'
	| 'ed25519'
	| 'x25519';

/** Algorithms valid for X.509 signing (key-pair must support signing). */
export const SIGNING_ALGORITHMS: KeyAlgorithm[] = [
	'rsa-2048',
	'rsa-3072',
	'rsa-4096',
	'ecdsa-p256',
	'ecdsa-p384',
	'ed25519',
];

export function isSigningAlgorithm(a: KeyAlgorithm): boolean {
	return SIGNING_ALGORITHMS.includes(a);
}

export type GeneratedKey = {
	algorithm: KeyAlgorithm;
	/** PKCS#8 unencrypted PEM. */
	privateKeyPem: string;
	/** SPKI PEM. */
	publicKeyPem: string;
};

/**
 * Generate a fresh key pair for any supported algorithm.
 * Private key is returned as unencrypted PKCS#8 PEM regardless of algorithm
 * so downstream consumers have a uniform shape.
 */
export function generateKey(algorithm: KeyAlgorithm): GeneratedKey {
	let pair: crypto.KeyPairSyncResult<string, string>;
	switch (algorithm) {
		case 'rsa-2048':
		case 'rsa-3072':
		case 'rsa-4096': {
			const modulusLength = parseInt(algorithm.split('-')[1]!, 10);
			pair = crypto.generateKeyPairSync('rsa', {
				modulusLength,
				publicKeyEncoding: {type: 'spki', format: 'pem'},
				privateKeyEncoding: {type: 'pkcs8', format: 'pem'},
			});
			break;
		}
		case 'ecdsa-p256':
		case 'ecdsa-p384': {
			const namedCurve = algorithm === 'ecdsa-p256' ? 'P-256' : 'P-384';
			pair = crypto.generateKeyPairSync('ec', {
				namedCurve,
				publicKeyEncoding: {type: 'spki', format: 'pem'},
				privateKeyEncoding: {type: 'pkcs8', format: 'pem'},
			});
			break;
		}
		case 'ed25519': {
			pair = crypto.generateKeyPairSync('ed25519', {
				publicKeyEncoding: {type: 'spki', format: 'pem'},
				privateKeyEncoding: {type: 'pkcs8', format: 'pem'},
			});
			break;
		}
		case 'x25519': {
			pair = crypto.generateKeyPairSync('x25519', {
				publicKeyEncoding: {type: 'spki', format: 'pem'},
				privateKeyEncoding: {type: 'pkcs8', format: 'pem'},
			});
			break;
		}
		default:
			throw new Error(`Unsupported algorithm: ${algorithm}`);
	}
	return {
		algorithm,
		privateKeyPem: pair.privateKey,
		publicKeyPem: pair.publicKey,
	};
}

/**
 * Encrypt a PKCS#8 PEM private key with a passphrase using AES-256-CBC.
 * The encrypted output is a standard `-----BEGIN ENCRYPTED PRIVATE KEY-----`
 * PEM that openssl, ssh-keygen and other tools accept.
 */
export function encryptPrivateKey(privateKeyPem: string, passphrase: string): string {
	if (!passphrase) throw new Error('passphrase is required to encrypt key');
	const key = crypto.createPrivateKey(privateKeyPem);
	return key.export({
		type: 'pkcs8',
		format: 'pem',
		cipher: 'aes-256-cbc',
		passphrase,
	}) as string;
}

/**
 * Return a plain unencrypted PKCS#8 PEM from either an encrypted or
 * unencrypted private-key PEM. Passes-through unencrypted input.
 */
export function decryptPrivateKey(
	privateKeyPem: string,
	passphrase: string | null,
): string {
	if (!isEncryptedKey(privateKeyPem)) return privateKeyPem;
	if (!passphrase) {
		throw new Error('Private key is encrypted but no password was provided');
	}
	let key: crypto.KeyObject;
	try {
		key = crypto.createPrivateKey({key: privateKeyPem, passphrase});
	} catch (err: any) {
		throw new Error(`Invalid password for private key: ${err?.message ?? err}`);
	}
	return key.export({type: 'pkcs8', format: 'pem'}) as string;
}

export function isEncryptedKey(pem: string): boolean {
	return /-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(pem);
}

/**
 * Detect the algorithm of a private-key PEM. Works on encrypted PEMs too
 * (you must provide the passphrase to decrypt the header is *not* enough —
 * algorithm is encoded inside the encrypted blob).
 */
export function detectPrivateKeyAlgorithm(
	privateKeyPem: string,
	passphrase?: string | null,
): KeyAlgorithm {
	const plain = decryptPrivateKey(privateKeyPem, passphrase ?? null);
	const key = crypto.createPrivateKey(plain);
	return keyObjectAlgorithm(key);
}

export function detectPublicKeyAlgorithm(publicKeyPem: string): KeyAlgorithm {
	const key = crypto.createPublicKey(publicKeyPem);
	return keyObjectAlgorithm(key);
}

function keyObjectAlgorithm(key: crypto.KeyObject): KeyAlgorithm {
	const t = key.asymmetricKeyType;
	if (t === 'rsa' || t === 'rsa-pss') {
		const details = (key as any).asymmetricKeyDetails ?? {};
		const bits: number = details.modulusLength ?? 0;
		if (bits >= 3500 && bits < 4500) return 'rsa-4096';
		if (bits >= 2500 && bits < 3500) return 'rsa-3072';
		return 'rsa-2048';
	}
	if (t === 'ec') {
		const details = (key as any).asymmetricKeyDetails ?? {};
		const curve: string = details.namedCurve ?? '';
		if (curve === 'P-384' || curve === 'secp384r1') return 'ecdsa-p384';
		return 'ecdsa-p256';
	}
	if (t === 'ed25519') return 'ed25519';
	if (t === 'x25519') return 'x25519';
	throw new Error(`Unsupported key type: ${t}`);
}

/**
 * For a given signing-capable algorithm, return the matching
 * X.509 signature-algorithm OID (used in tbsCertificate.signature
 * and Certificate.signatureAlgorithm).
 */
export function signatureAlgorithmOid(algorithm: KeyAlgorithm): string {
	switch (algorithm) {
		case 'rsa-2048':
		case 'rsa-3072':
		case 'rsa-4096':
			return '1.2.840.113549.1.1.11'; // sha256WithRSAEncryption
		case 'ecdsa-p256':
			return '1.2.840.10045.4.3.2'; // ecdsa-with-SHA256
		case 'ecdsa-p384':
			return '1.2.840.10045.4.3.3'; // ecdsa-with-SHA384
		case 'ed25519':
			return '1.3.101.112';
		default:
			throw new Error(`Algorithm ${algorithm} cannot sign X.509`);
	}
}

/**
 * Hash name suitable for `crypto.sign(hash, ...)`. Ed25519 uses `null` —
 * Node hashes internally.
 */
export function signingHashFor(algorithm: KeyAlgorithm): string | null {
	switch (algorithm) {
		case 'rsa-2048':
		case 'rsa-3072':
		case 'rsa-4096':
		case 'ecdsa-p256':
			return 'sha256';
		case 'ecdsa-p384':
			return 'sha384';
		case 'ed25519':
			return null;
		default:
			throw new Error(`Algorithm ${algorithm} cannot sign`);
	}
}
