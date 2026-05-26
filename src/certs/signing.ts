import crypto from 'crypto';
import fs from 'fs';
import {
	KeyAlgorithm,
	decryptPrivateKey,
	detectPrivateKeyAlgorithm,
	detectPublicKeyAlgorithm,
	signingHashFor,
} from './keys.js';

/**
 * Signed-file manifest. Emitted by `signFile` / `signBuffer` and consumed by
 * `verifyFile` / `verifyBuffer`. The format is intentionally simple, JSON-
 * encoded, so it can be inspected and reproduced with stock CLI tools:
 *
 *   {
 *     "v": 1,
 *     "alg": "ecdsa-p256",            // signing-key algorithm
 *     "hash": "sha256",               // hash used (null for Ed25519)
 *     "dataHash": "<hex sha256>",     // hash of the signed bytes
 *     "signature": "<base64>",        // raw DER / Ed25519 signature
 *     "signer": {
 *        "certPem": "<...optional, PEM cert that pins the signer>",
 *        "fingerprint": "<sha256 of the cert DER, optional>",
 *        "commonName": "<subject CN, optional>"
 *     },
 *     "signedAt": "<ISO timestamp>"
 *   }
 *
 * "Detached" mode emits a separate `.sig` file. "Bundled" mode glues the
 * manifest in front of the data so a single file is self-describing.
 */

export type SignatureManifest = {
	v: 1;
	alg: KeyAlgorithm;
	hash: string | null;
	dataHash: string;
	signature: string;
	signer?: {
		certPem?: string;
		fingerprint?: string;
		commonName?: string;
	};
	signedAt: string;
};

export type SignOptions = {
	/** PKCS#8 PEM (encrypted or plain). */
	privateKeyPem: string;
	/** Required if `privateKeyPem` is encrypted. */
	keyPassword?: string | null;
	/** Optional cert PEM to bake into the manifest for verifier convenience. */
	certPem?: string | null;
	/** Optional human-readable identifier (defaults to cert CN if certPem given). */
	commonName?: string | null;
};

function sha256Hex(buf: Buffer): string {
	return crypto.createHash('sha256').update(buf).digest('hex');
}

function dnCnFromCertPem(certPem: string): string | undefined {
	try {
		const x = new crypto.X509Certificate(certPem);
		const m = /(?:^|,|\/)CN=([^,/\n]+)/.exec(x.subject);
		return m?.[1]?.trim();
	} catch {
		return undefined;
	}
}

function fingerprintOfCertPem(certPem: string): string | undefined {
	try {
		const x = new crypto.X509Certificate(certPem);
		const der = x.raw;
		return crypto.createHash('sha256').update(der).digest('hex');
	} catch {
		return undefined;
	}
}

/**
 * Produce a detached signature manifest for an arbitrary byte buffer.
 * Works with RSA, ECDSA P-256/P-384, and Ed25519 private keys.
 */
export function signBuffer(data: Buffer, opts: SignOptions): SignatureManifest {
	const plain = decryptPrivateKey(opts.privateKeyPem, opts.keyPassword ?? null);
	const alg = detectPrivateKeyAlgorithm(plain);
	const hash = signingHashFor(alg);
	const key = crypto.createPrivateKey(plain);
	const signature = crypto.sign(hash, data, key);

	const dataHash = sha256Hex(data);
	const manifest: SignatureManifest = {
		v: 1,
		alg,
		hash,
		dataHash,
		signature: signature.toString('base64'),
		signedAt: new Date().toISOString(),
	};
	if (opts.certPem) {
		manifest.signer = {
			certPem: opts.certPem,
			fingerprint: fingerprintOfCertPem(opts.certPem),
			commonName: opts.commonName ?? dnCnFromCertPem(opts.certPem),
		};
	} else if (opts.commonName) {
		manifest.signer = {commonName: opts.commonName};
	}
	return manifest;
}

export function signFile(filePath: string, opts: SignOptions): SignatureManifest {
	const data = fs.readFileSync(filePath);
	return signBuffer(data, opts);
}

export type VerifyOptions = {
	/**
	 * Optional public key (SPKI PEM) or certificate (X.509 PEM) of the expected
	 * signer. If omitted, `manifest.signer.certPem` is used. If neither is
	 * present, verification fails.
	 */
	expectedSignerPem?: string | null;
	/**
	 * If provided, the signer cert's fingerprint must equal this hex string.
	 * Use this to pin a specific cert.
	 */
	expectedFingerprint?: string | null;
};

export type VerifyResult = {
	ok: boolean;
	reason?: string;
	algorithm?: KeyAlgorithm;
	signer?: {
		fingerprint?: string;
		commonName?: string;
	};
};

export function verifyBuffer(
	data: Buffer,
	manifest: SignatureManifest,
	opts: VerifyOptions = {},
): VerifyResult {
	if (manifest.v !== 1) {
		return {ok: false, reason: `Unsupported manifest version: ${manifest.v}`};
	}
	// Data integrity (cheap pre-check).
	const dataHash = sha256Hex(data);
	if (dataHash !== manifest.dataHash) {
		return {ok: false, reason: 'Data does not match the signed digest'};
	}

	const signerPem = opts.expectedSignerPem ?? manifest.signer?.certPem ?? null;
	if (!signerPem) {
		return {ok: false, reason: 'No signer key/cert available for verification'};
	}

	if (opts.expectedFingerprint && manifest.signer?.fingerprint) {
		if (
			manifest.signer.fingerprint.toLowerCase() !==
			opts.expectedFingerprint.toLowerCase()
		) {
			return {ok: false, reason: 'Signer fingerprint mismatch'};
		}
	}

	let pubKey: crypto.KeyObject;
	let detectedAlg: KeyAlgorithm;
	try {
		if (/-----BEGIN CERTIFICATE-----/.test(signerPem)) {
			pubKey = crypto.createPublicKey(signerPem);
		} else {
			pubKey = crypto.createPublicKey(signerPem);
		}
		const pubPem = pubKey.export({type: 'spki', format: 'pem'}) as string;
		detectedAlg = detectPublicKeyAlgorithm(pubPem);
	} catch (err: any) {
		return {ok: false, reason: `Cannot read signer key: ${err?.message ?? err}`};
	}

	if (detectedAlg !== manifest.alg) {
		return {
			ok: false,
			reason: `Signer key algorithm (${detectedAlg}) does not match manifest (${manifest.alg})`,
		};
	}

	const sig = Buffer.from(manifest.signature, 'base64');
	const hash = manifest.hash;
	let ok = false;
	try {
		ok = crypto.verify(hash, data, pubKey, sig);
	} catch (err: any) {
		return {ok: false, reason: `Verification error: ${err?.message ?? err}`};
	}

	if (!ok) return {ok: false, reason: 'Bad signature', algorithm: detectedAlg};
	return {
		ok: true,
		algorithm: detectedAlg,
		signer: manifest.signer
			? {
					fingerprint: manifest.signer.fingerprint,
					commonName: manifest.signer.commonName,
			  }
			: undefined,
	};
}

export function verifyFile(
	filePath: string,
	manifest: SignatureManifest,
	opts: VerifyOptions = {},
): VerifyResult {
	const data = fs.readFileSync(filePath);
	return verifyBuffer(data, manifest, opts);
}

// ---------- Detached signature file helpers ----------

export function manifestToJson(manifest: SignatureManifest): string {
	return JSON.stringify(manifest, null, 2);
}

export function manifestFromJson(text: string): SignatureManifest {
	const m = JSON.parse(text);
	if (m == null || typeof m !== 'object' || m.v !== 1) {
		throw new Error('Not a valid signature manifest');
	}
	return m as SignatureManifest;
}

/**
 * Write a detached signature: writes `<filePath>.sig` next to the data file.
 * Returns the full path of the .sig file.
 */
export function writeDetachedSignature(
	filePath: string,
	manifest: SignatureManifest,
): string {
	const sigPath = filePath + '.sig';
	fs.writeFileSync(sigPath, manifestToJson(manifest));
	return sigPath;
}

export function readDetachedSignature(sigPath: string): SignatureManifest {
	return manifestFromJson(fs.readFileSync(sigPath, 'utf8'));
}

// ---------- Bundled mode (single self-describing file) ----------

const BUNDLE_MAGIC = Buffer.from('SECUTORSIG\x01', 'utf8');

/**
 * Wrap a manifest + data into a single self-describing buffer.
 *
 * Layout (all big-endian):
 *
 *   bytes 0..10  magic "SECUTORSIG\x01"
 *   bytes 11..14 manifest length (uint32 BE)
 *   bytes 15..   manifest JSON
 *   then         the original data
 */
export function buildSignatureBundle(
	data: Buffer,
	manifest: SignatureManifest,
): Buffer {
	const json = Buffer.from(manifestToJson(manifest), 'utf8');
	const len = Buffer.alloc(4);
	len.writeUInt32BE(json.length, 0);
	return Buffer.concat([BUNDLE_MAGIC, len, json, data]);
}

export type ParsedBundle = {
	manifest: SignatureManifest;
	data: Buffer;
};

export function parseSignatureBundle(bundle: Buffer): ParsedBundle {
	if (bundle.length < BUNDLE_MAGIC.length + 4) {
		throw new Error('Not a signature bundle (too short)');
	}
	if (!bundle.subarray(0, BUNDLE_MAGIC.length).equals(BUNDLE_MAGIC)) {
		throw new Error('Not a signature bundle (bad magic)');
	}
	const off = BUNDLE_MAGIC.length;
	const jsonLen = bundle.readUInt32BE(off);
	if (bundle.length < off + 4 + jsonLen) {
		throw new Error('Not a signature bundle (truncated manifest)');
	}
	const json = bundle.subarray(off + 4, off + 4 + jsonLen).toString('utf8');
	const manifest = manifestFromJson(json);
	const data = bundle.subarray(off + 4 + jsonLen);
	return {manifest, data};
}
