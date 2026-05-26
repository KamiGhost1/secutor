import crypto, {webcrypto} from 'crypto';
import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';

let _engineInstalled = false;
function ensureEngine(): void {
	if (_engineInstalled) return;
	const subtle = (webcrypto as any).subtle ?? (globalThis.crypto as any)?.subtle;
	if (!subtle) {
		throw new Error('WebCrypto subtle not available — Node 18.17+ is required');
	}
	const engine = new pkijs.CryptoEngine({
		name: 'nodeEngine',
		crypto: webcrypto as any,
		subtle,
	});
	pkijs.setEngine('nodeEngine', engine);
	_engineInstalled = true;
}

// PKCS#12 OIDs (RFC 7292)
const OID_KEY_BAG_SHROUDED = '1.2.840.113549.1.12.10.1.2';
const OID_CERT_BAG = '1.2.840.113549.1.12.10.1.3';
const OID_X509_CERT_BAG = '1.2.840.113549.1.9.22.1';
// Microsoft's friendlyName attribute (used by openssl too).
const OID_FRIENDLY_NAME = '1.2.840.113549.1.9.20';
const OID_LOCAL_KEY_ID = '1.2.840.113549.1.9.21';

function pemToDer(pem: string): Buffer {
	const body = pem
		.replace(/-----BEGIN [^-]+-----/g, '')
		.replace(/-----END [^-]+-----/g, '')
		.replace(/\s+/g, '');
	return Buffer.from(body, 'base64');
}

function derToArrayBuffer(buf: Buffer): ArrayBuffer {
	// Use a fresh ArrayBuffer that's exactly the right length so pkijs's
	// schema parser doesn't read past the cert's DER into noise.
	const ab = new ArrayBuffer(buf.length);
	new Uint8Array(ab).set(buf);
	return ab;
}

function privateKeyPemToPkcs8Der(privateKeyPem: string): Buffer {
	// node:crypto handles RSA, ECDSA, Ed25519 and X25519 uniformly via PKCS#8.
	const key = crypto.createPrivateKey(privateKeyPem);
	return key.export({type: 'pkcs8', format: 'der'}) as Buffer;
}

function textBuffer(s: string): ArrayBuffer {
	return new TextEncoder().encode(s).buffer.slice(0) as ArrayBuffer;
}

function utf8Attribute(oid: string, value: string): pkijs.Attribute {
	return new pkijs.Attribute({
		type: oid,
		values: [new asn1js.BmpString({value})],
	});
}

function octetAttribute(oid: string, value: Buffer): pkijs.Attribute {
	return new pkijs.Attribute({
		type: oid,
		values: [new asn1js.OctetString({valueHex: derToArrayBuffer(value)})],
	});
}

export type BuildP12Input = {
	leafCertPem: string;
	leafPrivateKeyPem: string; // unencrypted PKCS#8 (caller must decrypt first)
	chainCertPems: string[];   // intermediate(s) + root, leaf-out order; can be empty
	password: string;
	friendlyName?: string;
};

/**
 * Build a PKCS#12 (.p12 / .pfx) blob using `pkijs`. Supports any private-key
 * algorithm node:crypto understands (RSA, ECDSA P-256/P-384, Ed25519) — the
 * P12 format itself is algorithm-agnostic; only the legacy `node-forge`
 * implementation was RSA-only.
 *
 * The output uses modern AES-256-CBC + PBKDF2-SHA-256 for the key bag and
 * SHA-256 HMAC for integrity, which OpenSSL 3.0+ reads natively. OpenSSL
 * 1.1.x with `-legacy` provider also reads it.
 */
export async function buildP12(input: BuildP12Input): Promise<Buffer> {
	ensureEngine();

	const passwordBuf = textBuffer(input.password);
	const localKeyId = Buffer.from(crypto.randomBytes(20));

	// --- Build SafeBags ---

	// Leaf + chain cert bags. Leaf gets friendlyName + localKeyId so it's
	// distinguished from the chain certs by readers like browsers / openssl.
	const certPems = [input.leafCertPem, ...input.chainCertPems];
	const certBags = certPems.map((pem, i) => {
		const der = pemToDer(pem);
		const certAsn1 = asn1js.fromBER(derToArrayBuffer(der));
		if (certAsn1.offset === -1) {
			throw new Error('Failed to parse certificate PEM');
		}
		const cert = new pkijs.Certificate({schema: certAsn1.result});
		const attrs: pkijs.Attribute[] = [];
		if (i === 0) {
			attrs.push(utf8Attribute(OID_FRIENDLY_NAME, input.friendlyName ?? ''));
			attrs.push(octetAttribute(OID_LOCAL_KEY_ID, localKeyId));
		}
		return new pkijs.SafeBag({
			bagId: OID_CERT_BAG,
			bagValue: new pkijs.CertBag({
				parsedValue: cert,
			}),
			bagAttributes: attrs.length ? attrs : undefined,
		});
	});

	// Key bag — encrypted PKCS#8 PrivateKeyInfo.
	const pkcs8Der = privateKeyPemToPkcs8Der(input.leafPrivateKeyPem);
	const pkcs8Asn1 = asn1js.fromBER(derToArrayBuffer(pkcs8Der));
	if (pkcs8Asn1.offset === -1) {
		throw new Error('Failed to parse PKCS#8 private key');
	}
	const pki = new pkijs.PrivateKeyInfo({schema: pkcs8Asn1.result});

	const keyBag = new pkijs.SafeBag({
		bagId: OID_KEY_BAG_SHROUDED,
		bagValue: new pkijs.PKCS8ShroudedKeyBag({
			parsedValue: pki,
		}),
		bagAttributes: [
			utf8Attribute(OID_FRIENDLY_NAME, input.friendlyName ?? ''),
			octetAttribute(OID_LOCAL_KEY_ID, localKeyId),
		],
	});

	// Encrypt the key bag with AES-256-CBC + PBKDF2-SHA-256.
	await (keyBag.bagValue as pkijs.PKCS8ShroudedKeyBag).makeInternalValues({
		password: passwordBuf,
		contentEncryptionAlgorithm: {name: 'AES-CBC', length: 256} as any,
		hmacHashAlgorithm: 'SHA-256',
		iterationCount: 100_000,
	});

	// --- Assemble AuthenticatedSafe ---

	const pfx = new pkijs.PFX({
		parsedValue: {
			integrityMode: 0, // password-based HMAC integrity
			authenticatedSafe: new pkijs.AuthenticatedSafe({
				parsedValue: {
					safeContents: [
						// Certs in a password-encrypted SafeContents.
						{
							privacyMode: 1, // password-based encryption
							value: new pkijs.SafeContents({safeBags: certBags}),
						},
						// Keys in a plain SafeContents (the key is *itself*
						// already wrapped in PKCS8ShroudedKeyBag).
						{
							privacyMode: 0,
							value: new pkijs.SafeContents({safeBags: [keyBag]}),
						},
					],
				},
			}),
		},
	});

	await pfx.parsedValue!.authenticatedSafe!.makeInternalValues({
		safeContents: [
			{
				password: passwordBuf,
				contentEncryptionAlgorithm: {name: 'AES-CBC', length: 256} as any,
				hmacHashAlgorithm: 'SHA-256',
				iterationCount: 100_000,
			},
			{
				// Plain — the key is encrypted inside its bag, not at this layer.
			},
		],
	});

	await pfx.makeInternalValues({
		password: passwordBuf,
		iterations: 100_000,
		pbkdf2HashAlgorithm: {name: 'SHA-256'} as any,
		hmacHashAlgorithm: 'SHA-256',
	});

	const ber = pfx.toSchema().toBER();
	return Buffer.from(ber);
}

export type ParsedP12 = {
	/** Leaf + chain certs as PEM strings, in the order they appeared in the file. */
	certPems: string[];
	/** Leaf private key as PKCS#8 PEM, decrypted; null if the P12 had no key bag. */
	privateKeyPem: string | null;
};

/**
 * Parse a PKCS#12 blob produced by anyone — openssl, node-forge, pkijs.
 * Algorithm-agnostic: any key/cert combination supported by node:crypto.
 */
export async function parseP12(blob: Buffer, password: string): Promise<ParsedP12> {
	ensureEngine();
	const passwordBuf = textBuffer(password);

	const ber = asn1js.fromBER(derToArrayBuffer(blob));
	if (ber.offset === -1) throw new Error('PKCS#12: failed to parse outer DER');
	const pfx = new pkijs.PFX({schema: ber.result});

	try {
		await pfx.parseInternalValues({
			password: passwordBuf,
			checkIntegrity: true,
		});
	} catch (err: any) {
		throw new Error(`PKCS#12 integrity check failed (wrong password?): ${err?.message ?? err}`);
	}

	const certPems: string[] = [];
	let privateKeyPem: string | null = null;

	const authSafe = pfx.parsedValue?.authenticatedSafe;
	const rawContents = authSafe?.safeContents;
	if (!authSafe || !rawContents || rawContents.length === 0) {
		throw new Error('PKCS#12: AuthenticatedSafe is empty');
	}

	// Each ContentInfo is either:
	//   1.2.840.113549.1.7.1  — Data (plaintext SafeContents)
	//   1.2.840.113549.1.7.6  — EncryptedData (password-encrypted SafeContents)
	// AuthenticatedSafe.parseInternalValues decrypts the EncryptedData layer
	// using the provided per-content parameters.
	const OID_DATA = '1.2.840.113549.1.7.1';
	const parseParams: any[] = rawContents.map(ci => {
		if (ci.contentType === OID_DATA) return {};
		return {password: passwordBuf};
	});
	await authSafe.parseInternalValues({safeContents: parseParams});

	const parsed = (authSafe as any).parsedValue?.safeContents;
	if (!parsed || !Array.isArray(parsed)) {
		throw new Error('PKCS#12: failed to decode SafeContents');
	}

	for (const sc of parsed) {
		const inner = sc?.value as pkijs.SafeContents | undefined;
		if (!inner?.safeBags) continue;
		for (const bag of inner.safeBags) {
			if (bag.bagId === OID_CERT_BAG) {
				const certBag = bag.bagValue as pkijs.CertBag;
				if (certBag.certValue && certBag.parsedValue instanceof pkijs.Certificate) {
					const der = Buffer.from(certBag.parsedValue.toSchema().toBER());
					certPems.push(derToPemCert(der));
				} else if (certBag.certValue) {
					// fallback — raw OctetString
					const raw = certBag.certValue as any;
					const inner = raw?.valueBlock?.valueHexView;
					if (inner) certPems.push(derToPemCert(Buffer.from(inner)));
				}
			} else if (bag.bagId === OID_KEY_BAG_SHROUDED) {
				const keyBag = bag.bagValue as pkijs.PKCS8ShroudedKeyBag;
				try {
					await (keyBag as any).parseInternalValues({password: passwordBuf});
				} catch (err: any) {
					throw new Error(`PKCS#12 key bag decryption failed: ${err?.message ?? err}`);
				}
				if (keyBag.parsedValue) {
					const der = Buffer.from(keyBag.parsedValue.toSchema().toBER());
					privateKeyPem = derToPemKey(der);
				}
			} else if (bag.bagId === '1.2.840.113549.1.12.10.1.1') {
				// keyBag (unencrypted PKCS#8) — uncommon, but support it.
				const kb: any = bag.bagValue;
				if (kb?.toSchema) {
					const der = Buffer.from(kb.toSchema().toBER());
					privateKeyPem = derToPemKey(der);
				}
			}
		}
	}

	if (certPems.length === 0 && !privateKeyPem) {
		throw new Error('PKCS#12 contained neither a certificate nor a private key');
	}

	return {certPems, privateKeyPem};
}

function derToPemCert(der: Buffer): string {
	return wrapPem('CERTIFICATE', der);
}
function derToPemKey(der: Buffer): string {
	return wrapPem('PRIVATE KEY', der);
}
function wrapPem(label: string, der: Buffer): string {
	const b64 = der.toString('base64');
	const wrapped = b64.match(/.{1,64}/g)!.join('\n');
	return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----\n`;
}
