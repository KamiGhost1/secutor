// Tiny CSR generator using node:crypto + node-forge to encode/sign PKCS#10.

import crypto from 'crypto';
import forge from 'node-forge';

export type CsrInput = {
	commonName: string;
	sans?: string[];
	algorithm?: 'rsa-2048' | 'rsa-3072' | 'rsa-4096' | 'ecdsa-p256' | 'ecdsa-p384';
};

export type CsrOutput = {
	csrDer: Buffer;
	csrPem: string;
	privateKeyPem: string;
	publicKeyPem: string;
};

function makeKey(algo: NonNullable<CsrInput['algorithm']>): {
	privPem: string;
	pubPem: string;
} {
	let priv: crypto.KeyObject;
	let pub: crypto.KeyObject;
	if (algo.startsWith('rsa')) {
		const bits = parseInt(algo.split('-')[1]!, 10);
		const {privateKey, publicKey} = crypto.generateKeyPairSync('rsa', {modulusLength: bits});
		priv = privateKey;
		pub = publicKey;
	} else if (algo === 'ecdsa-p384') {
		const {privateKey, publicKey} = crypto.generateKeyPairSync('ec', {namedCurve: 'P-384'});
		priv = privateKey;
		pub = publicKey;
	} else {
		const {privateKey, publicKey} = crypto.generateKeyPairSync('ec', {namedCurve: 'P-256'});
		priv = privateKey;
		pub = publicKey;
	}
	return {
		privPem: priv.export({type: 'pkcs8', format: 'pem'}) as string,
		pubPem: pub.export({type: 'spki', format: 'pem'}) as string,
	};
}

export function generateCsr(input: CsrInput): CsrOutput {
	const algo = input.algorithm ?? 'rsa-2048';
	const {privPem, pubPem} = makeKey(algo);

	// We'll build the PKCS#10 manually by:
	// 1) using forge to construct CertificationRequestInfo with a dummy RSA key
	// 2) swapping in the real SPKI
	// 3) signing the DER with node:crypto

	const dummy = forge.pki.rsa.generateKeyPair(2048);
	const csr = forge.pki.createCertificationRequest();
	csr.publicKey = dummy.publicKey;
	csr.setSubject([{name: 'commonName', value: input.commonName}]);
	if (input.sans?.length) {
		const altNames = input.sans.map(v => {
			if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return {type: 7, ip: v};
			return {type: 2, value: v};
		});
		(csr as any).setAttributes([
			{
				name: 'extensionRequest',
				extensions: [{name: 'subjectAltName', altNames}],
			},
		]);
	}
	csr.sign(dummy.privateKey, forge.md.sha256.create());

	const reqAsn1 = forge.pki.certificationRequestToAsn1(csr) as any;
	const certInfo = reqAsn1.value[0];
	// Inside CertificationRequestInfo, SPKI is at index 2 (version, subject, SPKI, attrs).
	const newSpkiDer = crypto.createPublicKey(pubPem).export({type: 'spki', format: 'der'}) as Buffer;
	const A = forge.asn1;
	const newSpkiAsn1 = A.fromDer(forge.util.createBuffer(newSpkiDer.toString('binary')));
	certInfo.value[2] = newSpkiAsn1;

	// Pick signature algorithm based on key.
	const sigInfo = sigAlgFor(algo);
	reqAsn1.value[1] = sigAlgIdAsn1(sigInfo);

	const certInfoDer = A.toDer(certInfo).getBytes();
	const sig = crypto.sign(sigInfo.hash, Buffer.from(certInfoDer, 'binary'), crypto.createPrivateKey(privPem));
	reqAsn1.value[2] = A.create(
		A.Class.UNIVERSAL,
		A.Type.BITSTRING,
		false,
		'\x00' + sig.toString('binary'),
	);

	const der = Buffer.from(A.toDer(reqAsn1).getBytes(), 'binary');
	const pem = forge.pem.encode({type: 'CERTIFICATE REQUEST', body: der.toString('binary')});
	return {csrDer: der, csrPem: pem, privateKeyPem: privPem, publicKeyPem: pubPem};
}

function sigAlgFor(algo: NonNullable<CsrInput['algorithm']>): {oid: string; hash: string; null: boolean} {
	if (algo.startsWith('rsa')) {
		return {oid: '1.2.840.113549.1.1.11', hash: 'sha256', null: true};
	}
	if (algo === 'ecdsa-p384') {
		return {oid: '1.2.840.10045.4.3.3', hash: 'sha384', null: false};
	}
	return {oid: '1.2.840.10045.4.3.2', hash: 'sha256', null: false};
}

function sigAlgIdAsn1(s: {oid: string; null: boolean}): forge.asn1.Asn1 {
	const A = forge.asn1;
	const children: forge.asn1.Asn1[] = [
		A.create(A.Class.UNIVERSAL, A.Type.OID, false, A.oidToDer(s.oid).getBytes()),
	];
	if (s.null) children.push(A.create(A.Class.UNIVERSAL, A.Type.NULL, false, ''));
	return A.create(A.Class.UNIVERSAL, A.Type.SEQUENCE, true, children);
}
