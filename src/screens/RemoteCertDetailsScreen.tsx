import React, {useEffect, useState} from 'react';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {clientFor, getHub} from '../net/sessionCache.js';
import {AdminApi, type AdminCertDetails} from '../net/adminApi.js';
import {HubError} from '../net/hubClient.js';
import {copyToClipboard} from '../utils/clipboard.js';

export function RemoteCertDetailsScreen({hubId, certId}: {hubId: string; certId: string}) {
	const {pop, showToast} = useApp();
	const t = useT();
	const hub = getHub(hubId);
	const [cert, setCert] = useState<AdminCertDetails | null>(null);
	const [err, setErr] = useState<string | null>(null);

	useEffect(() => {
		let cancelled = false;
		let client;
		try {
			client = clientFor(hubId);
		} catch (e: any) {
			setErr(e?.message ?? String(e));
			return;
		}
		new AdminApi(client)
			.getCertificate(certId)
			.then(c => !cancelled && setCert(c))
			.catch(e => !cancelled && setErr(e instanceof HubError ? `${e.code}: ${e.message}` : String(e?.message ?? e)))
			.finally(() => client.close());
		return () => {
			cancelled = true;
		};
	}, [hubId, certId]);

	useInput((input, key) => {
		if (key.escape) pop();
		else if ((input === 'c' || input === 'C') && cert) {
			const ids = (cert as any).identifiers ?? [];
			const text = Array.isArray(ids) && ids.length ? ids.join('\n') : cert.serial_hex;
			const r = copyToClipboard(text);
			showToast(
				r.ok
					? {kind: 'success', message: t('remoteCertDetails.copied', {via: r.via})}
					: {kind: 'error', message: r.error},
			);
		} else if ((input === 's' || input === 'S') && cert) {
			const r = copyToClipboard(cert.serial_hex);
			showToast(
				r.ok
					? {kind: 'success', message: t('remoteCerts.serialCopied', {via: r.via})}
					: {kind: 'error', message: r.error},
			);
		} else if ((input === 'p' || input === 'P') && cert) {
			const r = copyToClipboard(cert.pem);
			showToast(
				r.ok
					? {kind: 'success', message: t('remoteCertDetails.pemCopied', {via: r.via})}
					: {kind: 'error', message: r.error},
			);
		}
	});

	if (!hub) return null;
	const title = `${t('remoteCertDetails.title')} — 🌐 ${hub.name}`;

	if (err) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={title} />
				<Box padding={1}><Text color="red">{err}</Text></Box>
				<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}
	if (!cert) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={title} />
				<Box padding={1}><Text color="cyan">{t('remoteCerts.loading')}</Text></Box>
			</Box>
		);
	}

	const ids: string[] = (cert as any).identifiers ?? [];
	const status = cert.revoked ? t('remoteCertDetails.statusRevoked') : t('remoteCertDetails.statusValid');
	const statusColor = cert.revoked ? 'red' : 'green';

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={title} />
			<Box padding={1} flexDirection="column">
				<Text>
					<Text color="gray">{t('remoteCertDetails.status')}:</Text>{' '}
					<Text color={statusColor}>{status}</Text>
					{cert.revoked && cert.revocation_reason != null && (
						<Text color="gray"> · reason {cert.revocation_reason}</Text>
					)}
				</Text>
				<Box marginTop={1} flexDirection="column">
					<Text color="gray">{t('remoteCertDetails.identifiers')}:</Text>
					{ids.length === 0 ? (
						<Text color="gray">  —</Text>
					) : (
						ids.map(i => (
							<Text key={i}>  <Text color="cyan">{i}</Text></Text>
						))
					)}
				</Box>
				<Box marginTop={1} flexDirection="column">
					<KV label={t('remoteCertDetails.serial')} value={cert.serial_hex} />
					<KV label={t('remoteCertDetails.notBefore')} value={cert.not_before} />
					<KV label={t('remoteCertDetails.notAfter')} value={cert.not_after} />
					<KV label={t('remoteCertDetails.issuedAt')} value={cert.issued_at} />
					<KV label={t('remoteCertDetails.accountId')} value={cert.account_id} />
					<KV label={t('remoteCertDetails.orderId')} value={cert.order_id} />
					{cert.revoked_at && (
						<KV label={t('remoteCertDetails.revokedAt')} value={cert.revoked_at} />
					)}
					{cert.revoked_by && (
						<KV label={t('remoteCertDetails.revokedBy')} value={cert.revoked_by} />
					)}
				</Box>
			</Box>
			<FunctionBar
				keys={[
					{key: 'C', label: t('remoteCertDetails.fbarCopyIds')},
					{key: 'S', label: t('remoteCertDetails.fbarCopySerial')},
					{key: 'P', label: t('remoteCertDetails.fbarCopyPem')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}

function KV({label, value}: {label: string; value: string}) {
	return (
		<Text>
			<Text color="gray">{label}:</Text> <Text>{value}</Text>
		</Text>
	);
}
