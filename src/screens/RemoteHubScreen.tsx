import React, {useEffect, useState} from 'react';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Menu} from '../components/Menu.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {clientFor, getHub, forgetIdentity, recallSnapshot, rememberSnapshot} from '../net/sessionCache.js';
import {AdminApi, type AdminInfo, type CaInfo} from '../net/adminApi.js';
import {HubError} from '../net/hubClient.js';

type Loaded = {info: AdminInfo; ca: CaInfo};

export function RemoteHubScreen({hubId}: {hubId: string}) {
	const {pop, push, showToast} = useApp();
	const t = useT();
	const hub = getHub(hubId);
	// Seed from the session cache so navigating back from a sub-screen
	// renders instantly with the previously-fetched values — no "loading…"
	// flicker. `/info` + `/ca` change rarely; freshness within one session
	// isn't worth the round-trip.
	const cached = recallSnapshot(hubId);
	const [loaded, setLoaded] = useState<Loaded | null>(cached);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		if (!hub || loaded) return;
		let cancelled = false;
		(async () => {
			let client;
			try {
				client = clientFor(hubId);
			} catch (e: any) {
				setError(e?.message ?? String(e));
				return;
			}
			try {
				const api = new AdminApi(client);
				const [info, ca] = await Promise.all([api.info(), api.ca()]);
				if (cancelled) return;
				rememberSnapshot(hubId, {info, ca});
				setLoaded({info, ca});
			} catch (e: any) {
				if (!cancelled) setError(e instanceof HubError ? `${e.code}: ${e.message}` : String(e?.message ?? e));
			} finally {
				client.close();
			}
		})();
		return () => {
			cancelled = true;
		};
	}, [hubId, hub, loaded]);

	// Esc is owned by the Menu's onCancel below — adding it here would pop
	// twice and the user would land past Hubs.

	if (!hub) {
		return (
			<Box flexDirection="column">
				<Header title={t('remoteHub.title')} />
				<Box padding={1}><Text color="red">{t('remoteHub.notFound')}</Text></Box>
				<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={`${t('remoteHub.title')} — 🌐 ${hub.name}`} />
			<Box padding={1} flexDirection="column">
				<Text color="gray">{hub.baseUrl}</Text>
				{error && <Text color="red">{error}</Text>}
				{loaded && (
					<>
						<Text>{t('remoteHub.role', {role: loaded.info.role})}</Text>
						<Text>
							{t('remoteHub.caCn', {cn: loaded.ca.subject})}
						</Text>
						<Text color="gray">
							fp {loaded.ca.cert_fingerprint.slice(0, 24)}… · {loaded.ca.key_algorithm} · exp{' '}
							{loaded.ca.not_after.slice(0, 10)}
						</Text>
						<Text>
							{t('remoteHub.counts', {
								certs: String(loaded.info.counts.certificates),
								revoked: String(loaded.info.counts.revoked),
								orders: String(loaded.info.counts.orders),
								accounts: String(loaded.info.counts.accounts),
							})}
						</Text>
					</>
				)}
			</Box>
			<Box flexGrow={1} paddingX={1}>
				<Menu
					title={t('remoteHub.menu')}
					items={[
						{label: '📜 ' + t('remoteHub.listCerts'), value: 'certs'},
						{label: '👥 ' + t('remoteHub.listAccounts'), value: 'accounts'},
						{label: '📊 ' + t('remoteHub.stats'), value: 'stats'},
						{label: '📋 ' + t('remoteHub.audit'), value: 'audit'},
						{label: '🔑 ' + t('remoteHub.verifyCa'), value: 'verify-ca'},
						{label: '🔄 ' + t('remoteHub.rotateCa'), value: 'rotate-ca'},
						{label: '⏏ ' + t('remoteHub.disconnect'), value: 'disconnect'},
					]}
					onSelect={v => {
						if (v === 'certs') push({kind: 'remote-certs', hubId});
						else if (v === 'accounts') push({kind: 'remote-accounts', hubId});
						else if (v === 'stats') push({kind: 'remote-stats', hubId});
						else if (v === 'audit') push({kind: 'remote-audit', hubId});
						else if (v === 'verify-ca') push({kind: 'remote-ca-verify', hubId});
						else if (v === 'rotate-ca') push({kind: 'remote-ca-rotate', hubId});
						else {
							forgetIdentity(hubId);
							showToast({kind: 'success', message: t('remoteHub.disconnected')});
							pop();
						}
					}}
					onCancel={pop}
				/>
			</Box>
			<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
		</Box>
	);
}
