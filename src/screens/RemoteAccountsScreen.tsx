import React, {useEffect, useState} from 'react';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Menu} from '../components/Menu.js';
import {Confirm} from '../components/Confirm.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {clientFor, getHub} from '../net/sessionCache.js';
import {AdminApi, type AdminAccountRow} from '../net/adminApi.js';
import {HubError} from '../net/hubClient.js';

export function RemoteAccountsScreen({hubId}: {hubId: string}) {
	const {pop, showToast} = useApp();
	const t = useT();
	const hub = getHub(hubId);
	const [rows, setRows] = useState<AdminAccountRow[] | null>(null);
	const [err, setErr] = useState<string | null>(null);
	const [banning, setBanning] = useState<AdminAccountRow | null>(null);
	const [tick, setTick] = useState(0);

	useEffect(() => {
		let cancelled = false;
		const client = (() => {
			try {
				return clientFor(hubId);
			} catch (e: any) {
				setErr(e?.message ?? String(e));
				return null;
			}
		})();
		if (!client) return;
		new AdminApi(client)
			.listAccounts()
			.then(items => !cancelled && setRows(items))
			.catch(e => !cancelled && setErr(e instanceof HubError ? `${e.code}: ${e.message}` : String(e?.message ?? e)))
			.finally(() => client.close());
		return () => {
			cancelled = true;
		};
	}, [hubId, tick]);

	useInput((input, key) => {
		if (banning) return;
		// Same as RemoteCertsScreen: Menu.onCancel owns Esc once the list
		// renders; in the loading state we accept it directly.
		if (rows == null && key.escape) {
			pop();
			return;
		}
		if (input === 'r' || input === 'R') setTick(t => t + 1);
	});

	if (!hub) {
		return (
			<Box flexDirection="column">
				<Header title={t('remoteAccts.title')} />
				<Box padding={1}><Text color="red">{t('remoteHub.notFound')}</Text></Box>
				<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	if (banning) {
		const isBanned = banning.status === 'banned';
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('remoteAccts.title')} />
				<Box padding={1}>
					<Confirm
						message={
							isBanned
								? t('remoteAccts.confirmUnban', {id: banning.id.slice(0, 12)})
								: t('remoteAccts.confirmBan', {id: banning.id.slice(0, 12)})
						}
						onCancel={() => setBanning(null)}
						onConfirm={() => {
							const target = banning;
							setBanning(null);
							const client = clientFor(hubId);
							const api = new AdminApi(client);
							const action = isBanned
								? api.unbanAccount(target.id)
								: api.banAccount(target.id, {reason: 9, comment: 'TUI ban'});
							action
								.then((res: any) => {
									if (isBanned) {
										showToast({kind: 'success', message: t('remoteAccts.unbanned')});
									} else {
										showToast({
											kind: 'success',
											message: t('remoteAccts.banned', {
												revoked: String(res?.revoked_certificates ?? 0),
												orders: String(res?.cancelled_orders ?? 0),
											}),
										});
									}
									setTick(t => t + 1);
								})
								.catch(e => showToast({kind: 'error', message: e?.message ?? String(e)}))
								.finally(() => client.close());
						}}
					/>
				</Box>
			</Box>
		);
	}

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={`${t('remoteAccts.title')} — 🌐 ${hub.name}`} />
			{err && <Box padding={1}><Text color="red">{err}</Text></Box>}
			<Box flexGrow={1} paddingX={1}>
				{rows == null ? (
					<Text color="cyan">{t('remoteAccts.loading')}</Text>
				) : (
					<Menu
						emptyText={t('remoteAccts.empty')}
						items={rows.map(r => ({
							label: `${statusGlyph(r.status)} ${r.id.slice(0, 16)}…`,
							value: r.id,
							hint: `${r.status} · ${r.created_at.slice(0, 10)}${
								r.allow_list_json ? ' · allow-list' : ''
							}`,
						}))}
						onSelect={() => {}}
						onCancel={pop}
						onAction={(input, _k, item) => {
							if ((input === 'b' || input === 'B') && item) {
								const row = rows.find(x => x.id === item.value);
								if (row) setBanning(row);
							}
						}}
					/>
				)}
			</Box>
			<FunctionBar
				keys={[
					{key: 'B', label: t('remoteAccts.fbarBanUnban')},
					{key: 'R', label: t('remoteCerts.fbarRefresh')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}

function statusGlyph(s: string): string {
	if (s === 'banned') return '🚫';
	if (s === 'deactivated') return '⏸ ';
	return '✓';
}
