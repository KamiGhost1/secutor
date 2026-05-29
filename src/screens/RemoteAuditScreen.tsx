import React, {useEffect, useState} from 'react';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {clientFor, getHub} from '../net/sessionCache.js';
import {AdminApi} from '../net/adminApi.js';
import {HubError} from '../net/hubClient.js';

type Row = Awaited<ReturnType<AdminApi['listAudit']>>[number];

const FILTERS: Array<{label: string; action?: string}> = [
	{label: 'all'},
	{label: 'admin actions', action: 'account.ban'},
	{label: 'revokes', action: 'cert.revoke'},
	{label: 'cascade revokes', action: 'cert.revoke.cascade'},
	{label: 'issuance', action: 'cert.issue'},
	{label: 'admin issuance', action: 'cert.issue.admin'},
	{label: 'ca.verify', action: 'ca.verify'},
];

export function RemoteAuditScreen({hubId}: {hubId: string}) {
	const {pop} = useApp();
	const t = useT();
	const hub = getHub(hubId);
	const [rows, setRows] = useState<Row[] | null>(null);
	const [err, setErr] = useState<string | null>(null);
	const [filterIdx, setFilterIdx] = useState(0);
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
			.listAudit({action: FILTERS[filterIdx]!.action, limit: 100})
			.then(items => !cancelled && setRows(items))
			.catch(e => !cancelled && setErr(e instanceof HubError ? `${e.code}: ${e.message}` : String(e?.message ?? e)))
			.finally(() => client.close());
		return () => {
			cancelled = true;
		};
	}, [hubId, filterIdx, tick]);

	useInput((input, key) => {
		if (key.escape) pop();
		else if (input === 'r' || input === 'R') setTick(t => t + 1);
		else if (input === 'f' || input === 'F') setFilterIdx(i => (i + 1) % FILTERS.length);
	});

	if (!hub) return null;
	const title = `${t('remoteAudit.title')} — 🌐 ${hub.name}`;
	const cur = FILTERS[filterIdx]!;

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={title} />
			<Box padding={1}>
				<Text color="gray">
					{t('remoteAudit.filter', {f: cur.label})}{err ? ` · ${err}` : ''}
				</Text>
			</Box>
			<Box flexGrow={1} paddingX={1} flexDirection="column">
				{rows == null ? (
					<Text color="cyan">{t('remoteCerts.loading')}</Text>
				) : rows.length === 0 ? (
					<Text color="gray">{t('common.empty')}</Text>
				) : (
					rows.slice(0, 30).map(row => (
						<Box key={row.id} flexDirection="column">
							<Text>
								<Text color="gray">{row.ts.replace('T', ' ').slice(0, 19)}</Text>{' '}
								<Text color={actionColor(row.action)}>{row.action}</Text>{' '}
								<Text color="cyan">{(row.target ?? '').slice(0, 12)}</Text>{' '}
								<Text color="gray">
									{row.actor_type === 'admin' ? `[admin ${(row.actor_id ?? '').slice(0, 8)}…]` : `[${row.actor_type}]`}
								</Text>
							</Text>
							{row.details_json && (
								<Text color="gray">  {row.details_json.slice(0, 140)}</Text>
							)}
						</Box>
					))
				)}
			</Box>
			<FunctionBar
				keys={[
					{key: 'F', label: t('remoteAudit.fbarFilter')},
					{key: 'R', label: t('remoteCerts.fbarRefresh')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}

function actionColor(action: string): string {
	if (action.startsWith('cert.revoke')) return 'red';
	if (action.startsWith('cert.issue')) return 'green';
	if (action.startsWith('account.ban')) return 'magenta';
	if (action.startsWith('ca.')) return 'yellow';
	return 'white';
}
