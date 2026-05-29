import React, {useEffect, useState} from 'react';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {clientFor, getHub} from '../net/sessionCache.js';
import {AdminApi} from '../net/adminApi.js';
import {HubError} from '../net/hubClient.js';

type Loaded = {
	orders: Awaited<ReturnType<AdminApi['getOrderStats']>>;
	failures: Awaited<ReturnType<AdminApi['getFailureStats']>>;
};

export function RemoteStatsScreen({hubId}: {hubId: string}) {
	const {pop} = useApp();
	const t = useT();
	const hub = getHub(hubId);
	const [data, setData] = useState<Loaded | null>(null);
	const [err, setErr] = useState<string | null>(null);
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
		const api = new AdminApi(client);
		Promise.all([api.getOrderStats(), api.getFailureStats()])
			.then(([orders, failures]) => !cancelled && setData({orders, failures}))
			.catch(e => !cancelled && setErr(e instanceof HubError ? `${e.code}: ${e.message}` : String(e?.message ?? e)))
			.finally(() => client.close());
		return () => {
			cancelled = true;
		};
	}, [hubId, tick]);

	useInput((input, key) => {
		if (key.escape) pop();
		else if (input === 'r' || input === 'R') setTick(t => t + 1);
	});

	if (!hub) return null;
	const title = `${t('remoteStats.title')} — 🌐 ${hub.name}`;

	if (err) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={title} />
				<Box padding={1}><Text color="red">{err}</Text></Box>
				<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}
	if (!data) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={title} />
				<Box padding={1}><Text color="cyan">{t('remoteStats.loading')}</Text></Box>
			</Box>
		);
	}

	const o = data.orders;
	const f = data.failures;
	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={title} />
			<Box padding={1} flexDirection="column">
				<Text color="gray">
					{o.window.since.slice(0, 10)} → {o.window.until.slice(0, 10)}
				</Text>
				<Box marginTop={1} flexDirection="column">
					<Text>
						{t('remoteStats.totalOrders', {n: String(o.total)})} ·{' '}
						<Text color="green">{t('remoteStats.success', {n: String(o.by_status.valid ?? 0)})}</Text> ·{' '}
						<Text color="red">{t('remoteStats.failed', {n: String(o.by_status.invalid ?? 0)})}</Text> ·{' '}
						<Text color="yellow">{t('remoteStats.expired', {n: String(o.by_status.expired ?? 0)})}</Text>
					</Text>
					<Text color="gray">
						{t('remoteStats.successRate', {pct: (o.success_rate * 100).toFixed(1)})}
					</Text>
					<Box marginTop={1}>{renderBar(o.by_status, 40)}</Box>
				</Box>
				<Box marginTop={1} flexDirection="column">
					<Text bold>{t('remoteStats.topFailures', {n: String(f.total_invalid_orders)})}</Text>
					{f.by_problem_type.length === 0 ? (
						<Text color="gray">— {t('common.empty')}</Text>
					) : (
						f.by_problem_type.slice(0, 6).map((p, i) => (
							<Text key={i}>
								<Text color="red">{String(p.count).padStart(4)}</Text>{' '}
								<Text color="gray">{p.type.replace('urn:ietf:params:acme:error:', '')}</Text>
							</Text>
						))
					)}
				</Box>
				{f.top_failing_identifiers.length > 0 && (
					<Box marginTop={1} flexDirection="column">
						<Text bold>{t('remoteStats.topIdentifiers')}</Text>
						{f.top_failing_identifiers.slice(0, 5).map((id, i) => (
							<Text key={i}>
								<Text color="red">{String(id.count).padStart(4)}</Text>{' '}
								<Text color="cyan">{id.value}</Text>
							</Text>
						))}
					</Box>
				)}
				<Box marginTop={1} flexDirection="column">
					<Text bold>{t('remoteStats.lastDays')}</Text>
					{o.buckets.slice(-10).map((b, i) => (
						<Text key={i} color="gray">
							{b.ts}: {renderMiniBar(b)}
						</Text>
					))}
				</Box>
			</Box>
			<FunctionBar
				keys={[
					{key: 'R', label: t('remoteCerts.fbarRefresh')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}

function renderBar(status: Record<string, number>, width: number): React.ReactElement {
	const total = Object.values(status).reduce((a, b) => a + b, 0);
	if (!total) return <Text color="gray">—</Text>;
	const green = Math.round(((status.valid ?? 0) / total) * width);
	const red = Math.round(((status.invalid ?? 0) / total) * width);
	const yellow = Math.round(((status.expired ?? 0) / total) * width);
	const gray = Math.max(0, width - green - red - yellow);
	return (
		<Text>
			<Text color="green">{'█'.repeat(green)}</Text>
			<Text color="red">{'█'.repeat(red)}</Text>
			<Text color="yellow">{'█'.repeat(yellow)}</Text>
			<Text color="gray">{'░'.repeat(gray)}</Text>
		</Text>
	);
}

function renderMiniBar(b: {total: number; valid: number; invalid: number; expired: number}): string {
	if (!b.total) return '·';
	const ok = Math.max(0, b.valid);
	const bad = Math.max(0, b.invalid + b.expired);
	return `${'█'.repeat(Math.min(20, ok))}${'·'.repeat(Math.min(10, bad))}  ${b.total}`;
}
