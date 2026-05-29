import React, {useEffect, useState} from 'react';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {clientFor, getHub} from '../net/sessionCache.js';
import {AdminApi} from '../net/adminApi.js';

export function JobProgressScreen({hubId, jobId}: {hubId: string; jobId: string}) {
	const {pop, showToast} = useApp();
	const t = useT();
	const hub = getHub(hubId);
	const [job, setJob] = useState<Awaited<ReturnType<AdminApi['getJob']>> | null>(null);
	const [err, setErr] = useState<string | null>(null);

	useEffect(() => {
		let cancelled = false;
		const tick = () => {
			if (cancelled) return;
			try {
				const client = clientFor(hubId);
				new AdminApi(client)
					.getJob(jobId)
					.then(j => !cancelled && setJob(j))
					.catch(e => !cancelled && setErr(e?.message ?? String(e)))
					.finally(() => client.close());
			} catch (e: any) {
				setErr(e?.message ?? String(e));
			}
		};
		tick();
		const id = setInterval(tick, 1000);
		return () => {
			cancelled = true;
			clearInterval(id);
		};
	}, [hubId, jobId]);

	useInput((input, key) => {
		if (key.escape) pop();
		else if ((input === 'c' || input === 'C') && job && job.status === 'running') {
			const client = clientFor(hubId);
			new AdminApi(client)
				.cancelJob(jobId)
				.then(() => showToast({kind: 'success', message: t('jobProgress.cancelled')}))
				.catch(e => showToast({kind: 'error', message: e?.message ?? String(e)}))
				.finally(() => client.close());
		}
	});

	if (!hub) return null;
	const title = `${t('jobProgress.title')} — 🌐 ${hub.name}`;

	if (err) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={title} />
				<Box padding={1}><Text color="red">{err}</Text></Box>
				<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}
	if (!job) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={title} />
				<Box padding={1}><Text color="cyan">{t('common.empty')}…</Text></Box>
			</Box>
		);
	}

	const pct = job.total ? Math.floor(((job.done + job.failed) / job.total) * 100) : 100;
	const bar = renderProgress(job.done, job.failed, job.total, 40);
	const statusColor =
		job.status === 'done' ? 'green' :
		job.status === 'failed' ? 'red' :
		job.status === 'cancelled' ? 'yellow' : 'cyan';

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={title} />
			<Box padding={1} flexDirection="column">
				<Text>
					{t('jobProgress.jobId')}: <Text color="gray">{job.id.slice(0, 16)}…</Text>
				</Text>
				<Text>
					{t('jobProgress.status')}: <Text color={statusColor}>{job.status}</Text>
				</Text>
				<Box marginTop={1}>{bar}</Box>
				<Text>
					{t('jobProgress.counts', {
						done: String(job.done),
						failed: String(job.failed),
						total: String(job.total),
						pct: String(pct),
					})}
				</Text>
				<Text color="gray">
					{t('jobProgress.started')}: {job.started_at.replace('T', ' ').slice(0, 19)}
				</Text>
				{job.finished_at && (
					<Text color="gray">
						{t('jobProgress.finished')}: {job.finished_at.replace('T', ' ').slice(0, 19)}
					</Text>
				)}
			</Box>
			<FunctionBar
				keys={[
					...(job.status === 'running' ? [{key: 'C', label: t('jobProgress.fbarCancel')}] : []),
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}

function renderProgress(done: number, failed: number, total: number, width: number): React.ReactElement {
	if (!total) return <Text color="gray">—</Text>;
	const okW = Math.round((done / total) * width);
	const failW = Math.round((failed / total) * width);
	const pendW = Math.max(0, width - okW - failW);
	return (
		<Text>
			<Text color="green">{'█'.repeat(okW)}</Text>
			<Text color="red">{'█'.repeat(failW)}</Text>
			<Text color="gray">{'░'.repeat(pendW)}</Text>
		</Text>
	);
}
