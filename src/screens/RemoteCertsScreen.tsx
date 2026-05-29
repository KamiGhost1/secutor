import React, {useEffect, useState} from 'react';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Menu} from '../components/Menu.js';
import {Confirm} from '../components/Confirm.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {clientFor, getHub} from '../net/sessionCache.js';
import {AdminApi, type AdminCertRow} from '../net/adminApi.js';
import {HubError} from '../net/hubClient.js';
import {copyToClipboard} from '../utils/clipboard.js';

export function RemoteCertsScreen({hubId}: {hubId: string}) {
	const {pop, push, showToast} = useApp();
	const t = useT();
	const hub = getHub(hubId);
	const [rows, setRows] = useState<AdminCertRow[] | null>(null);
	const [err, setErr] = useState<string | null>(null);
	const [revoking, setRevoking] = useState<AdminCertRow | null>(null);
	const [showOnlyValid, setShowOnlyValid] = useState(false);
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
			.listCertificates(showOnlyValid ? {revoked: false} : {})
			.then(items => !cancelled && setRows(items))
			.catch(e => !cancelled && setErr(e instanceof HubError ? `${e.code}: ${e.message}` : String(e?.message ?? e)))
			.finally(() => client.close());
		return () => {
			cancelled = true;
		};
	}, [hubId, showOnlyValid, tick]);

	// Esc is handled by Menu.onCancel below when the list is loaded; while
	// loading there's no Menu and we accept Esc directly.
	useInput((input, key) => {
		if (revoking) return;
		if (rows == null && key.escape) {
			pop();
			return;
		}
		if (input === 'v' || input === 'V') setShowOnlyValid(s => !s);
		else if (input === 'r' || input === 'R') setTick(t => t + 1);
	});

	if (!hub) {
		return (
			<Box flexDirection="column">
				<Header title={t('remoteCerts.title')} />
				<Box padding={1}><Text color="red">{t('remoteHub.notFound')}</Text></Box>
				<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	if (revoking) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('remoteCerts.title')} />
				<Box padding={1}>
					<Confirm
						message={t('remoteCerts.confirmRevoke', {
							serial: revoking.serial_hex.slice(0, 16) + '…',
						})}
						onCancel={() => setRevoking(null)}
						onConfirm={() => {
							const target = revoking;
							setRevoking(null);
							const client = clientFor(hubId);
							new AdminApi(client)
								.revokeCertificate(target.id, 1 /* keyCompromise */)
								.then(() => {
									showToast({kind: 'success', message: t('remoteCerts.revoked')});
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
			<Header title={`${t('remoteCerts.title')} — 🌐 ${hub.name}`} />
			<Box padding={1}>
				<Text color="gray">
					{showOnlyValid ? t('remoteCerts.filterValid') : t('remoteCerts.filterAll')}
				</Text>
			</Box>
			{err && (
				<Box padding={1}><Text color="red">{err}</Text></Box>
			)}
			<Box flexGrow={1} paddingX={1}>
				{rows == null ? (
					<Text color="cyan">{t('remoteCerts.loading')}</Text>
				) : (
					<Menu
						emptyText={t('remoteCerts.empty')}
						items={rows.map(r => {
							const ids = r.identifiers ?? [];
							const idsLabel = ids.length === 0
								? '(no identifiers)'
								: ids.length <= 2
									? ids.join(', ')
									: `${ids.slice(0, 2).join(', ')} +${ids.length - 2}`;
							return {
								label: `${r.revoked ? '🚫' : '✓'} ${idsLabel}`,
								value: r.id,
								hint: `serial ${r.serial_hex.slice(0, 12)}… · iss ${r.issued_at.slice(0, 10)} · exp ${r.not_after.slice(0, 10)}${
									r.revoked ? ` · reason ${r.revocation_reason ?? '?'}` : ''
								}`,
							};
						})}
						onSelect={(id) => push({kind: 'remote-cert-details', hubId, certId: id as string})}
						onCancel={pop}
						onAction={(input, _k, item) => {
							if ((input === 'd' || input === 'D') && item) {
								const row = rows.find(x => x.id === item.value);
								if (row && !row.revoked) setRevoking(row);
								else if (row && row.revoked) {
									showToast({kind: 'info', message: t('remoteCerts.alreadyRevoked')});
								}
							} else if ((input === 'c' || input === 'C') && item) {
								const row = rows.find(x => x.id === item.value);
								if (!row) return;
								const r = copyToClipboard(row.serial_hex);
								if (r.ok) {
									showToast({kind: 'success', message: t('remoteCerts.serialCopied', {via: r.via})});
								} else {
									showToast({kind: 'error', message: r.error});
								}
							}
						}}
					/>
				)}
			</Box>
			<FunctionBar
				keys={[
					{key: 'V', label: t('remoteCerts.fbarToggleFilter')},
					{key: 'D', label: t('remoteCerts.fbarRevoke')},
					{key: 'C', label: t('remoteCerts.fbarCopySerial')},
					{key: 'R', label: t('remoteCerts.fbarRefresh')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}
