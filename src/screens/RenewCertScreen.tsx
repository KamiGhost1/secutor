import React, {useMemo, useState} from 'react';
import {Box, Text, useInput} from 'ink';
import Spinner from 'ink-spinner';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {TextField} from '../components/TextField.js';
import {Button} from '../components/Button.js';
import {useArrowFocus} from '../components/Form.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {certRepo} from '../storage/repos.js';
import {renewCertificate} from '../certs/generator.js';
import {expiryStatusOfRow, expiryColor, expiryIcon} from '../certs/expiry.js';

export function RenewCertScreen({id}: {id: number}) {
	useArrowFocus();
	const {pop, replace, showToast} = useApp();
	const t = useT();
	const row = useMemo(() => certRepo.findById(id), [id]);

	const originalDays = useMemo(() => {
		if (!row) return 365;
		const before = Date.parse(row.not_before);
		const after = Date.parse(row.not_after);
		if (!Number.isFinite(before) || !Number.isFinite(after)) return 365;
		const days = Math.round((after - before) / (24 * 3600 * 1000));
		return days > 0 ? days : 365;
	}, [row]);

	const [days, setDays] = useState(String(originalDays));
	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);

	useInput((_input, key) => {
		if (key.escape && !busy) pop();
	});

	if (!row) {
		return (
			<Box flexDirection="column">
				<Header title={t('renew.title')} />
				<Box padding={1}>
					<Text color="red">{t('cert.notFound')}</Text>
				</Box>
				<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	const status = expiryStatusOfRow(row);
	const isSelfSigned =
		row.type === 'ca' && row.issuer_id === null;
	const parent = row.issuer_id !== null ? certRepo.findById(row.issuer_id) : null;
	const signerName = isSelfSigned ? row.name : parent?.name || '—';
	const signerHasKey = isSelfSigned ? !!row.key_pem : !!parent?.key_pem;

	const submit = async () => {
		setError(null);
		const d = parseInt(days, 10);
		if (!d || d < 1) return setError(t('renew.errDays'));
		if (!signerHasKey) return setError(t('renew.errNoKey'));

		setBusy(true);
		try {
			const result = await new Promise<ReturnType<typeof renewCertificate>>((res, rej) => {
				setTimeout(() => {
					try {
						res(renewCertificate(id, {validityDays: d}));
					} catch (e) {
						rej(e);
					}
				}, 10);
			});
			certRepo.replaceCert(id, {
				cert_pem: result.certPem,
				issuer_id: result.newIssuerId,
				serial: result.serial,
				not_before: result.notBefore.toISOString(),
				not_after: result.notAfter.toISOString(),
				fingerprint: result.fingerprint,
			});
			showToast({
				kind: 'success',
				message: t('renew.toastDone', {
					name: row.name,
					to: result.notAfter.toISOString().slice(0, 10),
				}),
			});
			replace({kind: 'cert-details', id});
		} catch (e: any) {
			setError(e.message);
			setBusy(false);
		}
	};

	if (busy) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('renew.title')} />
				<Box padding={2}>
					<Spinner type="dots" />
					<Text> {t('renew.busy')}</Text>
				</Box>
			</Box>
		);
	}

	const statusLabel =
		status.kind === 'expired'
			? t('renew.statusExpired', {days: status.daysOverdue})
			: status.kind === 'expiring-soon'
			? t('renew.statusSoon', {days: status.daysLeft})
			: status.kind === 'not-yet-valid'
			? t('renew.statusFuture', {days: status.daysUntilStart})
			: t('renew.statusOk', {days: status.daysLeft});

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('renew.title')} />
			<Box padding={1} flexDirection="column">
				<Box flexDirection="column" marginBottom={1}>
					<Text>
						<Text color="gray">{t('renew.cert')}: </Text>
						<Text bold>{row.name}</Text>
						<Text color="gray"> · CN={row.common_name}</Text>
					</Text>
					<Text>
						<Text color="gray">{t('renew.signer')}: </Text>
						<Text bold>{signerName}</Text>
						<Text color="gray">
							{' '}
							{isSelfSigned ? `(${t('renew.signerSelf')})` : ''}
							{!signerHasKey ? ` · ${t('renew.signerNoKey')}` : ''}
						</Text>
					</Text>
					<Text>
						<Text color="gray">{t('renew.currentNotAfter')}: </Text>
						<Text>{row.not_after.slice(0, 10)}</Text>
					</Text>
					<Text>
						<Text color="gray">{t('renew.currentStatus')}: </Text>
						<Text color={expiryColor(status)}>
							{expiryIcon(status)} {statusLabel}
						</Text>
					</Text>
				</Box>
				<TextField
					id="days"
					label={t('renew.days')}
					value={days}
					onChange={setDays}
					autoFocus
					placeholder={String(originalDays)}
				/>
				<Text color="gray">{t('renew.daysHint')}</Text>
				{error && (
					<Box marginTop={1}>
						<Text color="red">⚠ {error}</Text>
					</Box>
				)}
				<Box marginTop={1}>
					<Button
						id="submit"
						label={t('renew.cta')}
						onPress={submit}
						disabled={!signerHasKey}
					/>
					<Box marginLeft={2}>
						<Button id="cancel" label={t('common.cancel')} onPress={pop} />
					</Box>
				</Box>
			</Box>
			<FunctionBar
				keys={[
					{key: 'Enter', label: t('fbar.submit')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}
