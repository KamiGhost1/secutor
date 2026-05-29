import React, {useState} from 'react';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Confirm} from '../components/Confirm.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {certRepo} from '../storage/repos.js';
import {parseCertPem} from '../certs/parser.js';
import {verifyCertById} from '../certs/verify.js';
import {expiryStatusOfRow, expiryColor, expiryIcon} from '../certs/expiry.js';
import {copyToClipboard} from '../utils/clipboard.js';

export function CertDetailsScreen({id}: {id: number}) {
	const {pop, push, showToast} = useApp();
	const t = useT();
	const [, setTick] = useState(0);
	const [confirmRevoke, setConfirmRevoke] = useState(false);
	// Re-read on every render — the screen state is small (one row + verify walk)
	// and we want any external change (relink, re-sign, revoke, etc.) to surface
	// immediately when this screen re-renders, e.g. after navigating back from
	// the reassign-issuer flow.
	const row = certRepo.findById(id);

	if (!row) {
		return (
			<Box flexDirection="column">
				<Header title={t('cert.notFound')} />
				<Box padding={1}>
					<Text color="red">{t('cert.notFound')} (id={id})</Text>
				</Box>
				<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	const parsed = parseCertPem(row.cert_pem);
	const verify = verifyCertById(id);
	const canRevoke = row.issuer_id !== null;
	const isRevoked = !!row.revoked_at;
	const expiry = expiryStatusOfRow(row);
	const isSelfSigned = row.type === 'ca' && row.issuer_id === null;
	const canRenew =
		isSelfSigned ? !!row.key_pem : !!(row.issuer_id !== null && certRepo.findById(row.issuer_id!)?.key_pem);

	useInput((input, key) => {
		if (confirmRevoke) return;
		if (key.escape) pop();
		else if (input === 'e' || input === 'E') push({kind: 'export-cert', id});
		else if (input === 'p' || input === 'P') push({kind: 'create-profile', certId: id});
		else if (input === 'v' || input === 'V') push({kind: 'verify'});
		else if (input === 'm' || input === 'M') push({kind: 'reassign-issuer', id});
		else if (input === 't' || input === 'T') push({kind: 'transfer-entity', transferKind: 'cert', id});
		else if (input === 'c' || input === 'C') {
			const r = copyToClipboard(row.fingerprint);
			if (r.ok) {
				showToast({kind: 'success', message: t('cert.fpCopied', {via: r.via})});
			} else {
				showToast({kind: 'error', message: t('cert.fpCopyFailed', {err: r.error})});
			}
		}
		else if ((input === 'n' || input === 'N') && canRenew) push({kind: 'renew-cert', id});
		else if ((input === 'r' || input === 'R') && canRevoke) {
			if (isRevoked) {
				certRepo.unrevoke(id);
				setTick(x => x + 1);
				showToast({kind: 'success', message: t('cert.unrevoked')});
			} else {
				setConfirmRevoke(true);
			}
		}
	});

	if (confirmRevoke) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('cert.title', {name: row.name})} />
				<Box padding={1}>
					<Confirm
						message={t('cert.confirmRevoke', {name: row.name})}
						onConfirm={() => {
							certRepo.revoke(id, null);
							setConfirmRevoke(false);
							setTick(x => x + 1);
							showToast({kind: 'success', message: t('cert.revoked')});
						}}
						onCancel={() => setConfirmRevoke(false)}
					/>
				</Box>
			</Box>
		);
	}

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('cert.title', {name: row.name})} />
			<Box padding={1} flexDirection="column" flexGrow={1}>
				<Row label={t('cert.row.dbName')} value={row.name} />
				<Row label={t('cert.row.type')} value={row.type.toUpperCase()} />
				<Row label={t('cert.row.cn')} value={parsed.subject.commonName || '—'} />
				<Row label={t('cert.row.org')} value={parsed.subject.organizationName || '—'} />
				<Row
					label={t('cert.row.cscity')}
					value={`${parsed.subject.countryName || '—'} / ${parsed.subject.stateOrProvinceName || '—'} / ${parsed.subject.localityName || '—'}`}
				/>
				<Row label={t('cert.row.email')} value={parsed.subject.emailAddress || '—'} />
				<Row label={t('cert.row.issuer')} value={parsed.issuer.commonName || '—'} />
				<Row label={t('cert.row.serial')} value={parsed.serial} />
				<Row label={t('cert.row.notBefore')} value={parsed.notBefore.toISOString()} />
				<Box>
					<Box width={26}>
						<Text color="gray">{t('cert.row.notAfter')}</Text>
					</Box>
					<Box flexGrow={1}>
						<Text color={expiryColor(expiry)}>
							{expiryIcon(expiry)} {parsed.notAfter.toISOString()} ·{' '}
							{expiry.kind === 'expired'
								? t('expiry.expiredFor', {days: expiry.daysOverdue})
								: expiry.kind === 'expiring-soon'
								? t('expiry.expiringIn', {days: expiry.daysLeft})
								: expiry.kind === 'not-yet-valid'
								? t('expiry.notYetValid', {days: expiry.daysUntilStart})
								: t('expiry.validFor', {days: expiry.daysLeft})}
						</Text>
					</Box>
				</Box>
				<Row label={t('cert.row.san')} value={parsed.sans.length ? parsed.sans.join(', ') : '—'} />
				<Row label={t('cert.row.keyUsage')} value={parsed.keyUsage.join(', ') || '—'} />
				<Row label={t('cert.row.eku')} value={parsed.extKeyUsage.join(', ') || '—'} />
				<Row label={t('cert.row.fp')} value={row.fingerprint} />
				<Row label={t('cert.row.created')} value={row.created_at} />
				{isRevoked && (
					<Box marginTop={1}>
						<Text bold color="red">
							⛔ {t('cert.revokedAt', {date: row.revoked_at!})}
							{row.revocation_reason ? ` (${row.revocation_reason})` : ''}
						</Text>
					</Box>
				)}
				<Box marginTop={1}>
					<Text bold color={verify.ok ? 'green' : 'red'}>
						{verify.ok ? '✔ ' + t('cert.valid') : `✘ ${verify.reason}`}
					</Text>
				</Box>
				<Box>
					<Text color="gray">{t('cert.chain', {chain: verify.chain.join(' → ')})}</Text>
				</Box>
			</Box>
			<FunctionBar
				keys={[
					{key: 'E', label: t('fbar.export')},
					{key: 'P', label: t('fbar.makeP12')},
					{key: 'V', label: t('fbar.verify')},
					{key: 'M', label: t('fbar.manageIssuer')},
					{key: 'T', label: t('fbar.transfer')},
					{key: 'C', label: t('fbar.copyFp')},
					...(canRenew ? [{key: 'N', label: t('fbar.renew')}] : []),
					...(canRevoke
						? [{key: 'R', label: isRevoked ? t('fbar.unrevoke') : t('fbar.revoke')}]
						: []),
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}

function Row({label, value}: {label: string; value: string}) {
	return (
		<Box>
			<Box width={26}>
				<Text color="gray">{label}</Text>
			</Box>
			<Box flexGrow={1}>
				<Text>{value}</Text>
			</Box>
		</Box>
	);
}
