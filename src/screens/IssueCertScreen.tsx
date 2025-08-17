import React, {useMemo, useState} from 'react';
import {Box, Text, useInput} from 'ink';
import Spinner from 'ink-spinner';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {TextField} from '../components/TextField.js';
import {Button} from '../components/Button.js';
import {Menu} from '../components/Menu.js';
import {useArrowFocus} from '../components/Form.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {issueCert} from '../certs/generator.js';
import {certRepo} from '../storage/repos.js';

export function IssueCertScreen({certType}: {certType: 'server' | 'client'}) {
	const {pop, replace, showToast} = useApp();
	const t = useT();
	const cas = useMemo(() => certRepo.list({type: 'ca'}), []);
	const signableCount = cas.filter(c => !!c.key_pem).length;
	const [step, setStep] = useState<'pick-ca' | 'form' | 'busy'>('pick-ca');
	const [caId, setCaId] = useState<number | null>(null);

	if (signableCount === 0) {
		useInput((_i, key) => {
			if (key.escape) pop();
		});
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={certType === 'server' ? t('issue.titleServer') : t('issue.titleClient')} />
				<Box padding={1}>
					<Text color="yellow">{t('issue.noCa')}</Text>
				</Box>
				<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	if (step === 'pick-ca') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('issue.pickCa')} />
				<Box padding={1}>
					<Menu
						items={cas.map(c => ({
							label: `${c.key_pem ? '🔑 ' : '🔒 '}${c.name}`,
							value: c.id,
							hint: c.key_pem
								? `CN=${c.common_name}`
								: `CN=${c.common_name} · ${t('issue.caNoKey')}`,
							disabled: !c.key_pem,
						}))}
						onSelect={(id) => {
							setCaId(id);
							setStep('form');
						}}
						onCancel={pop}
					/>
				</Box>
				<FunctionBar keys={[{key: 'Enter', label: t('fbar.pick')}, {key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	return (
		<IssueForm
			certType={certType}
			caId={caId!}
			onCancel={pop}
			onCreated={(id) => {
				showToast({kind: 'success', message: t('issue.issued')});
				replace({kind: 'cert-details', id});
			}}
		/>
	);
}

function IssueForm({
	certType,
	caId,
	onCancel,
	onCreated,
}: {
	certType: 'server' | 'client';
	caId: number;
	onCancel: () => void;
	onCreated: (id: number) => void;
}) {
	useArrowFocus();
	const t = useT();
	const issuer = useMemo(() => certRepo.findById(caId), [caId]);
	const [name, setName] = useState('');
	const [cn, setCn] = useState('');
	const [sans, setSans] = useState(certType === 'server' ? 'localhost,127.0.0.1' : '');
	const [org, setOrg] = useState('');
	const [days, setDays] = useState('365');
	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);

	useInput((_input, key) => {
		if (key.escape && !busy) onCancel();
	});

	const submit = async () => {
		setError(null);
		if (!name.trim()) return setError(t('issue.errName'));
		if (!cn.trim()) return setError(t('issue.errCn'));
		const d = parseInt(days, 10);
		if (!d) return setError(t('issue.errDays'));
		if (certRepo.findByName(name.trim())) return setError(t('issue.errNameTaken'));

		setBusy(true);
		try {
			const sanList = sans
				.split(',')
				.map(s => s.trim())
				.filter(Boolean);
			const id = await new Promise<number>((resolve, reject) => {
				setTimeout(() => {
					try {
						resolve(
							issueCert(certType, {
								name: name.trim(),
								caId,
								commonName: cn.trim(),
								organizationName: org.trim() || undefined,
								validityDays: d,
								sans: sanList,
							}),
						);
					} catch (e) {
						reject(e);
					}
				}, 10);
			});
			onCreated(id);
		} catch (e: any) {
			setError(e.message);
			setBusy(false);
		}
	};

	if (busy) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={certType === 'server' ? t('issue.titleServer') : t('issue.titleClient')} />
				<Box padding={2}>
					<Spinner type="dots" />
					<Text> {t('issue.busy')}</Text>
				</Box>
			</Box>
		);
	}

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={certType === 'server' ? t('issue.titleServer') : t('issue.titleClient')} />
			<Box padding={1} flexDirection="column">
				{issuer && (
					<Box marginBottom={1}>
						<Text color="gray">{t('issue.issuedBy')} </Text>
						<Text bold color="cyan">🔑 {issuer.name}</Text>
						<Text color="gray"> · CN={issuer.common_name}</Text>
					</Box>
				)}
				<TextField id="name" label={t('issue.dbName')} value={name} onChange={setName} autoFocus placeholder={certType === 'server' ? 'srv-api' : 'user-alice'} />
				<TextField id="cn" label={t('issue.cn')} value={cn} onChange={setCn} placeholder={certType === 'server' ? 'api.example.com' : 'alice@example.com'} />
				{certType === 'server' && (
					<TextField id="sans" label={t('issue.sans')} value={sans} onChange={setSans} placeholder="api.example.com,*.example.com,10.0.0.5" />
				)}
				<TextField id="org" label={t('issue.org')} value={org} onChange={setOrg} />
				<TextField id="days" label={t('issue.days')} value={days} onChange={setDays} />
				{error && (
					<Box marginTop={1}>
						<Text color="red">⚠ {error}</Text>
					</Box>
				)}
				<Box marginTop={1}>
					<Button id="submit" label={t('issue.cta')} onPress={submit} />
					<Box marginLeft={2}>
						<Button id="cancel" label={t('common.cancel')} onPress={onCancel} />
					</Box>
				</Box>
			</Box>
			<FunctionBar
				keys={[
					{key: 'Tab', label: t('fbar.fields')},
					{key: 'Enter', label: t('fbar.submit')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}
