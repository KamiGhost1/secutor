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
import {issueIntermediateCA} from '../certs/generator.js';
import {certRepo} from '../storage/repos.js';

export function IssueIntermediateCAScreen() {
	const {pop, replace, showToast} = useApp();
	const t = useT();
	const cas = useMemo(() => certRepo.list({type: 'ca'}), []);
	const signableCount = cas.filter(c => !!c.key_pem).length;
	const [step, setStep] = useState<'pick-ca' | 'form'>('pick-ca');
	const [caId, setCaId] = useState<number | null>(null);

	if (signableCount === 0) {
		useInput((_i, key) => {
			if (key.escape) pop();
		});
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('issueCa.title')} />
				<Box padding={1}>
					<Text color="yellow">{t('issueCa.noCa')}</Text>
				</Box>
				<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	if (step === 'pick-ca') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('issueCa.pickCa')} />
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
		<IssueIntermediateForm
			caId={caId!}
			onCancel={pop}
			onCreated={(id) => {
				showToast({kind: 'success', message: t('issueCa.created')});
				replace({kind: 'cert-details', id});
			}}
		/>
	);
}

function IssueIntermediateForm({
	caId,
	onCancel,
	onCreated,
}: {
	caId: number;
	onCancel: () => void;
	onCreated: (id: number) => void;
}) {
	useArrowFocus();
	const t = useT();
	const issuer = useMemo(() => certRepo.findById(caId), [caId]);
	const [name, setName] = useState('');
	const [cn, setCn] = useState('');
	const [org, setOrg] = useState('');
	const [country, setCountry] = useState('');
	const [state, setState] = useState('');
	const [city, setCity] = useState('');
	const [email, setEmail] = useState('');
	const [days, setDays] = useState('1825');
	const [pathLen, setPathLen] = useState('0');
	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);

	useInput((_input, key) => {
		if (key.escape && !busy) onCancel();
	});

	const submit = async () => {
		setError(null);
		if (!name.trim()) return setError(t('issueCa.errName'));
		if (!cn.trim()) return setError(t('issueCa.errCn'));
		const d = parseInt(days, 10);
		if (!d || d < 1) return setError(t('issueCa.errDays'));
		if (certRepo.findByName(name.trim())) return setError(t('issueCa.errNameTaken'));

		const trimmedPathLen = pathLen.trim();
		let pl: number | undefined;
		if (trimmedPathLen.length > 0) {
			const parsed = parseInt(trimmedPathLen, 10);
			if (Number.isNaN(parsed) || parsed < 0) return setError(t('issueCa.errPathLen'));
			pl = parsed;
		}

		setBusy(true);
		try {
			const id = await new Promise<number>((resolve, reject) => {
				setTimeout(() => {
					try {
						resolve(
							issueIntermediateCA({
								name: name.trim(),
								caId,
								commonName: cn.trim(),
								organizationName: org.trim() || undefined,
								countryName: country.trim() || undefined,
								stateOrProvinceName: state.trim() || undefined,
								localityName: city.trim() || undefined,
								emailAddress: email.trim() || undefined,
								validityDays: d,
								pathLenConstraint: pl,
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
				<Header title={t('issueCa.title')} />
				<Box padding={2} flexDirection="row">
					<Spinner type="dots" />
					<Text> {t('issueCa.busy')}</Text>
				</Box>
			</Box>
		);
	}

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('issueCa.title')} />
			<Box padding={1} flexDirection="column">
				{issuer && (
					<Box marginBottom={1}>
						<Text color="gray">{t('issue.issuedBy')} </Text>
						<Text bold color="cyan">🔑 {issuer.name}</Text>
						<Text color="gray"> · CN={issuer.common_name}</Text>
					</Box>
				)}
				<TextField id="name" label={t('issueCa.dbName')} value={name} onChange={setName} autoFocus placeholder="intermediate-ca" />
				<TextField id="cn" label={t('issueCa.cn')} value={cn} onChange={setCn} placeholder="My Intermediate CA" />
				<TextField id="org" label={t('issueCa.org')} value={org} onChange={setOrg} />
				<TextField id="country" label={t('issueCa.country')} value={country} onChange={setCountry} />
				<TextField id="state" label={t('issueCa.state')} value={state} onChange={setState} />
				<TextField id="city" label={t('issueCa.city')} value={city} onChange={setCity} />
				<TextField id="email" label={t('issueCa.email')} value={email} onChange={setEmail} />
				<TextField id="days" label={t('issueCa.days')} value={days} onChange={setDays} />
				<TextField id="pathLen" label={t('issueCa.pathLen')} value={pathLen} onChange={setPathLen} placeholder={t('issueCa.pathLenPlaceholder')} />
				{error && (
					<Box marginTop={1}>
						<Text color="red">⚠ {error}</Text>
					</Box>
				)}
				<Box marginTop={1}>
					<Button id="submit" label={t('issueCa.cta')} onPress={submit} />
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
