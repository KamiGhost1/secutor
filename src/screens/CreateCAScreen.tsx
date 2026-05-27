import React, {useState} from 'react';
import {Box, Text, useInput} from 'ink';
import Spinner from 'ink-spinner';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {TextField, PasswordField} from '../components/TextField.js';
import {Button} from '../components/Button.js';
import {AlgorithmPicker} from '../components/AlgorithmPicker.js';
import {ScrollableForm} from '../components/ScrollableForm.js';
import {useArrowFocus} from '../components/Form.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {createCA} from '../certs/generator.js';
import {certRepo} from '../storage/repos.js';
import {KeyAlgorithm} from '../certs/keys.js';

export function CreateCAScreen() {
	useArrowFocus();
	const {pop, replace, showToast} = useApp();
	const t = useT();
	const [name, setName] = useState('');
	const [cn, setCn] = useState('');
	const [org, setOrg] = useState('');
	const [country, setCountry] = useState('US');
	const [state, setState] = useState('');
	const [city, setCity] = useState('');
	const [email, setEmail] = useState('');
	const [days, setDays] = useState('3650');
	const [algorithm, setAlgorithm] = useState<KeyAlgorithm>('rsa-2048');
	const [keyPw, setKeyPw] = useState('');
	const [keyPwRepeat, setKeyPwRepeat] = useState('');
	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);

	useInput((_input, key) => {
		if (key.escape && !busy) pop();
	});

	const submit = async () => {
		setError(null);
		if (!name.trim()) return setError(t('createCa.errName'));
		if (!cn.trim()) return setError(t('createCa.errCn'));
		const d = parseInt(days, 10);
		if (!d || d < 1) return setError(t('createCa.errDays'));
		if (certRepo.findByName(name.trim())) return setError(t('createCa.errNameTaken'));
		if (keyPw && keyPw !== keyPwRepeat) return setError(t('createCa.errKeyPwMismatch'));
		if (keyPw && keyPw.length < 4) return setError(t('createCa.errKeyPwShort'));

		setBusy(true);
		try {
			const id = await new Promise<number>((resolve, reject) => {
				setTimeout(() => {
					try {
						resolve(
							createCA({
								name: name.trim(),
								commonName: cn.trim(),
								organizationName: org.trim() || undefined,
								countryName: country.trim() || undefined,
								stateOrProvinceName: state.trim() || undefined,
								localityName: city.trim() || undefined,
								emailAddress: email.trim() || undefined,
								validityDays: d,
								algorithm,
								keyPassword: keyPw || null,
							}),
						);
					} catch (e) {
						reject(e);
					}
				}, 10);
			});
			showToast({kind: 'success', message: t('createCa.created', {name: name.trim()})});
			replace({kind: 'cert-details', id});
		} catch (e: any) {
			setError(e.message);
			setBusy(false);
		}
	};

	if (busy) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('createCa.title')} />
				<Box padding={2} flexDirection="row">
					<Spinner type="dots" />
					<Text> {t('createCa.busy')}</Text>
				</Box>
			</Box>
		);
	}

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('createCa.title')} />
			<Box padding={1} flexDirection="column" flexShrink={0}>
				<ScrollableForm>
					<TextField id="name" label={t('createCa.dbName')} value={name} onChange={setName} autoFocus placeholder="root-ca" />
					<TextField id="cn" label={t('createCa.cn')} value={cn} onChange={setCn} placeholder="My Root CA" />
					<AlgorithmPicker id="algorithm" label={t('createCa.algorithm')} value={algorithm} onChange={setAlgorithm} />
					<TextField id="org" label={t('createCa.org')} value={org} onChange={setOrg} />
					<TextField id="country" label={t('createCa.country')} value={country} onChange={setCountry} />
					<TextField id="state" label={t('createCa.state')} value={state} onChange={setState} />
					<TextField id="city" label={t('createCa.city')} value={city} onChange={setCity} />
					<TextField id="email" label={t('createCa.email')} value={email} onChange={setEmail} />
					<TextField id="days" label={t('createCa.days')} value={days} onChange={setDays} />
					<Box flexDirection="row" flexShrink={0}>
						<Text color="gray">{t('createCa.passphraseSection')}</Text>
					</Box>
					<PasswordField id="keyPw" label={t('createCa.keyPassword')} value={keyPw} onChange={setKeyPw} placeholder={t('createCa.keyPasswordHint')} />
					<PasswordField id="keyPwRepeat" label={t('createCa.keyPasswordRepeat')} value={keyPwRepeat} onChange={setKeyPwRepeat} />
					<Box flexDirection="row" flexShrink={0}>
						<Button id="submit" label={t('common.create')} onPress={submit} />
						<Box marginLeft={2} flexShrink={0}>
							<Button id="cancel" label={t('common.cancel')} onPress={pop} />
						</Box>
					</Box>
				</ScrollableForm>
				{error && (
					<Box marginTop={1} flexShrink={0}>
						<Text color="red">⚠ {error}</Text>
					</Box>
				)}
			</Box>
			<FunctionBar
				keys={[
					{key: 'Tab', label: t('fbar.fields')},
					{key: 'Ctrl+K', label: t('fbar.algorithm')},
					{key: 'Enter', label: t('fbar.submit')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}
