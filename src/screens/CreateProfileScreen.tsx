import React, {useMemo, useState} from 'react';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Menu} from '../components/Menu.js';
import {TextField, PasswordField} from '../components/TextField.js';
import {Button} from '../components/Button.js';
import {useArrowFocus} from '../components/Form.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {certRepo, profileRepo} from '../storage/repos.js';
import {buildP12} from '../certs/generator.js';

export function CreateProfileScreen({certId}: {certId?: number}) {
	const {pop, replace, showToast} = useApp();
	const t = useT();
	const certs = useMemo(
		() => certRepo.list().filter(c => c.type !== 'ca'),
		[],
	);
	const [pickedId, setPickedId] = useState<number | null>(certId ?? null);

	if (!pickedId) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('createProfile.pickCert')} />
				<Box padding={1}>
					{certs.length === 0 ? (
						<Text color="yellow">{t('createProfile.noLeaves')}</Text>
					) : (
						<Menu
							items={certs.map(c => ({
								label: `${c.type === 'server' ? '🖥' : '👤'} ${c.name}`,
								value: c.id,
								hint: `CN=${c.common_name}`,
							}))}
							onSelect={(id) => setPickedId(id)}
							onCancel={pop}
						/>
					)}
				</Box>
				<FunctionBar keys={[{key: 'Enter', label: t('fbar.pick')}, {key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	return (
		<ProfileForm
			certId={pickedId}
			onCancel={pop}
			onCreated={(id) => {
				showToast({kind: 'success', message: t('createProfile.created')});
				replace({kind: 'export-profile', id});
			}}
		/>
	);
}

function ProfileForm({
	certId,
	onCancel,
	onCreated,
}: {
	certId: number;
	onCancel: () => void;
	onCreated: (id: number) => void;
}) {
	useArrowFocus();
	const t = useT();
	const cert = certRepo.findById(certId);
	const [name, setName] = useState(cert ? `${cert.name}-profile` : '');
	const [friendly, setFriendly] = useState(cert?.common_name || '');
	const [pass, setPass] = useState('');
	const [error, setError] = useState<string | null>(null);

	useInput((_input, key) => {
		if (key.escape) onCancel();
	});

	const submit = () => {
		setError(null);
		if (!name.trim()) return setError(t('createProfile.errName'));
		if (!cert) return setError(t('createProfile.errCertMissing'));

		const chain: typeof cert[] = [];
		let cur = cert;
		const seen = new Set<number>();
		while (cur.issuer_id && !seen.has(cur.issuer_id)) {
			seen.add(cur.issuer_id);
			const parent = certRepo.findById(cur.issuer_id);
			if (!parent) break;
			chain.push(parent);
			cur = parent;
		}

		try {
			const data = buildP12(cert, chain, pass, friendly || undefined);
			const id = profileRepo.insert({
				name: name.trim(),
				cert_id: cert.id,
				format: 'p12',
				friendly_name: friendly || null,
				data,
			});
			onCreated(id);
		} catch (e: any) {
			setError(e.message);
		}
	};

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('createProfile.title', {name: cert?.name || ''})} />
			<Box padding={1} flexDirection="column">
				<TextField id="name" label={t('createProfile.profileName')} value={name} onChange={setName} autoFocus />
				<TextField id="friendly" label={t('createProfile.friendly')} value={friendly} onChange={setFriendly} />
				<PasswordField id="pass" label={t('createProfile.password')} value={pass} onChange={setPass} />
				{error && (
					<Box marginTop={1}>
						<Text color="red">⚠ {error}</Text>
					</Box>
				)}
				<Box marginTop={1}>
					<Button id="submit" label={t('createProfile.cta')} onPress={submit} />
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
