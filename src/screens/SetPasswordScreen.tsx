import React, {useState} from 'react';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {PasswordField} from '../components/TextField.js';
import {Button} from '../components/Button.js';
import {useArrowFocus} from '../components/Form.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {getContextMeta, setContextPassword} from '../storage/contextStore.js';
import {closeContext, openContext} from '../storage/db.js';

export function SetPasswordScreen({name}: {name: string}) {
	useArrowFocus();
	const {pop, showToast, replace, setContextName} = useApp();
	const t = useT();
	const meta = getContextMeta(name);
	const [oldPass, setOldPass] = useState('');
	const [newPass, setNewPass] = useState('');
	const [newPass2, setNewPass2] = useState('');
	const [removePass, setRemovePass] = useState(false);
	const [error, setError] = useState<string | null>(null);

	useInput((input, key) => {
		if (key.escape) pop();
		if (input === 'r' && key.ctrl) setRemovePass(v => !v);
	});

	const submit = () => {
		setError(null);
		if (!removePass) {
			if (newPass.length < 4) return setError(t('setPw.errPwShort'));
			if (newPass !== newPass2) return setError(t('setPw.errPwMismatch'));
		}
		try {
			closeContext();
			setContextPassword(name, oldPass || null, removePass ? null : newPass);
			openContext(name, removePass ? null : newPass);
			setContextName(name);
			showToast({
				kind: 'success',
				message: removePass ? t('setPw.removed') : t('setPw.changed'),
			});
			replace({kind: 'main'});
		} catch (e: any) {
			setError(e.message);
		}
	};

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('setPw.title', {name})} />
			<Box padding={1} flexDirection="column">
				<Text color="gray">
					{t('setPw.state', {state: meta?.encrypted ? t('setPw.encrypted') : t('setPw.unencrypted')})}
				</Text>
				<Box marginTop={1} />
				{meta?.encrypted && (
					<PasswordField id="old" label={t('setPw.current')} value={oldPass} onChange={setOldPass} autoFocus />
				)}
				<Box>
					<Text color={removePass ? 'green' : 'gray'}>
						{t('setPw.removeToggle', {state: removePass ? '✔' : '✘'})}
					</Text>
				</Box>
				{!removePass && (
					<>
						<PasswordField id="new" label={t('setPw.new')} value={newPass} onChange={setNewPass} autoFocus={!meta?.encrypted} />
						<PasswordField id="new2" label={t('setPw.repeat')} value={newPass2} onChange={setNewPass2} />
					</>
				)}
				{error && (
					<Box marginTop={1}>
						<Text color="red">⚠ {error}</Text>
					</Box>
				)}
				<Box marginTop={1}>
					<Button id="submit" label={t('common.apply')} onPress={submit} />
					<Box marginLeft={2}>
						<Button id="cancel" label={t('common.cancel')} onPress={pop} />
					</Box>
				</Box>
			</Box>
			<FunctionBar
				keys={[
					{key: 'Tab', label: t('fbar.fields')},
					{key: 'Enter', label: t('common.apply')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}
