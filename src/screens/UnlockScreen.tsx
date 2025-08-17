import React, {useState} from 'react';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {PasswordField} from '../components/TextField.js';
import {Button} from '../components/Button.js';
import {useArrowFocus} from '../components/Form.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {verifyContextPassword, writeRootMeta, readRootMeta} from '../storage/contextStore.js';
import {openContext} from '../storage/db.js';

export function UnlockScreen({name}: {name: string}) {
	useArrowFocus();
	const t = useT();
	const {pop, replace, setContextName, showToast} = useApp();
	const [password, setPassword] = useState('');
	const [error, setError] = useState<string | null>(null);

	useInput((_input, key) => {
		if (key.escape) pop();
	});

	const submit = () => {
		setError(null);
		if (!verifyContextPassword(name, password)) {
			setError(t('unlock.wrong'));
			return;
		}
		try {
			openContext(name, password);
			setContextName(name);
			const root = readRootMeta();
			root.currentContext = name;
			writeRootMeta(root);
			replace({kind: 'main'});
			showToast({kind: 'success', message: t('contexts.unlockedToast', {name})});
		} catch (e: any) {
			setError(e.message);
		}
	};

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('unlock.title', {name})} />
			<Box padding={1} flexDirection="column">
				<Text color="gray">{t('unlock.prompt')}</Text>
				<Box marginTop={1}>
					<PasswordField
						id="pass"
						label={t('context.password')}
						value={password}
						onChange={setPassword}
						onSubmit={submit}
						autoFocus
					/>
				</Box>
				{error && (
					<Box marginTop={1}>
						<Text color="red">⚠ {error}</Text>
					</Box>
				)}
				<Box marginTop={1}>
					<Button id="submit" label={t('unlock.cta')} onPress={submit} />
					<Box marginLeft={2}>
						<Button id="cancel" label={t('common.cancel')} onPress={pop} />
					</Box>
				</Box>
			</Box>
			<FunctionBar
				keys={[
					{key: 'Enter', label: t('fbar.unlock')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}
