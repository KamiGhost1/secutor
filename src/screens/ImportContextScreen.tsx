import React, {useState} from 'react';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {FileExplorer} from '../components/FileExplorer.js';
import {TextField, PasswordField} from '../components/TextField.js';
import {Button} from '../components/Button.js';
import {useArrowFocus} from '../components/Form.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {createContext, contextExists} from '../storage/contextStore.js';
import {importContext} from '../storage/db.js';

type Step = 'pick-file' | 'config';

export function ImportContextScreen() {
	const {pop, showToast} = useApp();
	const t = useT();
	const [step, setStep] = useState<Step>('pick-file');
	const [src, setSrc] = useState<string | null>(null);

	if (step === 'pick-file') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('importCtx.pickFile')} />
				<Box padding={1} flexDirection="column" flexGrow={1}>
					<FileExplorer
						mode="open"
						title={t('importCtx.pickFile')}
						onSelect={(p) => {
							setSrc(p);
							setStep('config');
						}}
						onCancel={pop}
					/>
				</Box>
			</Box>
		);
	}

	return (
		<ImportConfigForm
			source={src!}
			onCancel={pop}
			onDone={(name) => {
				showToast({kind: 'success', message: t('importCtx.imported', {name})});
				pop();
			}}
		/>
	);
}

function ImportConfigForm({
	source,
	onCancel,
	onDone,
}: {
	source: string;
	onCancel: () => void;
	onDone: (name: string) => void;
}) {
	useArrowFocus();
	const t = useT();
	const [name, setName] = useState('');
	const [srcPassword, setSrcPassword] = useState('');
	const [newPassword, setNewPassword] = useState('');
	const [error, setError] = useState<string | null>(null);

	useInput((_input, key) => {
		if (key.escape) onCancel();
	});

	const submit = () => {
		setError(null);
		if (!name.trim()) return setError(t('importCtx.errName'));
		if (contextExists(name.trim())) return setError(t('importCtx.errExists'));
		try {
			createContext({
				name: name.trim(),
				password: newPassword || undefined,
			});
			importContext({
				name: name.trim(),
				sourcePath: source,
				sourcePassword: srcPassword || null,
				newPassword: newPassword || null,
			});
			onDone(name.trim());
		} catch (e: any) {
			setError(e.message);
		}
	};

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('importCtx.cfgTitle')} />
			<Box padding={1} flexDirection="column">
				<Text color="gray">{t('importCtx.source', {path: source})}</Text>
				<Box marginTop={1}>
					<TextField id="name" label={t('importCtx.newName')} value={name} onChange={setName} autoFocus />
				</Box>
				<PasswordField id="src-pass" label={t('importCtx.srcPw')} value={srcPassword} onChange={setSrcPassword} placeholder={t('importCtx.srcPwPlaceholder')} />
				<PasswordField id="new-pass" label={t('importCtx.newPw')} value={newPassword} onChange={setNewPassword} placeholder={t('importCtx.newPwPlaceholder')} />
				{error && (
					<Box marginTop={1}>
						<Text color="red">⚠ {error}</Text>
					</Box>
				)}
				<Box marginTop={1}>
					<Button id="submit" label={t('importCtx.cta')} onPress={submit} />
					<Box marginLeft={2}>
						<Button id="cancel" label={t('common.cancel')} onPress={onCancel} />
					</Box>
				</Box>
			</Box>
			<FunctionBar keys={[{key: 'Enter', label: t('fbar.submit')}, {key: 'Esc', label: t('fbar.back')}]} />
		</Box>
	);
}
