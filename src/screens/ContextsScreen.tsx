import React, {useState} from 'react';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Menu} from '../components/Menu.js';
import {Confirm} from '../components/Confirm.js';
import {TextField, PasswordField} from '../components/TextField.js';
import {Button} from '../components/Button.js';
import {useArrowFocus} from '../components/Form.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {useFunctionKey} from '../input/useFunctionKey.js';
import {
	listContexts,
	createContext,
	deleteContext,
	writeRootMeta,
	readRootMeta,
} from '../storage/contextStore.js';
import {openContext} from '../storage/db.js';

type Mode = 'list' | 'create' | 'confirm-delete';

export function ContextsScreen() {
	const {push, replace, setContextName, showToast, exit} = useApp();
	const t = useT();
	const [mode, setMode] = useState<Mode>('list');
	const [contexts, setContexts] = useState(() => listContexts());
	const [pendingDelete, setPendingDelete] = useState<string | null>(null);

	const refresh = () => setContexts(listContexts());

	useFunctionKey('f10', () => exit(), []);

	if (mode === 'create') {
		return (
			<CreateContextForm
				onCancel={() => setMode('list')}
				onCreated={(name) => {
					refresh();
					setMode('list');
					showToast({kind: 'success', message: t('contexts.created2', {name})});
				}}
			/>
		);
	}

	if (mode === 'confirm-delete' && pendingDelete) {
		return (
			<Box flexDirection="column">
				<Header title={t('contexts.title')} />
				<Box padding={1}>
					<Confirm
						message={t('contexts.confirmDelete', {name: pendingDelete})}
						onConfirm={() => {
							deleteContext(pendingDelete);
							setPendingDelete(null);
							setMode('list');
							refresh();
							showToast({kind: 'success', message: t('contexts.deleted')});
						}}
						onCancel={() => {
							setPendingDelete(null);
							setMode('list');
						}}
					/>
				</Box>
			</Box>
		);
	}

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('contexts.title')} />
			<Box padding={1} flexDirection="column" flexGrow={1}>
				<Menu
					searchable
					searchPlaceholder={t('search.placeholder')}
					title={t('contexts.pickPrompt')}
					emptyText={t('contexts.empty')}
					items={contexts.map(c => ({
						label: c.name,
						value: c.name,
						hint: `${c.encrypted ? '🔒 ' + t('contexts.encrypted') : '○ ' + t('contexts.plain')} · ${t('contexts.created', {date: c.createdAt.slice(0, 10)})}`,
					}))}
					onSelect={(name) => {
						const ctx = contexts.find(c => c.name === name)!;
						if (ctx.encrypted) {
							push({kind: 'unlock', name});
						} else {
							try {
								openContext(name, null);
								setContextName(name);
								const root = readRootMeta();
								root.currentContext = name;
								writeRootMeta(root);
								replace({kind: 'main'});
							} catch (e: any) {
								showToast({kind: 'error', message: e.message});
							}
						}
					}}
					onAction={(input, _key, item) => {
						if (input === 'n' || input === 'N') setMode('create');
						else if ((input === 'd' || input === 'D') && item) {
							setPendingDelete(item.value as string);
							setMode('confirm-delete');
						} else if (input === 'i' || input === 'I') push({kind: 'import-context'});
						else if (input === 's' || input === 'S') push({kind: 'settings'});
						else if (input === 'q' || input === 'Q') exit();
					}}
				/>
			</Box>
			<FunctionBar
				keys={[
					{key: 'N', label: t('fbar.new')},
					{key: 'D', label: t('fbar.delete')},
					{key: 'I', label: t('fbar.import')},
					{key: 'S', label: t('main.settings')},
					{key: '/', label: t('fbar.search')},
					{key: 'Enter', label: t('fbar.openCmd')},
					{key: 'F10', label: t('fbar.quit')},
				]}
			/>
		</Box>
	);
}

function CreateContextForm({
	onCancel,
	onCreated,
}: {
	onCancel: () => void;
	onCreated: (name: string) => void;
}) {
	useArrowFocus();
	const t = useT();
	const [name, setName] = useState('');
	const [usePass, setUsePass] = useState(false);
	const [pass1, setPass1] = useState('');
	const [pass2, setPass2] = useState('');
	const [error, setError] = useState<string | null>(null);

	useInput((input, key) => {
		if (key.escape) onCancel();
		if (input === 'e' && key.ctrl) setUsePass(v => !v);
	});

	const submit = () => {
		setError(null);
		if (!name.trim()) return setError(t('context.errEnterName'));
		if (usePass) {
			if (pass1.length < 4) return setError(t('context.errPwShort'));
			if (pass1 !== pass2) return setError(t('context.errPwMismatch'));
		}
		try {
			createContext({name: name.trim(), password: usePass ? pass1 : undefined});
			onCreated(name.trim());
		} catch (e: any) {
			setError(e.message);
		}
	};

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('context.newTitle')} />
			<Box padding={1} flexDirection="column">
				<TextField
					id="name"
					label={t('context.name')}
					value={name}
					onChange={setName}
					autoFocus
					placeholder={t('context.namePlaceholder')}
				/>
				<Box marginTop={1}>
					<Text color={usePass ? 'green' : 'gray'}>
						{t('context.encryptToggle', {state: usePass ? '✔' : '✘'})}
					</Text>
				</Box>
				{usePass && (
					<Box flexDirection="column" marginTop={1}>
						<PasswordField id="p1" label={t('context.password')} value={pass1} onChange={setPass1} />
						<PasswordField id="p2" label={t('context.repeat')} value={pass2} onChange={setPass2} />
					</Box>
				)}
				{error && (
					<Box marginTop={1}>
						<Text color="red">⚠ {error}</Text>
					</Box>
				)}
				<Box marginTop={1}>
					<Button id="submit" label={t('common.create')} onPress={submit} />
					<Box marginLeft={2}>
						<Button id="cancel" label={t('common.cancel')} onPress={onCancel} />
					</Box>
				</Box>
				<Box marginTop={1}>
					<Text color="gray">{t('context.tabsHint')}</Text>
				</Box>
			</Box>
		</Box>
	);
}
