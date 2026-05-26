import React from 'react';
import {Box, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Menu} from '../components/Menu.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {useFunctionKey} from '../input/useFunctionKey.js';
import {closeContext} from '../storage/db.js';

type Action =
	| 'all'
	| 'ca'
	| 'server'
	| 'client'
	| 'profiles'
	| 'create-ca'
	| 'issue-intermediate-ca'
	| 'issue-server'
	| 'issue-client'
	| 'create-profile'
	| 'import-cert'
	| 'import-profile'
	| 'verify'
	| 'sni'
	| 'audit'
	| 'sign-file'
	| 'verify-signature'
	| 'ssh-keys'
	| 'export'
	| 'import'
	| 'set-password'
	| 'switch-context'
	| 'settings'
	| 'quit';

export function MainMenuScreen() {
	const {push, replace, setContextName, contextName, exit} = useApp();
	const t = useT();

	useFunctionKey('f10', () => exit(), []);

	const items = [
		{label: '📜  ' + t('main.allCerts'),       value: 'all' as Action},
		{label: '🏛  ' + t('main.cas'),             value: 'ca' as Action},
		{label: '🖥  ' + t('main.serverCerts'),     value: 'server' as Action},
		{label: '👤  ' + t('main.clientCerts'),     value: 'client' as Action},
		{label: '📦  ' + t('main.profiles'),        value: 'profiles' as Action},
		{label: '─────────────────────────',       value: 'sep' as any, disabled: true},
		{label: '➕  ' + t('main.createCa'),        value: 'create-ca' as Action},
		{label: '➕  ' + t('main.issueIntermediateCa'), value: 'issue-intermediate-ca' as Action},
		{label: '➕  ' + t('main.issueServer'),     value: 'issue-server' as Action},
		{label: '➕  ' + t('main.issueClient'),     value: 'issue-client' as Action},
		{label: '➕  ' + t('main.createProfile'),   value: 'create-profile' as Action},
		{label: '⤵   ' + t('main.importCert'),     value: 'import-cert' as Action},
		{label: '⤵   ' + t('main.importProfile'),  value: 'import-profile' as Action},
		{label: '─────────────────────────',       value: 'sep2' as any, disabled: true},
		{label: '🔍  ' + t('main.verify'),          value: 'verify' as Action},
		{label: '🌐  ' + t('main.sni'),             value: 'sni' as Action},
		{label: '🩺  ' + t('main.audit'),           value: 'audit' as Action},
		{label: '─────────────────────────',       value: 'sep3' as any, disabled: true},
		{label: '✍   ' + t('main.signFile'),       value: 'sign-file' as Action},
		{label: '🔎  ' + t('main.verifySignature'),value: 'verify-signature' as Action},
		{label: '🔑  ' + t('main.sshKeys'),         value: 'ssh-keys' as Action},
		{label: '─────────────────────────',       value: 'sep4' as any, disabled: true},
		{label: '⤴   ' + t('main.exportStore'),    value: 'export' as Action},
		{label: '⤵   ' + t('main.importStore'),    value: 'import' as Action},
		{label: '🔑  ' + t('main.setPassword'),     value: 'set-password' as Action},
		{label: '🔄  ' + t('main.switchContext'),   value: 'switch-context' as Action},
		{label: '⚙   ' + t('main.settings'),        value: 'settings' as Action},
		{label: '⏻   ' + t('main.quit'),            value: 'quit' as Action},
	];

	useInput((_input, key) => {
		if (key.escape) {
			closeContext();
			setContextName(null);
			replace({kind: 'contexts'});
		}
	});

	const handle = (a: Action) => {
		switch (a) {
			case 'all':           return push({kind: 'certificates'});
			case 'ca':            return push({kind: 'certificates', filter: 'ca'});
			case 'server':        return push({kind: 'certificates', filter: 'server'});
			case 'client':        return push({kind: 'certificates', filter: 'client'});
			case 'profiles':      return push({kind: 'profiles'});
			case 'create-ca':     return push({kind: 'create-ca'});
			case 'issue-intermediate-ca': return push({kind: 'issue-intermediate-ca'});
			case 'issue-server':  return push({kind: 'issue-cert', certType: 'server'});
			case 'issue-client':  return push({kind: 'issue-cert', certType: 'client'});
			case 'create-profile':return push({kind: 'create-profile'});
			case 'import-cert':   return push({kind: 'import-cert'});
			case 'import-profile':return push({kind: 'import-profile'});
			case 'verify':        return push({kind: 'verify'});
			case 'sni':           return push({kind: 'sni-search'});
			case 'audit':         return push({kind: 'audit'});
			case 'sign-file':     return push({kind: 'sign-file'});
			case 'verify-signature': return push({kind: 'verify-signature'});
			case 'ssh-keys':      return push({kind: 'ssh-keys'});
			case 'export':        return push({kind: 'export-context'});
			case 'import':        return push({kind: 'import-context'});
			case 'set-password':  return push({kind: 'set-password', name: contextName!});
			case 'settings':      return push({kind: 'settings'});
			case 'switch-context':
				closeContext();
				setContextName(null);
				return replace({kind: 'contexts'});
			case 'quit':          return exit();
		}
	};

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('main.title')} />
			<Box padding={1} flexDirection="column" flexGrow={1}>
				<Menu items={items as any} onSelect={(v) => handle(v as Action)} />
			</Box>
			<FunctionBar
				keys={[
					{key: 'Enter', label: t('fbar.openCmd')},
					{key: 'Esc', label: t('fbar.switchCtx')},
					{key: 'F10', label: t('fbar.quit')},
				]}
			/>
		</Box>
	);
}
