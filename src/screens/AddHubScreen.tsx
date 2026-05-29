import React, {useState} from 'react';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {TextField} from '../components/TextField.js';
import {Button} from '../components/Button.js';
import {Menu} from '../components/Menu.js';
import {Confirm} from '../components/Confirm.js';
import {useArrowFocus} from '../components/Form.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {addHub, HubClientAuth} from '../storage/hubStore.js';
import {probeServerFingerprint, HubError} from '../net/hubClient.js';
import {certRepo} from '../storage/repos.js';
import {listEntries as listKeystoreEntries} from '../storage/hubKeystore.js';

type Step =
	| {kind: 'url'}
	| {kind: 'source'}
	| {kind: 'pick-context-cert'}
	| {kind: 'pick-keystore'}
	| {kind: 'enter-files'}
	| {kind: 'probe'}
	| {kind: 'confirm-pin'; fingerprint: string};

export function AddHubScreen() {
	useArrowFocus();
	const {pop, showToast, contextName} = useApp();
	const t = useT();
	const [step, setStep] = useState<Step>({kind: 'url'});
	const [name, setName] = useState('');
	const [baseUrl, setBaseUrl] = useState('');
	const [auth, setAuth] = useState<HubClientAuth | null>(null);
	const [certPath, setCertPath] = useState('');
	const [keyPath, setKeyPath] = useState('');

	useInput((_, key) => {
		if (key.escape && step.kind === 'url') pop();
	});

	if (step.kind === 'url') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('addHub.title')} />
				<Box padding={1} flexDirection="column">
					<TextField label={t('addHub.nameLabel')} value={name} onChange={setName} autoFocus />
					<TextField label={t('addHub.urlLabel')} value={baseUrl} onChange={setBaseUrl} />
					<Box marginTop={1}>
						<Button
							label={t('common.next')}
							onPress={() => {
								if (!name.trim() || !baseUrl.trim()) {
									showToast({kind: 'error', message: t('addHub.errMissing')});
									return;
								}
								if (!/^https:\/\//i.test(baseUrl)) {
									showToast({kind: 'error', message: t('addHub.errHttpsOnly')});
									return;
								}
								setStep({kind: 'source'});
							}}
						/>
					</Box>
				</Box>
				<FunctionBar
					keys={[
						{key: 'Esc', label: t('fbar.back')},
						{key: '↑↓/Tab', label: t('fbar.fields')},
					]}
				/>
			</Box>
		);
	}

	if (step.kind === 'source') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('addHub.sourceTitle')} />
				<Box flexGrow={1} paddingX={1}>
					<Menu
						items={[
							{label: t('addHub.sourceContext'), value: 'context'},
							{label: t('addHub.sourceFile'), value: 'file'},
							{label: t('addHub.sourceKeystore'), value: 'keystore'},
						]}
						onSelect={v => {
							if (v === 'context') setStep({kind: 'pick-context-cert'});
							else if (v === 'file') setStep({kind: 'enter-files'});
							else setStep({kind: 'pick-keystore'});
						}}
						onCancel={() => setStep({kind: 'url'})}
					/>
				</Box>
			</Box>
		);
	}

	if (step.kind === 'pick-context-cert') {
		const clients = certRepo.list({type: 'client'});
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('addHub.pickContextCert')} />
				<Box flexGrow={1} paddingX={1}>
					<Menu
						emptyText={t('addHub.noClientCerts')}
						items={clients.map(c => ({
							label: c.name,
							value: c.name,
							hint: c.common_name,
						}))}
						onSelect={certName => {
							setAuth({kind: 'context', context: contextName ?? '', certName});
							setStep({kind: 'probe'});
							startProbe(baseUrl, fpHandler);
						}}
						onCancel={() => setStep({kind: 'source'})}
					/>
				</Box>
			</Box>
		);
	}

	if (step.kind === 'pick-keystore') {
		const entries = listKeystoreEntries();
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('addHub.pickKeystoreEntry')} />
				<Box flexGrow={1} paddingX={1}>
					<Menu
						emptyText={t('addHub.noKeystoreEntries')}
						items={entries.map(e => ({
							label: e.name,
							value: e.name,
							hint: `fp ${e.fingerprint.slice(0, 12)}…${e.encrypted ? ' · enc' : ''}`,
						}))}
						onSelect={n => {
							setAuth({kind: 'keystore', keystoreEntry: n});
							setStep({kind: 'probe'});
							startProbe(baseUrl, fpHandler);
						}}
						onCancel={() => setStep({kind: 'source'})}
					/>
				</Box>
			</Box>
		);
	}

	if (step.kind === 'enter-files') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('addHub.enterFiles')} />
				<Box padding={1} flexDirection="column">
					<TextField label={t('addHub.certPath')} value={certPath} onChange={setCertPath} autoFocus />
					<TextField label={t('addHub.keyPath')} value={keyPath} onChange={setKeyPath} />
					<Box marginTop={1}>
						<Button
							label={t('common.next')}
							onPress={() => {
								if (!certPath || !keyPath) {
									showToast({kind: 'error', message: t('addHub.errMissing')});
									return;
								}
								setAuth({kind: 'file', certPath, keyPath});
								setStep({kind: 'probe'});
								startProbe(baseUrl, fpHandler);
							}}
						/>
					</Box>
				</Box>
				<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	if (step.kind === 'probe') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('addHub.probing')} />
				<Box padding={1}>
					<Text color="cyan">{t('addHub.probing')}…</Text>
				</Box>
			</Box>
		);
	}

	// confirm-pin
	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('addHub.confirmPin')} />
			<Box padding={1} flexDirection="column">
				<Text>{t('addHub.serverFp')}</Text>
				<Text color="cyan">{step.fingerprint}</Text>
				<Box marginTop={1}>
					<Confirm
						message={t('addHub.trustQuestion', {host: baseUrl})}
						onCancel={() => setStep({kind: 'source'})}
						onConfirm={() => {
							try {
								addHub({
									name: name.trim(),
									baseUrl: baseUrl.trim(),
									serverFingerprint: step.fingerprint,
									clientAuth: auth!,
								});
								showToast({kind: 'success', message: t('addHub.added', {name})});
								pop();
							} catch (e: any) {
								showToast({kind: 'error', message: e?.message ?? String(e)});
							}
						}}
					/>
				</Box>
			</Box>
		</Box>
	);

	function fpHandler(err: HubError | null, fp: string | null) {
		if (err) {
			showToast({kind: 'error', message: `${err.code}: ${err.message}`});
			setStep({kind: 'source'});
			return;
		}
		setStep({kind: 'confirm-pin', fingerprint: fp!});
	}
}

// Wraps probeServerFingerprint into a no-throw callback so the rendering
// flow stays linear with setStep.
function startProbe(baseUrl: string, cb: (err: HubError | null, fp: string | null) => void): void {
	probeServerFingerprint(baseUrl)
		.then(fp => cb(null, fp))
		.catch(err => cb(err instanceof HubError ? err : new HubError('probe-failed', String(err?.message ?? err)), null));
}

