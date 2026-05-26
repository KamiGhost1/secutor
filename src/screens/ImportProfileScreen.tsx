import React, {useMemo, useState} from 'react';
import fs from 'fs';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {FileExplorer} from '../components/FileExplorer.js';
import {TextField, PasswordField} from '../components/TextField.js';
import {Button} from '../components/Button.js';
import {useArrowFocus} from '../components/Form.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {certRepo, profileRepo} from '../storage/repos.js';
import {parsePkcs12, saveImport, ImportResult} from '../certs/importer.js';

type Step =
	| {kind: 'pick-file'}
	| {kind: 'password'; filePath: string}
	| {kind: 'preview'; filePath: string; password: string; result: ImportResult};

export function ImportProfileScreen() {
	const {pop, showToast} = useApp();
	const t = useT();
	const [step, setStep] = useState<Step>({kind: 'pick-file'});

	if (step.kind === 'pick-file') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('importProf.pickTitle')} />
				<Box padding={1} flexDirection="column" flexGrow={1}>
					<FileExplorer
						mode="open"
						title={t('importProf.pickHint')}
						onSelect={(p) => setStep({kind: 'password', filePath: p})}
						onCancel={pop}
					/>
				</Box>
			</Box>
		);
	}

	if (step.kind === 'password') {
		return (
			<PasswordPrompt
				filePath={step.filePath}
				onCancel={pop}
				onParsed={(result, pass) =>
					setStep({kind: 'preview', filePath: step.filePath, password: pass, result})
				}
			/>
		);
	}

	return (
		<PreviewAndSave
			filePath={step.filePath}
			result={step.result}
			onCancel={pop}
			onSaved={() => {
				showToast({kind: 'success', message: t('importProf.imported')});
				pop();
			}}
		/>
	);
}

function PasswordPrompt({
	filePath,
	onCancel,
	onParsed,
}: {
	filePath: string;
	onCancel: () => void;
	onParsed: (r: ImportResult, password: string) => void;
}) {
	useArrowFocus();
	const t = useT();
	const [pass, setPass] = useState('');
	const [error, setError] = useState<string | null>(null);

	useInput((_input, key) => {
		if (key.escape) onCancel();
	});

	const submit = async () => {
		setError(null);
		try {
			const buf = fs.readFileSync(filePath);
			const r = await parsePkcs12(buf, pass);
			onParsed(r, pass);
		} catch (e: any) {
			setError(e.message || t('importCert.pkcs12.cantDecrypt'));
		}
	};

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('importProf.passTitle')} />
			<Box padding={1} flexDirection="column">
				<Text color="gray">{filePath}</Text>
				<Box marginTop={1} />
				<PasswordField id="pass" label={t('importProf.passLabel')} value={pass} onChange={setPass} onSubmit={submit} autoFocus />
				{error && (
					<Box marginTop={1}>
						<Text color="red">⚠ {error}</Text>
					</Box>
				)}
				<Box marginTop={1}>
					<Button id="ok" label={t('importProf.openCta')} onPress={submit} />
					<Box marginLeft={2}>
						<Button id="cancel" label={t('common.cancel')} onPress={onCancel} />
					</Box>
				</Box>
			</Box>
			<FunctionBar
				keys={[
					{key: 'Enter', label: t('fbar.decrypt')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}

function PreviewAndSave({
	filePath,
	result,
	onCancel,
	onSaved,
}: {
	filePath: string;
	result: ImportResult;
	onCancel: () => void;
	onSaved: (profileId: number) => void;
}) {
	useArrowFocus();
	const t = useT();
	const cas = useMemo(() => certRepo.list({type: 'ca'}), []);
	const leaf = result.certs[0];
	const [name, setName] = useState(
		(leaf?.parsed.subject.commonName || 'imported-profile')
			.replace(/[^a-zA-Z0-9._-]/g, '_')
			.slice(0, 40),
	);
	const [friendly, setFriendly] = useState(leaf?.parsed.subject.commonName || '');
	const [alsoImportCerts, setAlsoImportCerts] = useState(true);
	const [issuerId, setIssuerId] = useState<number | null>(() => {
		if (!leaf) return null;
		const found = cas.find(c => c.common_name === leaf.parsed.issuer.commonName);
		return found?.id ?? null;
	});
	const [error, setError] = useState<string | null>(null);

	useInput((input, key) => {
		if (key.escape) onCancel();
		if (input === 'a' && key.ctrl) setAlsoImportCerts(v => !v);
		if (input === 'p' && key.ctrl) {
			if (cas.length === 0) return;
			const order = cas.map(c => c.id);
			const i = issuerId === null ? -1 : order.indexOf(issuerId);
			const next = i + 1 >= order.length ? null : order[i + 1];
			setIssuerId(next);
		}
	});

	const submit = () => {
		setError(null);
		if (!name.trim()) return setError(t('importProf.errName'));
		if (profileRepo.list().some(p => p.name === name.trim()))
			return setError(t('importProf.errNameTaken'));
		if (!leaf) return setError(t('importProf.errNoLeaf'));
		try {
			let certId: number;
			const existing = certRepo.list().find(r => r.fingerprint === leaf.fingerprint);
			if (existing) {
				certId = existing.id;
			} else if (alsoImportCerts) {
				const r = saveImport(result, {
					leafName: name.trim() + '-cert',
					leafType: leaf.suggestedType,
					leafKeyPem: null,
					chainAsCAs: result.certs.length > 1,
					issuerCertId: issuerId,
				});
				certId = r.leafId;
			} else {
				return setError(t('importProf.errMissingCert'));
			}
			const data = fs.readFileSync(filePath);
			const profileId = profileRepo.insert({
				name: name.trim(),
				cert_id: certId,
				format: 'p12',
				friendly_name: friendly || null,
				data,
			});
			onSaved(profileId);
		} catch (e: any) {
			setError(e.message);
		}
	};

	const issuerLabel =
		issuerId === null
			? t('importCert.issuerNone')
			: cas.find(c => c.id === issuerId)?.name || '???';

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('importProf.cfgTitle')} />
			<Box padding={1} flexDirection="column">
				<Text color="gray">{t('importProf.certCount', {n: result.certs.length})}</Text>
				{leaf && (
					<Box marginTop={1} flexDirection="column" borderStyle="round" borderColor="gray" paddingX={1}>
						<Text bold>{t('importCert.leaf')}</Text>
						<Text>{t('importCert.cn', {cn: leaf.parsed.subject.commonName || '—'})}</Text>
						<Text>{t('importCert.issuer', {cn: leaf.parsed.issuer.commonName || '—'})}</Text>
						<Text>{t('importCert.validUntil', {from: leaf.parsed.notBefore.toISOString().slice(0,10), to: leaf.parsed.notAfter.toISOString().slice(0,10)})}</Text>
					</Box>
				)}
				<Box marginTop={1} />
				<TextField id="name" label={t('importProf.profileName')} value={name} onChange={setName} autoFocus />
				<TextField id="friendly" label={t('importProf.friendly')} value={friendly} onChange={setFriendly} />
				<Box>
					<Text color={alsoImportCerts ? 'green' : 'gray'}>
						{t('importProf.alsoImport', {state: alsoImportCerts ? '✔' : '✘'})}
					</Text>
				</Box>
				{alsoImportCerts && (
					<Box>
						<Text color="cyan">{t('importProf.issuer')}</Text>
						<Text bold>{issuerLabel}</Text>
					</Box>
				)}
				{error && (
					<Box marginTop={1}>
						<Text color="red">⚠ {error}</Text>
					</Box>
				)}
				<Box marginTop={1}>
					<Button id="ok" label={t('importProf.cta')} onPress={submit} />
					<Box marginLeft={2}>
						<Button id="cancel" label={t('common.cancel')} onPress={onCancel} />
					</Box>
				</Box>
			</Box>
			<FunctionBar
				keys={[
					{key: '↑/↓', label: t('fbar.fields')},
					{key: 'Ctrl+A', label: t('fbar.autoImport')},
					{key: 'Ctrl+P', label: t('fbar.issuer')},
					{key: 'Enter', label: t('common.save')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}
