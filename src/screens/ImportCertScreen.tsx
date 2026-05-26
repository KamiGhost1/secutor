import React, {useEffect, useMemo, useState} from 'react';
import path from 'path';
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
import {certRepo, CertType} from '../storage/repos.js';
import {
	detectFormat,
	parsePem,
	parsePkcs12,
	saveImport,
	ImportResult,
} from '../certs/importer.js';

type Step =
	| {kind: 'pick-cert-file'}
	| {kind: 'pkcs12-password'; filePath: string}
	| {kind: 'pick-key-file'; result: ImportResult; certDir: string}
	| {kind: 'configure'; result: ImportResult; extraKeyPem: string | null}
	| {kind: 'busy'};

export function ImportCertScreen() {
	const {pop, replace, showToast} = useApp();
	const t = useT();
	const [step, setStep] = useState<Step>({kind: 'pick-cert-file'});

	if (step.kind === 'pick-cert-file') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('importCert.pickFileTitle')} />
				<Box padding={1} flexDirection="column" flexGrow={1}>
					<Text color="gray">{t('importCert.pickFileHint')}</Text>
					<Box flexGrow={1}>
						<FileExplorer
							mode="open"
							title={t('importCert.fileTitle')}
							onSelect={(p) => {
								try {
									const buf = fs.readFileSync(p);
									const fmt = detectFormat(buf);
									if (fmt === 'pem') {
										const r = parsePem(buf.toString('utf8'));
										if (r.certs.length === 0 && r.key) {
											showToast({kind: 'error', message: t('importCert.onlyKey')});
											return;
										}
										if (r.key) {
											setStep({kind: 'configure', result: r, extraKeyPem: null});
										} else {
											setStep({kind: 'pick-key-file', result: r, certDir: path.dirname(p)});
										}
									} else {
										setStep({kind: 'pkcs12-password', filePath: p});
									}
								} catch (e: any) {
									showToast({kind: 'error', message: e.message});
								}
							}}
							onCancel={pop}
						/>
					</Box>
				</Box>
			</Box>
		);
	}

	if (step.kind === 'pkcs12-password') {
		return (
			<Pkcs12PasswordForm
				filePath={step.filePath}
				onCancel={pop}
				onParsed={(result) => setStep({kind: 'configure', result, extraKeyPem: null})}
			/>
		);
	}

	if (step.kind === 'pick-key-file') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('importCert.keyTitle')} />
				<Box padding={1} flexDirection="column">
					<Text color="gray">{t('importCert.keyHint')}</Text>
				</Box>
				<Box padding={1} flexDirection="column" flexGrow={1}>
					<FileExplorer
						mode="open"
						startDir={step.certDir}
						title={t('importCert.keyPickTitle')}
						onSelect={(p) => {
							try {
								const text = fs.readFileSync(p, 'utf8');
								const m = text.match(
									/-----BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (RSA |EC |ENCRYPTED )?PRIVATE KEY-----/,
								);
								if (!m) {
									showToast({kind: 'error', message: t('importCert.keyNotFound')});
									return;
								}
								setStep({kind: 'configure', result: step.result, extraKeyPem: m[0]});
							} catch (e: any) {
								showToast({kind: 'error', message: e.message});
							}
						}}
						onCancel={() => setStep({kind: 'configure', result: step.result, extraKeyPem: null})}
					/>
				</Box>
			</Box>
		);
	}

	if (step.kind === 'configure') {
		return (
			<ConfigureForm
				result={step.result}
				extraKeyPem={step.extraKeyPem}
				onCancel={pop}
				onSaved={(leafId) => {
					showToast({kind: 'success', message: t('importCert.imported')});
					replace({kind: 'cert-details', id: leafId});
				}}
			/>
		);
	}

	return null;
}

function Pkcs12PasswordForm({
	filePath,
	onCancel,
	onParsed,
}: {
	filePath: string;
	onCancel: () => void;
	onParsed: (r: ImportResult) => void;
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
			onParsed(r);
		} catch (e: any) {
			setError(e.message || t('importCert.pkcs12.cantDecrypt'));
		}
	};

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('importCert.pkcs12.title')} />
			<Box padding={1} flexDirection="column">
				<Text color="gray">{filePath}</Text>
				<Box marginTop={1} />
				<PasswordField id="pass" label={t('importCert.pkcs12.password')} value={pass} onChange={setPass} onSubmit={submit} autoFocus />
				{error && (
					<Box marginTop={1}>
						<Text color="red">⚠ {error}</Text>
					</Box>
				)}
				<Box marginTop={1}>
					<Button id="ok" label={t('importCert.pkcs12.cta')} onPress={submit} />
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

function ConfigureForm({
	result,
	extraKeyPem,
	onCancel,
	onSaved,
}: {
	result: ImportResult;
	extraKeyPem: string | null;
	onCancel: () => void;
	onSaved: (leafId: number) => void;
}) {
	useArrowFocus();
	const t = useT();
	const leaf = result.certs[0];
	const cas = useMemo(() => certRepo.list({type: 'ca'}), []);

	const [name, setName] = useState(
		(leaf.parsed.subject.commonName || 'imported').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 40),
	);
	const [type, setType] = useState<CertType>(leaf.suggestedType);
	const [chainAsCAs, setChainAsCAs] = useState(result.certs.length > 1);
	// The issuer picker selects the DB parent of the *topmost* cert in the file
	// when chainAsCAs is on (since we'll insert the whole chain), otherwise
	// it's the parent of the leaf (since we're only saving the leaf).
	const topMostInChain =
		chainAsCAs && result.certs.length > 1
			? result.certs[result.certs.length - 1]
			: leaf;
	const isSelfSigned =
		JSON.stringify(topMostInChain.parsed.subject) ===
		JSON.stringify(topMostInChain.parsed.issuer);
	const [issuerId, setIssuerId] = useState<number | null>(() => {
		if (isSelfSigned) return null;
		const issuerCN = topMostInChain.parsed.issuer.commonName;
		const found = cas.find(c => c.common_name === issuerCN);
		return found?.id ?? null;
	});

	useEffect(() => {
		if (isSelfSigned) {
			setIssuerId(null);
			return;
		}
		const issuerCN = topMostInChain.parsed.issuer.commonName;
		const found = cas.find(c => c.common_name === issuerCN);
		setIssuerId(prev => (prev !== null ? prev : found?.id ?? null));
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [chainAsCAs]);
	const [error, setError] = useState<string | null>(null);

	useInput((input, key) => {
		if (key.escape) onCancel();
		if (input === 't' && key.ctrl) {
			setType(c => (c === 'ca' ? 'server' : c === 'server' ? 'client' : 'ca'));
		}
		if (input === 'b' && key.ctrl) {
			if (result.certs.length > 1) setChainAsCAs(v => !v);
		}
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
		if (!name.trim()) return setError(t('importCert.errName'));
		if (certRepo.findByName(name.trim())) return setError(t('importCert.errNameTaken'));
		try {
			const r = saveImport(result, {
				leafName: name.trim(),
				leafType: type,
				leafKeyPem: extraKeyPem,
				chainAsCAs,
				issuerCertId: issuerId,
			});
			onSaved(r.leafId);
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
			<Header title={t('importCert.cfgTitle')} />
			<Box padding={1} flexDirection="column">
				<Text color="gray">{t('importCert.source', {fmt: result.source.toUpperCase(), n: result.certs.length})}</Text>
				<Text color="gray">{t('importCert.foundKey', {state: result.key || extraKeyPem ? t('common.yes') : t('common.no')})}</Text>
				<Box marginTop={1} flexDirection="column" borderStyle="round" borderColor="gray" paddingX={1}>
					<Text bold>{t('importCert.leaf')}</Text>
					<Text>{t('importCert.cn', {cn: leaf.parsed.subject.commonName || '—'})}</Text>
					<Text>{t('importCert.issuer', {cn: leaf.parsed.issuer.commonName || '—'})}</Text>
					<Text>{t('importCert.validUntil', {from: leaf.parsed.notBefore.toISOString().slice(0,10), to: leaf.parsed.notAfter.toISOString().slice(0,10)})}</Text>
					{leaf.parsed.sans.length > 0 && <Text>{t('importCert.san', {sans: leaf.parsed.sans.join(', ')})}</Text>}
					<Text>{t('importCert.fingerprint', {fp: fingerprintShort(leaf.fingerprint)})}</Text>
				</Box>
				<Box marginTop={1} />
				<TextField id="name" label={t('importCert.dbName')} value={name} onChange={setName} autoFocus />
				<Box>
					<Text color="cyan">{t('importCert.typeToggle')}</Text>
					<Text bold>{type.toUpperCase()}</Text>
					<Text color="gray"> {t('importCert.typeHelp')}</Text>
				</Box>
				{result.certs.length > 1 && (
					<Box>
						<Text color={chainAsCAs ? 'green' : 'gray'}>
							{t('importCert.chainToggle', {n: result.certs.length - 1, state: chainAsCAs ? '✔' : '✘'})}
						</Text>
					</Box>
				)}
				{!isSelfSigned && (
					<Box>
						<Text color="cyan">{t('importCert.issuerToggle')}</Text>
						<Text bold>{issuerLabel}</Text>
					</Box>
				)}
				{isSelfSigned && type === 'ca' && (
					<Box>
						<Text color="gray">{t('importCert.selfSignedHint')}</Text>
					</Box>
				)}
				{error && (
					<Box marginTop={1}>
						<Text color="red">⚠ {error}</Text>
					</Box>
				)}
				<Box marginTop={1}>
					<Button id="ok" label={t('importCert.cta')} onPress={submit} />
					<Box marginLeft={2}>
						<Button id="cancel" label={t('common.cancel')} onPress={onCancel} />
					</Box>
				</Box>
			</Box>
			<FunctionBar
				keys={[
					{key: '↑/↓', label: t('fbar.fields')},
					{key: 'Ctrl+T', label: t('fbar.type')},
					{key: 'Ctrl+B', label: t('fbar.chain')},
					{key: 'Ctrl+P', label: t('fbar.issuer')},
					{key: 'Enter', label: t('common.save')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}

function fingerprintShort(fp: string): string {
	return fp.slice(0, 16) + '…' + fp.slice(-8);
}
