import React, {useMemo, useState} from 'react';
import fs from 'fs';
import path from 'path';
import {Box, Text, useInput} from 'ink';
import Spinner from 'ink-spinner';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {PasswordField} from '../components/TextField.js';
import {Button} from '../components/Button.js';
import {Menu} from '../components/Menu.js';
import {FileExplorer} from '../components/FileExplorer.js';
import {useArrowFocus} from '../components/Form.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {certRepo} from '../storage/repos.js';
import {isEncryptedKey} from '../certs/keys.js';
import {
	signFile,
	writeDetachedSignature,
	buildSignatureBundle,
	manifestToJson,
} from '../certs/signing.js';

type Step = 'pick-cert' | 'pick-file' | 'configure' | 'pick-output' | 'busy' | 'done';
type Mode = 'detached' | 'bundle';

export function SignFileScreen() {
	useArrowFocus();
	const {pop, showToast} = useApp();
	const t = useT();
	const certs = useMemo(
		() => certRepo.list().filter(c => !!c.key_pem),
		[],
	);

	const [step, setStep] = useState<Step>('pick-cert');
	const [certId, setCertId] = useState<number | null>(null);
	const [filePath, setFilePath] = useState<string | null>(null);
	const [mode, setMode] = useState<Mode>('detached');
	const [keyPw, setKeyPw] = useState('');
	const [error, setError] = useState<string | null>(null);
	const [savedPath, setSavedPath] = useState<string | null>(null);

	// Steps `pick-cert`, `pick-file`, `pick-output` are owned by Menu /
	// FileExplorer which already handle Esc via their own `onCancel`. Step
	// `configure` is also owned by an inner Menu. The outer hook is therefore
	// only active for steps without an inner Esc handler (just `done`); this
	// prevents the previously-observed double-cancel on Esc.
	useInput(
		(_input, key) => {
			if (key.escape) pop();
		},
		{isActive: step === 'done'},
	);

	if (certs.length === 0) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('sign.title')} />
				<Box padding={1}>
					<Text color="yellow">{t('sign.noCerts')}</Text>
				</Box>
				<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	if (step === 'pick-cert') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('sign.title')} />
				<Box padding={1}>
					<Menu
						items={certs.map(c => ({
							label: `${typeIcon(c.type)} ${isEncryptedKey(c.key_pem) ? '🔐 ' : '🔑 '}${c.name}`,
							value: c.id,
							hint: `CN=${c.common_name}`,
						}))}
						onSelect={(id) => {
							setCertId(id);
							setStep('pick-file');
						}}
						onCancel={pop}
					/>
				</Box>
				<FunctionBar keys={[{key: 'Enter', label: t('fbar.pick')}, {key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	if (step === 'pick-file') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('sign.pickFileTitle')} />
				<Box padding={1}>
					<FileExplorer
						mode="open"
						onSelect={(p) => {
							setFilePath(p);
							setStep('configure');
						}}
						onCancel={() => setStep('pick-cert')}
					/>
				</Box>
			</Box>
		);
	}

	if (step === 'configure') {
		const cert = certs.find(c => c.id === certId)!;
		const encrypted = isEncryptedKey(cert.key_pem);
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('sign.configureTitle')} />
				<Box padding={1} flexDirection="column">
					<Text color="gray">{t('sign.signerLine', {name: cert.name, cn: cert.common_name})}</Text>
					<Text color="gray">{t('sign.fileLine', {path: filePath ?? ''})}</Text>

					<Box marginTop={1}>
						<Menu
							title={t('sign.modeTitle')}
							items={[
								{label: '📎 ' + t('sign.modeDetached'), value: 'detached' as Mode, hint: t('sign.modeDetachedHint')},
								{label: '📦 ' + t('sign.modeBundle'), value: 'bundle' as Mode, hint: t('sign.modeBundleHint')},
							]}
							onSelect={(m) => {
								setMode(m);
								if (encrypted) return; // ask password below before proceeding
								setStep('pick-output');
							}}
							onCancel={() => setStep('pick-file')}
						/>
					</Box>

					{encrypted && (
						<Box marginTop={1} flexDirection="column">
							<PasswordField id="keyPw" label={t('sign.keyPassword')} value={keyPw} onChange={setKeyPw} placeholder={t('sign.keyPasswordHint')} autoFocus />
							<Box marginTop={1}>
								<Button
									id="proceed"
									label={t('common.next')}
									onPress={() => {
										if (!keyPw) {
											setError(t('sign.errKeyPassword'));
											return;
										}
										setError(null);
										setStep('pick-output');
									}}
								/>
							</Box>
						</Box>
					)}

					{error && (
						<Box marginTop={1}>
							<Text color="red">⚠ {error}</Text>
						</Box>
					)}
				</Box>
				<FunctionBar keys={[{key: 'Enter', label: t('fbar.pick')}, {key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	if (step === 'pick-output') {
		const fileName = filePath ? path.basename(filePath) : '';
		const defaultName = mode === 'detached' ? `${fileName}.sig` : `${fileName}.secsig`;
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('sign.saveTitle')} />
				<Box padding={1}>
					<FileExplorer
						mode="save"
						defaultFileName={defaultName}
						startDir={filePath ? path.dirname(filePath) : undefined}
						onSelect={(out) => doSign(out)}
						onCancel={() => setStep('configure')}
					/>
				</Box>
			</Box>
		);
	}

	if (step === 'busy') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('sign.title')} />
				<Box padding={2}>
					<Spinner type="dots" />
					<Text> {t('sign.busy')}</Text>
				</Box>
			</Box>
		);
	}

	// done
	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('sign.title')} />
			<Box padding={1} flexDirection="column">
				<Text color="green">{t('sign.done')}</Text>
				{savedPath && (
					<Box marginTop={1}>
						<Text>{t('sign.savedPath', {path: savedPath})}</Text>
					</Box>
				)}
			</Box>
			<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
		</Box>
	);

	function doSign(outPath: string) {
		if (!certId || !filePath) return;
		const cert = certRepo.findById(certId);
		if (!cert) {
			setError(t('sign.errCertGone'));
			return;
		}
		setStep('busy');
		setTimeout(() => {
			try {
				const manifest = signFile(filePath, {
					privateKeyPem: cert.key_pem,
					keyPassword: keyPw || null,
					certPem: cert.cert_pem,
					commonName: cert.common_name,
				});
				if (mode === 'detached') {
					if (outPath.endsWith('.sig')) {
						// reuse writeDetachedSignature's <data>.sig convention when possible
						fs.writeFileSync(outPath, manifestToJson(manifest));
					} else {
						fs.writeFileSync(outPath, manifestToJson(manifest));
					}
					setSavedPath(outPath);
				} else {
					const data = fs.readFileSync(filePath);
					const bundle = buildSignatureBundle(data, manifest);
					fs.writeFileSync(outPath, bundle);
					setSavedPath(outPath);
				}
				showToast({kind: 'success', message: t('sign.done')});
				setStep('done');
			} catch (e: any) {
				setError(e.message);
				setStep('configure');
			}
		}, 10);
	}
}

function typeIcon(t: string): string {
	if (t === 'ca') return '🏛';
	if (t === 'server') return '🖥';
	return '👤';
}
