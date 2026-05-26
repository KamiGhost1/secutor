import React, {useState} from 'react';
import fs from 'fs';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {FileExplorer} from '../components/FileExplorer.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {
	manifestFromJson,
	parseSignatureBundle,
	verifyBuffer,
	VerifyResult,
} from '../certs/signing.js';

type Step =
	| 'pick-data'
	| 'pick-sig'
	| 'result';

const BUNDLE_MAGIC = Buffer.from('SECUTORSIG\x01', 'utf8');

function looksLikeBundle(buf: Buffer): boolean {
	return buf.length >= BUNDLE_MAGIC.length && buf.subarray(0, BUNDLE_MAGIC.length).equals(BUNDLE_MAGIC);
}

export function VerifySignatureScreen() {
	const {pop} = useApp();
	const t = useT();

	const [step, setStep] = useState<Step>('pick-data');
	const [dataPath, setDataPath] = useState<string | null>(null);
	const [sigPath, setSigPath] = useState<string | null>(null);
	const [result, setResult] = useState<VerifyResult | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [bundleMode, setBundleMode] = useState(false);

	// `pick-data` and `pick-sig` are owned by their FileExplorer's `onCancel`.
	// The outer hook is only active on the `result` step to avoid double-step
	// Esc behaviour.
	useInput(
		(_input, key) => {
			if (key.escape) pop();
		},
		{isActive: step === 'result'},
	);

	if (step === 'pick-data') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('verifySig.pickDataTitle')} />
				<Box padding={1}>
					<FileExplorer
						mode="open"
						onSelect={(p) => {
							setDataPath(p);
							// Auto-detect bundle: if the file *starts* with the magic, no
							// separate .sig is needed — go straight to verifying.
							let buf: Buffer | null = null;
							try {
								buf = fs.readFileSync(p);
							} catch (e: any) {
								setError(e.message);
								return;
							}
							if (looksLikeBundle(buf)) {
								setBundleMode(true);
								verifyBundle(buf);
							} else {
								setBundleMode(false);
								setStep('pick-sig');
							}
						}}
						onCancel={pop}
					/>
				</Box>
				<Box paddingX={1}>
					<Text color="gray">{t('verifySig.pickDataHint')}</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'pick-sig') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('verifySig.pickSigTitle')} />
				<Box padding={1}>
					<FileExplorer
						mode="open"
						startDir={dataPath ? require('path').dirname(dataPath) : undefined}
						onSelect={(p) => {
							setSigPath(p);
							verifyDetached(dataPath!, p);
						}}
						onCancel={() => setStep('pick-data')}
					/>
				</Box>
			</Box>
		);
	}

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('verifySig.resultTitle')} />
			<Box padding={1} flexDirection="column">
				{error && <Text color="red">⚠ {error}</Text>}
				{result && (
					<>
						{result.ok ? (
							<Box flexDirection="column">
								<Text color="green" bold>✔ {t('verifySig.ok')}</Text>
								<Text color="gray">{t('verifySig.algo', {algo: result.algorithm ?? ''})}</Text>
								{result.signer?.commonName && (
									<Text color="gray">{t('verifySig.signer', {cn: result.signer.commonName})}</Text>
								)}
								{result.signer?.fingerprint && (
									<Text color="gray">{t('verifySig.fingerprint', {fp: result.signer.fingerprint})}</Text>
								)}
							</Box>
						) : (
							<Box flexDirection="column">
								<Text color="red" bold>✘ {t('verifySig.bad')}</Text>
								<Text color="yellow">{result.reason}</Text>
							</Box>
						)}
					</>
				)}
				<Box marginTop={1}>
					<Text color="gray">{t('verifySig.dataPath', {path: dataPath ?? ''})}</Text>
				</Box>
				{!bundleMode && sigPath && (
					<Text color="gray">{t('verifySig.sigPath', {path: sigPath})}</Text>
				)}
				{bundleMode && (
					<Text color="gray">{t('verifySig.bundleNote')}</Text>
				)}
			</Box>
			<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
		</Box>
	);

	function verifyBundle(buf: Buffer) {
		try {
			const {manifest, data} = parseSignatureBundle(buf);
			const r = verifyBuffer(data, manifest);
			setResult(r);
			setError(null);
		} catch (e: any) {
			setError(e.message);
			setResult(null);
		}
		setStep('result');
	}

	function verifyDetached(data: string, sig: string) {
		try {
			const manifest = manifestFromJson(fs.readFileSync(sig, 'utf8'));
			const r = verifyBuffer(fs.readFileSync(data), manifest);
			setResult(r);
			setError(null);
		} catch (e: any) {
			setError(e.message);
			setResult(null);
		}
		setStep('result');
	}
}
