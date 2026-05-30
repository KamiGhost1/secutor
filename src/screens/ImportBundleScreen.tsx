import React, {useState} from 'react';
import fs from 'fs';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {FileExplorer} from '../components/FileExplorer.js';
import {PasswordField} from '../components/TextField.js';
import {Button} from '../components/Button.js';
import {Confirm} from '../components/Confirm.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {
	parseBundle,
	isBundleFile,
	bundleVariant,
	ParsedBundle,
} from '../transfer/keyBundle.js';
import {importBundle, ImportSummary} from '../transfer/repoBridge.js';

type Step =
	| {kind: 'pick-file'}
	| {kind: 'password'; fileBuf: Buffer}
	| {kind: 'preview'; parsed: ParsedBundle}
	| {kind: 'confirm'; parsed: ParsedBundle}
	| {kind: 'done'; summary: ImportSummary};

export function ImportBundleScreen() {
	const {pop, contextName, showToast} = useApp();
	const t = useT();
	const [step, setStep] = useState<Step>({kind: 'pick-file'});
	const [password, setPassword] = useState('');

	useInput((_, key) => {
		if (key.escape && step.kind === 'done') pop();
	});

	if (step.kind === 'pick-file') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('importBundle.title')} />
				<Box padding={1}>
					<Text color="gray">{t('importBundle.pickFile')}</Text>
				</Box>
				<Box flexGrow={1} paddingX={1}>
					<FileExplorer
						mode="open"
						title={t('importBundle.pickFile')}
						onCancel={pop}
						onSelect={p => {
							try {
								const buf = fs.readFileSync(p);
								if (!isBundleFile(buf)) {
									showToast({kind: 'error', message: t('importBundle.notBundle')});
									return;
								}
								if (bundleVariant(buf) === 'encrypted') {
									setStep({kind: 'password', fileBuf: buf});
								} else {
									const parsed = parseBundle(buf);
									setStep({kind: 'preview', parsed});
								}
							} catch (e: any) {
								showToast({kind: 'error', message: e?.message ?? String(e)});
							}
						}}
					/>
				</Box>
			</Box>
		);
	}

	if (step.kind === 'password') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('importBundle.passwordTitle')} />
				<Box padding={1} flexDirection="column">
					<Text color="gray">{t('importBundle.passwordHint')}</Text>
					<PasswordField
						label={t('importBundle.passwordLabel')}
						value={password}
						onChange={setPassword}
						autoFocus
						onSubmit={pw => {
							try {
								const parsed = parseBundle(step.fileBuf, pw);
								setStep({kind: 'preview', parsed});
							} catch (e: any) {
								showToast({kind: 'error', message: t('importBundle.wrongPassword')});
							}
						}}
					/>
				</Box>
				<FunctionBar
					keys={[
						{key: 'Esc', label: t('fbar.back')},
						{key: 'Enter', label: t('fbar.submit')},
					]}
				/>
			</Box>
		);
	}

	if (step.kind === 'preview') {
		const m = step.parsed.manifest;
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('importBundle.previewTitle')} />
				<Box padding={1} flexDirection="column">
					<Text>{t('importBundle.previewKind', {kind: m.kind})}</Text>
					<Text>{t('importBundle.previewName', {name: m.name})}</Text>
					<Text>{t('importBundle.previewItems', {count: String(m.items.length)})}</Text>
					{m.fingerprint && (
						<Text color="gray">
							{t('importBundle.previewFp', {fp: m.fingerprint.slice(0, 16) + '…'})}
						</Text>
					)}
					<Box marginTop={1}>
						<Button
							label={t('common.next')}
							onPress={() => setStep({kind: 'confirm', parsed: step.parsed})}
						/>
					</Box>
				</Box>
				<FunctionBar
					keys={[
						{key: 'Esc', label: t('fbar.back')},
						{key: 'Enter', label: t('fbar.submit')},
					]}
				/>
			</Box>
		);
	}

	if (step.kind === 'confirm') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('importBundle.title')} />
				<Box padding={1}>
					<Confirm
						message={t('importBundle.confirm', {ctx: contextName ?? '?'})}
						onCancel={() => setStep({kind: 'preview', parsed: step.parsed})}
						onConfirm={() => {
							try {
								const summary = importBundle(step.parsed);
								setStep({kind: 'done', summary});
							} catch (e: any) {
								showToast({
									kind: 'error',
									message: t('importBundle.failed', {msg: e?.message ?? String(e)}),
								});
							}
						}}
					/>
				</Box>
			</Box>
		);
	}

	// done
	const s = step.summary;
	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('importBundle.title')} />
			<Box padding={1} flexDirection="column">
				{s.inserted.map((r, i) => (
					<Text key={`i${i}`} color="green">
						{t('importBundle.summary.inserted', {kind: r.kind, name: r.name})}
					</Text>
				))}
				{s.updated.map((r, i) => (
					<Text key={`u${i}`} color="yellow">
						{t('importBundle.summary.updated', {kind: r.kind, name: r.name})}
					</Text>
				))}
				{s.duplicates.map((r, i) => (
					<Text key={`d${i}`} color="gray">
						{t('importBundle.summary.duplicates', {kind: r.kind, name: r.name})}
					</Text>
				))}
				{s.conflicts.map((c, i) => (
					<Text key={`c${i}`} color="cyan">
						{t('importBundle.summary.conflict', {reason: c.reason})}
					</Text>
				))}
				{s.issuerRelinks > 0 && (
					<Text color="magenta">
						{t('importBundle.summary.relinks', {n: String(s.issuerRelinks)})}
					</Text>
				)}
				{s.inserted.length === 0 &&
					s.updated.length === 0 &&
					s.duplicates.length === 0 && (
						<Text color="gray">{t('common.empty')}</Text>
					)}
			</Box>
			<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
		</Box>
	);
}
