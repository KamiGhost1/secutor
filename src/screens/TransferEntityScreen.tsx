import React, {useState} from 'react';
import fs from 'fs';
import {Box, Text, useFocus, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Menu} from '../components/Menu.js';
import {FileExplorer} from '../components/FileExplorer.js';
import {TextField, PasswordField} from '../components/TextField.js';
import {Button} from '../components/Button.js';
import {Confirm} from '../components/Confirm.js';
import {useArrowFocus} from '../components/Form.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {certRepo, sshKeyRepo, profileRepo} from '../storage/repos.js';
import {listContexts, getContextMeta, verifyContextPassword} from '../storage/contextStore.js';
import {openContext, closeContext, getCurrentSession} from '../storage/db.js';
import {
	exportCert,
	exportCertSubtree,
	exportSshKey,
	exportProfile,
	importBundle,
	ImportSummary,
} from '../transfer/repoBridge.js';
import {
	buildPlainBundle,
	buildEncryptedBundle,
	BundleManifest,
} from '../transfer/keyBundle.js';

export type TransferKind = 'cert' | 'ssh' | 'profile';

type Step =
	| {kind: 'menu'}
	| {kind: 'export-options'}
	| {kind: 'export-password'}
	| {kind: 'export-save'; password: string | null}
	| {kind: 'pick-target-ctx'}
	| {kind: 'unlock-target'; targetCtx: string}
	| {kind: 'transfer-rename'; targetCtx: string; targetPw: string | null}
	| {kind: 'transfer-confirm'; targetCtx: string; targetPw: string | null; rename: string}
	| {kind: 'transfer-busy'};

function entityName(kind: TransferKind, id: number): string {
	if (kind === 'cert') return certRepo.findById(id)?.name ?? '?';
	if (kind === 'ssh') return sshKeyRepo.findById(id)?.name ?? '?';
	return profileRepo.findById(id)?.name ?? '?';
}

function isCa(kind: TransferKind, id: number): boolean {
	if (kind !== 'cert') return false;
	return certRepo.findById(id)?.type === 'ca';
}

export function TransferEntityScreen({
	transferKind,
	id,
}: {
	transferKind: TransferKind;
	id: number;
}) {
	const {pop, showToast, contextName, setContextName} = useApp();
	const t = useT();
	const [step, setStep] = useState<Step>({kind: 'menu'});
	const [encrypt, setEncrypt] = useState(false);
	const [subtree, setSubtree] = useState(false);
	const [includeParents, setIncludeParents] = useState(true);
	const [bundlePw, setBundlePw] = useState('');
	const [bundlePwConfirm, setBundlePwConfirm] = useState('');
	const [targetPwInput, setTargetPwInput] = useState('');
	const [renameInput, setRenameInput] = useState('');
	useArrowFocus();

	const name = entityName(transferKind, id);
	const canSubtree = isCa(transferKind, id);

	function buildCurrent(opts: {includeParents: boolean; subtree: boolean}): {
		manifest: BundleManifest;
		payload: Buffer;
	} {
		if (transferKind === 'cert') {
			if (opts.subtree) return exportCertSubtree(id, {contextName: contextName ?? ''});
			return exportCert(id, {
				contextName: contextName ?? '',
				includeParents: opts.includeParents,
			});
		}
		if (transferKind === 'ssh') return exportSshKey(id, {contextName: contextName ?? ''});
		return exportProfile(id, {contextName: contextName ?? ''});
	}

	function summaryToString(s: ImportSummary): string {
		const parts: string[] = [];
		if (s.inserted.length) parts.push(`+${s.inserted.length}`);
		if (s.updated.length) parts.push(`~${s.updated.length}`);
		if (s.duplicates.length) parts.push(`=${s.duplicates.length}`);
		return parts.join(' ') || 'no-op';
	}

	useInput((_, key) => {
		if (step.kind === 'menu' && key.escape) pop();
	});

	/* ─── step: menu ─── */
	if (step.kind === 'menu') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('transfer.title', {name})} />
				<Box padding={1}>
					<Text color="gray">
						{t(`transfer.kind.${transferKind}` as any)} · {name}
					</Text>
				</Box>
				<Box flexGrow={1} paddingX={1}>
					<Menu
						title={t('transfer.menuTitle')}
						items={[
							{label: t('transfer.exportToFile'), value: 'file'},
							{label: t('transfer.sendToContext'), value: 'ctx'},
						]}
						onSelect={v => {
							if (v === 'file') setStep({kind: 'export-options'});
							else setStep({kind: 'pick-target-ctx'});
						}}
						onCancel={pop}
					/>
				</Box>
				<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	/* ─── step: export options ─── */
	if (step.kind === 'export-options') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('transfer.optionsTitle')} />
				<Box padding={1} flexDirection="column">
					<Toggle
						id="encrypt"
						label={t('transfer.optEncrypt')}
						value={encrypt}
						onChange={setEncrypt}
					/>
					{transferKind === 'cert' && canSubtree && (
						<Toggle
							id="subtree"
							label={t('transfer.optSubtree')}
							value={subtree}
							onChange={setSubtree}
						/>
					)}
					{transferKind === 'cert' && !canSubtree && (
						<Toggle
							id="parents"
							label={t('transfer.optIncludeParents')}
							value={includeParents}
							onChange={setIncludeParents}
						/>
					)}
					<Box marginTop={1}>
						<Button
							id="next"
							label={t('common.next')}
							onPress={() => {
								if (encrypt) setStep({kind: 'export-password'});
								else setStep({kind: 'export-save', password: null});
							}}
						/>
					</Box>
				</Box>
				<FunctionBar
					keys={[
						{key: 'Esc', label: t('fbar.back')},
						{key: '↑↓/Tab', label: t('fbar.fields')},
						{key: 'Enter', label: t('fbar.submit')},
					]}
				/>
			</Box>
		);
	}

	/* ─── step: export password (when --encrypt) ─── */
	if (step.kind === 'export-password') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('transfer.passwordLabel')} />
				<Box padding={1} flexDirection="column">
					<PasswordField
						id="pw1"
						label={t('transfer.passwordLabel')}
						value={bundlePw}
						onChange={setBundlePw}
						autoFocus
					/>
					<PasswordField
						id="pw2"
						label={t('transfer.passwordConfirm')}
						value={bundlePwConfirm}
						onChange={setBundlePwConfirm}
					/>
					<Box marginTop={1}>
						<Button
							id="next"
							label={t('common.next')}
							onPress={() => {
								if (!bundlePw) {
									showToast({kind: 'error', message: t('transfer.passwordLabel')});
									return;
								}
								if (bundlePw !== bundlePwConfirm) {
									showToast({kind: 'error', message: t('transfer.passwordMismatch')});
									return;
								}
								setStep({kind: 'export-save', password: bundlePw});
							}}
						/>
					</Box>
				</Box>
				<FunctionBar
					keys={[
						{key: 'Esc', label: t('fbar.back')},
						{key: '↑↓/Tab', label: t('fbar.fields')},
						{key: 'Enter', label: t('fbar.submit')},
					]}
				/>
			</Box>
		);
	}

	/* ─── step: file-explorer save ─── */
	if (step.kind === 'export-save') {
		const stamp = new Date().toISOString().slice(0, 10);
		const defName = `${name.replace(/[^a-zA-Z0-9._-]/g, '_')}-${stamp}.skb`;
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('transfer.saveTitle')} />
				<Box padding={1} flexDirection="column" flexGrow={1}>
					<FileExplorer
						mode="save"
						defaultFileName={defName}
						title={t('transfer.saveTitle')}
						onCancel={() => setStep({kind: 'menu'})}
						onSelect={target => {
							try {
								const built = buildCurrent({includeParents, subtree});
								const bytes = step.password
									? buildEncryptedBundle(built.manifest, built.payload, step.password)
									: buildPlainBundle(built.manifest, built.payload);
								fs.writeFileSync(target, bytes, {mode: 0o600});
								showToast({
									kind: 'success',
									message: t('transfer.exported', {path: target, bytes: String(bytes.length)}),
								});
								pop();
							} catch (e: any) {
								showToast({kind: 'error', message: e?.message ?? String(e)});
							}
						}}
					/>
				</Box>
			</Box>
		);
	}

	/* ─── step: pick target context ─── */
	if (step.kind === 'pick-target-ctx') {
		const others = listContexts().filter(c => c.name !== contextName);
		if (!others.length) {
			return (
				<Box flexDirection="column" flexGrow={1}>
					<Header title={t('transfer.pickTargetCtx')} />
					<Box padding={1}>
						<Text color="yellow">{t('transfer.noOtherCtx')}</Text>
					</Box>
					<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
				</Box>
			);
		}
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('transfer.pickTargetCtx')} />
				<Box flexGrow={1} paddingX={1}>
					<Menu
						items={others.map(c => ({
							label: c.encrypted ? `🔒 ${c.name}` : c.name,
							value: c.name,
						}))}
						onSelect={ctx => {
							const meta = getContextMeta(ctx);
							if (meta?.encrypted) {
								setStep({kind: 'unlock-target', targetCtx: ctx});
							} else {
								setStep({kind: 'transfer-rename', targetCtx: ctx, targetPw: null});
							}
						}}
						onCancel={() => setStep({kind: 'menu'})}
					/>
				</Box>
			</Box>
		);
	}

	/* ─── step: unlock target context ─── */
	if (step.kind === 'unlock-target') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('transfer.targetCtxLocked')} />
				<Box padding={1} flexDirection="column">
					<Text color="gray">{step.targetCtx}</Text>
					<PasswordField
						label={t('transfer.passwordLabel')}
						value={targetPwInput}
						onChange={setTargetPwInput}
						autoFocus
						onSubmit={pw => {
							if (!verifyContextPassword(step.targetCtx, pw)) {
								showToast({kind: 'error', message: t('importBundle.wrongPassword')});
								return;
							}
							setStep({kind: 'transfer-rename', targetCtx: step.targetCtx, targetPw: pw});
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

	/* ─── step: optional rename ─── */
	if (step.kind === 'transfer-rename') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('transfer.renameLabel')} />
				<Box padding={1} flexDirection="column">
					<TextField
						id="rename"
						label={t('transfer.renameLabel')}
						value={renameInput}
						onChange={setRenameInput}
						placeholder={name}
						autoFocus
					/>
					<Box marginTop={1}>
						<Button
							id="next"
							label={t('common.next')}
							onPress={() =>
								setStep({
									kind: 'transfer-confirm',
									targetCtx: step.targetCtx,
									targetPw: step.targetPw,
									rename: renameInput,
								})
							}
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

	/* ─── step: confirm + run ─── */
	if (step.kind === 'transfer-confirm') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('transfer.title', {name})} />
				<Box padding={1}>
					<Confirm
						message={t('transfer.confirmSend', {name, ctx: step.targetCtx})}
						onCancel={() => setStep({kind: 'menu'})}
						onConfirm={() => {
							setStep({kind: 'transfer-busy'});
							// Build bundle from the current context, then close+open target,
							// import, close, re-open original. Original password is kept in
							// the session record so we can re-open silently.
							const session = getCurrentSession();
							const originalCtx = session?.contextName ?? contextName!;
							const originalPw = session?.password ?? null;
							let built: {manifest: BundleManifest; payload: Buffer};
							try {
								built = buildCurrent({includeParents, subtree});
							} catch (e: any) {
								showToast({kind: 'error', message: e?.message ?? String(e)});
								pop();
								return;
							}
							let summary: ImportSummary | null = null;
							try {
								closeContext();
								openContext(step.targetCtx, step.targetPw);
								summary = importBundle(
									{manifest: built.manifest, payload: built.payload, encrypted: false},
									{rename: step.rename || undefined},
								);
								closeContext();
								openContext(originalCtx, originalPw);
								setContextName(originalCtx);
								showToast({
									kind: 'success',
									message: t('transfer.sendOk', {
										ctx: step.targetCtx,
										summary: summaryToString(summary),
									}),
								});
								pop();
							} catch (e: any) {
								// Best-effort: try to recover the original context so the
								// user isn't left without one.
								try {
									closeContext();
								} catch {}
								try {
									openContext(originalCtx, originalPw);
									setContextName(originalCtx);
								} catch {}
								showToast({
									kind: 'error',
									message: t('transfer.sendErr', {msg: e?.message ?? String(e)}),
								});
								pop();
							}
						}}
					/>
				</Box>
			</Box>
		);
	}

	if (step.kind === 'transfer-busy') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('transfer.busySending')} />
				<Box padding={1}>
					<Text color="cyan">{t('transfer.busySending')}</Text>
				</Box>
			</Box>
		);
	}

	return null;
}

function Toggle({
	id,
	label,
	value,
	onChange,
}: {
	id: string;
	label: string;
	value: boolean;
	onChange: (b: boolean) => void;
}) {
	const {isFocused} = useFocus({id});
	useInput(
		(input, key) => {
			if (!isFocused) return;
			if (input === ' ' || key.return) onChange(!value);
			if (input === 'y' || input === 'Y') onChange(true);
			if (input === 'n' || input === 'N') onChange(false);
		},
		{isActive: isFocused},
	);
	return (
		<Box marginBottom={0}>
			<Text color={isFocused ? 'cyan' : 'gray'}>
				{isFocused ? '› ' : '  '}[{value ? 'x' : ' '}] {label}
			</Text>
		</Box>
	);
}
