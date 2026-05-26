import React, {useMemo, useState} from 'react';
import os from 'os';
import path from 'path';
import {Box, Text, useInput} from 'ink';
import Spinner from 'ink-spinner';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {PasswordField} from '../components/TextField.js';
import {Button} from '../components/Button.js';
import {FileExplorer} from '../components/FileExplorer.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {sshKeyRepo} from '../storage/repos.js';
import {exportToSshFolder, toOpenSshPrivateKey} from '../ssh/sshKeys.js';
import {decryptPrivateKey, isEncryptedKey} from '../certs/keys.js';

type Mode = 'view' | 'export-ssh' | 'export-folder' | 'busy';

export function SshKeyDetailsScreen({id}: {id: number}) {
	const {pop, showToast} = useApp();
	const t = useT();
	const row = useMemo(() => sshKeyRepo.findById(id), [id]);
	const [mode, setMode] = useState<Mode>('view');
	const [pw, setPw] = useState('');
	const [error, setError] = useState<string | null>(null);

	useInput((input, key) => {
		if (mode === 'busy') return;
		if (key.escape) return pop();
		if (mode === 'view') {
			if (input === 'e' || input === 'E') setMode('export-ssh');
			else if (input === 'x' || input === 'X') setMode('export-folder');
		}
	});

	if (!row) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('ssh.detailsTitle')} />
				<Box padding={1}>
					<Text color="red">{t('ssh.notFound')}</Text>
				</Box>
				<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	if (mode === 'export-ssh') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('ssh.exportToFolderTitle')} />
				<Box padding={1} flexDirection="column">
					<Text>{t('ssh.exportToFolderHint', {dir: path.join(os.homedir(), '.ssh', row.name)})}</Text>
					{row.encrypted ? (
						<Box flexDirection="column" marginTop={1}>
							<PasswordField id="pw" label={t('ssh.passphraseToDecrypt')} value={pw} onChange={setPw} autoFocus />
						</Box>
					) : null}
					{error && (
						<Box marginTop={1}>
							<Text color="red">⚠ {error}</Text>
						</Box>
					)}
					<Box marginTop={1}>
						<Button
							id="go"
							label={t('common.export')}
							onPress={() => {
								if (row.encrypted && !pw) {
									setError(t('ssh.errPassphraseRequired'));
									return;
								}
								setError(null);
								setMode('busy');
								setTimeout(() => {
									try {
										const out = exportToSshFolder({
											name: row.name,
											privateKeyPem: row.private_key,
											publicKeyOpenssh: row.public_key,
											passphrase: row.encrypted ? pw : null,
											comment: row.comment ?? '',
										});
										showToast({kind: 'success', message: t('ssh.exportedTo', {path: out.privateKeyPath})});
										setMode('view');
									} catch (e: any) {
										setError(e.message);
										setMode('export-ssh');
									}
								}, 10);
							}}
						/>
						<Box marginLeft={2}>
							<Button id="cancel" label={t('common.cancel')} onPress={() => setMode('view')} />
						</Box>
					</Box>
				</Box>
				<FunctionBar keys={[{key: 'Enter', label: t('common.export')}, {key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	if (mode === 'export-folder') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('ssh.savePrivateTitle')} />
				<Box padding={1} flexDirection="column">
					{row.encrypted && (
						<PasswordField id="pw" label={t('ssh.passphraseToDecrypt')} value={pw} onChange={setPw} autoFocus />
					)}
					{error && (
						<Box marginTop={1}>
							<Text color="red">⚠ {error}</Text>
						</Box>
					)}
					<Box marginTop={1}>
						<Text color="gray">{t('ssh.savePrivateHint')}</Text>
					</Box>
				</Box>
				<Box padding={1}>
					<FileExplorer
						mode="save"
						defaultFileName={row.name}
						onSelect={(out) => {
							setMode('busy');
							setTimeout(() => {
								try {
									const fs = require('fs') as typeof import('fs');
									const plain = isEncryptedKey(row.private_key)
										? decryptPrivateKey(row.private_key, pw || null)
										: row.private_key;
									const ossh = toOpenSshPrivateKey(plain, row.comment ?? '');
									fs.writeFileSync(out, ossh, {mode: 0o600});
									fs.writeFileSync(out + '.pub', row.public_key + '\n', {mode: 0o644});
									showToast({kind: 'success', message: t('ssh.exportedTo', {path: out})});
									setMode('view');
								} catch (e: any) {
									setError(e.message);
									setMode('export-folder');
								}
							}, 10);
						}}
						onCancel={() => setMode('view')}
					/>
				</Box>
			</Box>
		);
	}

	if (mode === 'busy') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('ssh.detailsTitle')} />
				<Box padding={2}>
					<Spinner type="dots" />
					<Text> {t('common.required')}</Text>
				</Box>
			</Box>
		);
	}

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('ssh.detailsTitle')} />
			<Box padding={1} flexDirection="column">
				<KV label={t('ssh.kv.name')} value={row.name} />
				<KV label={t('ssh.kv.algorithm')} value={row.algorithm} />
				<KV label={t('ssh.kv.comment')} value={row.comment || '—'} />
				<KV label={t('ssh.kv.fingerprint')} value={row.fingerprint} />
				<KV label={t('ssh.kv.encrypted')} value={row.encrypted ? t('common.yes') : t('common.no')} />
				<KV label={t('ssh.kv.created')} value={row.created_at.replace('T', ' ').slice(0, 19)} />
				<Box marginTop={1} flexDirection="column">
					<Text color="gray">{t('ssh.publicKey')}:</Text>
					<Text color="cyan" wrap="wrap">{row.public_key}</Text>
				</Box>
			</Box>
			<FunctionBar
				keys={[
					{key: 'E', label: t('ssh.fbarExportSsh')},
					{key: 'X', label: t('ssh.fbarExportFile')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}

function KV({label, value}: {label: string; value: string}) {
	return (
		<Box>
			<Box width={20}>
				<Text color="gray">{label}</Text>
			</Box>
			<Text>{value}</Text>
		</Box>
	);
}
