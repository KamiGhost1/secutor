import React, {useState, useCallback} from 'react';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Menu} from '../components/Menu.js';
import {Confirm} from '../components/Confirm.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {sshKeyRepo, SshKeyRow} from '../storage/repos.js';

export function SshKeysScreen() {
	const {push, pop, showToast} = useApp();
	const t = useT();
	const [rows, setRows] = useState<SshKeyRow[]>(() => sshKeyRepo.list());
	const [confirmDelete, setConfirmDelete] = useState<SshKeyRow | null>(null);

	const refresh = useCallback(() => setRows(sshKeyRepo.list()), []);

	useInput(
		(input, key) => {
			if (key.escape) return pop();
			if (input === 'n' || input === 'N') push({kind: 'create-ssh-key'});
		},
		{isActive: !confirmDelete},
	);

	if (confirmDelete) {
		return (
			<Confirm
				message={t('ssh.confirmDelete', {name: confirmDelete.name})}
				onConfirm={() => {
					sshKeyRepo.delete(confirmDelete.id);
					setConfirmDelete(null);
					refresh();
					showToast({kind: 'success', message: t('ssh.deleted')});
				}}
				onCancel={() => setConfirmDelete(null)}
			/>
		);
	}

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('ssh.title')} />
			<Box padding={1} flexDirection="column" flexGrow={1}>
				{rows.length === 0 ? (
					<Text color="gray">{t('ssh.empty')}</Text>
				) : (
					<Menu
						items={rows.map(r => ({
							label: `${algoEmoji(r.algorithm)} ${r.name}`,
							value: r.id,
							hint: `${r.algorithm} · ${r.fingerprint}${r.encrypted ? ' · 🔐' : ''}`,
						}))}
						onSelect={(id) => push({kind: 'ssh-key-details', id})}
						onAction={(input, _key, item) => {
							if (!item) return;
							const row = rows.find(r => r.id === item.value);
							if (!row) return;
							if (input === 'd' || input === 'D') setConfirmDelete(row);
							else if (input === 'e' || input === 'E') push({kind: 'ssh-key-details', id: row.id});
						}}
					/>
				)}
			</Box>
			<FunctionBar
				keys={[
					{key: 'N', label: t('ssh.fbarNew')},
					{key: 'Enter', label: t('fbar.openCmd')},
					{key: 'D', label: t('fbar.delete')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}

export function algoEmoji(algorithm: string): string {
	if (algorithm.startsWith('ssh-ed25519')) return '⚡';
	if (algorithm.startsWith('ssh-ecdsa')) return '🌀';
	if (algorithm.startsWith('ssh-rsa')) return '🔢';
	return '🔑';
}
