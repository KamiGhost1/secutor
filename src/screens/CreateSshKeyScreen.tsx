import React, {useState} from 'react';
import {Box, Text, useFocus, useInput} from 'ink';
import Spinner from 'ink-spinner';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {TextField, PasswordField} from '../components/TextField.js';
import {Button} from '../components/Button.js';
import {useArrowFocus} from '../components/Form.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {sshKeyRepo} from '../storage/repos.js';
import {generateSshKey, SshKeyAlgorithm} from '../ssh/sshKeys.js';

const ALGOS: SshKeyAlgorithm[] = [
	'ssh-ed25519',
	'ssh-ecdsa-p256',
	'ssh-ecdsa-p384',
	'ssh-rsa-2048',
	'ssh-rsa-3072',
	'ssh-rsa-4096',
];

const PRETTY: Record<SshKeyAlgorithm, string> = {
	'ssh-ed25519': 'Ed25519',
	'ssh-ecdsa-p256': 'ECDSA P-256',
	'ssh-ecdsa-p384': 'ECDSA P-384',
	'ssh-rsa-2048': 'RSA 2048',
	'ssh-rsa-3072': 'RSA 3072',
	'ssh-rsa-4096': 'RSA 4096',
};

function SshAlgoPicker({
	value,
	onChange,
}: {
	value: SshKeyAlgorithm;
	onChange: (a: SshKeyAlgorithm) => void;
}) {
	const {isFocused} = useFocus({id: 'ssh-algo'});
	const t = useT();

	useInput(
		(input, key) => {
			const cycle = (delta: 1 | -1) => {
				const idx = Math.max(0, ALGOS.indexOf(value));
				const next = (idx + delta + ALGOS.length) % ALGOS.length;
				onChange(ALGOS[next]!);
			};
			if (key.ctrl && (input === 'k' || input === 'K')) cycle(1);
			else if (key.leftArrow) cycle(-1);
			else if (key.rightArrow) cycle(1);
		},
		{isActive: isFocused},
	);

	return (
		<Box flexDirection="row">
			<Box width={20} flexShrink={0}>
				<Text color={isFocused ? 'cyan' : 'gray'}>
					{isFocused ? '› ' : '  '}{t('ssh.algorithm')}
				</Text>
			</Box>
			<Box borderStyle={isFocused ? 'bold' : 'single'} borderColor={isFocused ? 'cyan' : 'gray'} paddingX={1} width={40}>
				<Text>
					{PRETTY[value]}
					<Text color="gray">  ·  Ctrl+K / ←/→</Text>
				</Text>
			</Box>
		</Box>
	);
}

export function CreateSshKeyScreen() {
	useArrowFocus();
	const {pop, replace, showToast} = useApp();
	const t = useT();
	const [name, setName] = useState('');
	const [comment, setComment] = useState('');
	const [algorithm, setAlgorithm] = useState<SshKeyAlgorithm>('ssh-ed25519');
	const [pw, setPw] = useState('');
	const [pwRepeat, setPwRepeat] = useState('');
	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);

	useInput((_input, key) => {
		if (key.escape && !busy) pop();
	});

	const submit = async () => {
		setError(null);
		if (!name.trim()) return setError(t('ssh.errName'));
		if (sshKeyRepo.findByName(name.trim())) return setError(t('ssh.errNameTaken'));
		if (pw && pw !== pwRepeat) return setError(t('createCa.errKeyPwMismatch'));
		if (pw && pw.length < 4) return setError(t('createCa.errKeyPwShort'));

		setBusy(true);
		setTimeout(() => {
			try {
				const k = generateSshKey({
					algorithm,
					comment: comment.trim() || undefined,
					passphrase: pw || null,
				});
				const id = sshKeyRepo.insert({
					name: name.trim(),
					algorithm: k.algorithm,
					comment: comment.trim() || null,
					public_key: k.publicKeyOpenssh,
					private_key: k.privateKeyPem,
					encrypted: pw ? 1 : 0,
					fingerprint: k.fingerprintSha256,
				});
				showToast({kind: 'success', message: t('ssh.created', {name: name.trim()})});
				replace({kind: 'ssh-key-details', id});
			} catch (e: any) {
				setError(e.message);
				setBusy(false);
			}
		}, 10);
	};

	if (busy) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('ssh.createTitle')} />
				<Box padding={2}>
					<Spinner type="dots" />
					<Text> {t('ssh.busy')}</Text>
				</Box>
			</Box>
		);
	}

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('ssh.createTitle')} />
			<Box padding={1} flexDirection="column">
				<TextField id="name" label={t('ssh.name')} value={name} onChange={setName} autoFocus placeholder="id_secutor" />
				<SshAlgoPicker value={algorithm} onChange={setAlgorithm} />
				<TextField id="comment" label={t('ssh.comment')} value={comment} onChange={setComment} placeholder="user@host" />
				<Box marginTop={1}>
					<Text color="gray">{t('createCa.passphraseSection')}</Text>
				</Box>
				<PasswordField id="pw" label={t('ssh.passphrase')} value={pw} onChange={setPw} placeholder={t('ssh.passphraseHint')} />
				<PasswordField id="pwRepeat" label={t('ssh.passphraseRepeat')} value={pwRepeat} onChange={setPwRepeat} />
				{error && (
					<Box marginTop={1}>
						<Text color="red">⚠ {error}</Text>
					</Box>
				)}
				<Box marginTop={1}>
					<Button id="submit" label={t('common.create')} onPress={submit} />
					<Box marginLeft={2}>
						<Button id="cancel" label={t('common.cancel')} onPress={pop} />
					</Box>
				</Box>
			</Box>
			<FunctionBar
				keys={[
					{key: 'Tab', label: t('fbar.fields')},
					{key: 'Ctrl+K', label: t('fbar.algorithm')},
					{key: 'Enter', label: t('fbar.submit')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}
