import React, {useEffect, useState} from 'react';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Menu} from '../components/Menu.js';
import {Confirm} from '../components/Confirm.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {listHubs, removeHub, touchLastSeen, Hub} from '../storage/hubStore.js';
import {resolveIdentity, EncryptedKeyError} from '../net/clientIdentity.js';
import {makeHubClient, HubError} from '../net/hubClient.js';
import {rememberIdentity} from '../net/sessionCache.js';
import {PasswordField} from '../components/TextField.js';

export function HubsScreen() {
	const {pop, push, showToast} = useApp();
	const t = useT();
	const [hubs, setHubs] = useState<Hub[]>([]);
	const [deleting, setDeleting] = useState<Hub | null>(null);
	const [keyPwFor, setKeyPwFor] = useState<Hub | null>(null);
	const [keyPwInput, setKeyPwInput] = useState('');

	useEffect(() => {
		setHubs(listHubs());
	}, []);

	// Esc is owned by the Menu below (onCancel={pop}); duplicating it here
	// causes a double pop on the Hubs screen → user falls past the Contexts
	// screen.
	useInput((input, _key) => {
		if (deleting || keyPwFor) return;
		if (input === 'a' || input === 'A') push({kind: 'add-hub'});
	});

	function connect(hub: Hub, password?: string) {
		let id;
		try {
			id = resolveIdentity(hub.clientAuth, {keyPassword: password ?? null});
		} catch (err: any) {
			if (err instanceof EncryptedKeyError) {
				setKeyPwFor(hub);
				return;
			}
			showToast({kind: 'error', message: err?.message ?? String(err)});
			return;
		}
		const client = makeHubClient(hub, id);
		client
			.request({method: 'GET', path: '/admin/v1/info'})
			.then(r => {
				if (r.status >= 400) {
					showToast({kind: 'error', message: `Hub returned ${r.status}: ${JSON.stringify(r.body)}`});
					return;
				}
				touchLastSeen(hub.id);
				rememberIdentity(hub.id, id);
				push({kind: 'remote-hub', hubId: hub.id});
			})
			.catch(err => {
				if (err instanceof HubError) {
					showToast({kind: 'error', message: `${err.code}: ${err.message}`});
				} else {
					showToast({kind: 'error', message: String(err?.message ?? err)});
				}
			})
			.finally(() => client.close());
	}

	if (deleting) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('hubs.title')} />
				<Box padding={1}>
					<Confirm
						message={t('hubs.confirmDelete', {name: deleting.name})}
						onCancel={() => setDeleting(null)}
						onConfirm={() => {
							removeHub(deleting.id);
							setHubs(listHubs());
							setDeleting(null);
							showToast({kind: 'success', message: t('hubs.deleted', {name: deleting.name})});
						}}
					/>
				</Box>
			</Box>
		);
	}

	if (keyPwFor) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('hubs.keyPwTitle', {name: keyPwFor.name})} />
				<Box padding={1} flexDirection="column">
					<Text color="gray">{t('hubs.keyPwHint')}</Text>
					<PasswordField
						label={t('hubs.keyPwLabel')}
						value={keyPwInput}
						onChange={setKeyPwInput}
						autoFocus
						onSubmit={pw => {
							const target = keyPwFor;
							setKeyPwFor(null);
							setKeyPwInput('');
							if (target) connect(target, pw);
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

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('hubs.title')} />
			<Box flexGrow={1} paddingX={1}>
				<Menu
					title={t('hubs.list')}
					emptyText={t('hubs.empty')}
					items={hubs.map(h => ({
						label: `🌐 ${h.name}`,
						value: h.id,
						hint: `${h.baseUrl} · fp ${h.serverFingerprint.slice(0, 12)}… · ${h.clientAuth.kind}`,
					}))}
					onSelect={id => {
						const hub = hubs.find(x => x.id === id);
						if (hub) connect(hub);
					}}
					onCancel={pop}
					onAction={(input, _k, item) => {
						if ((input === 'd' || input === 'D') && item) {
							const hub = hubs.find(x => x.id === item.value);
							if (hub) setDeleting(hub);
						}
					}}
				/>
			</Box>
			<FunctionBar
				keys={[
					{key: 'Enter', label: t('hubs.fbarConnect')},
					{key: 'A', label: t('hubs.fbarAdd')},
					{key: 'D', label: t('fbar.delete')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}
