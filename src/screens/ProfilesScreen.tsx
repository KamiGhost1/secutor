import React, {useMemo, useState} from 'react';
import {Box} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Menu} from '../components/Menu.js';
import {Confirm} from '../components/Confirm.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {profileRepo, certRepo} from '../storage/repos.js';

export function ProfilesScreen() {
	const {pop, push, showToast} = useApp();
	const t = useT();
	const [tick, setTick] = useState(0);
	const [del, setDel] = useState<number | null>(null);
	const rows = useMemo(() => profileRepo.list(), [tick]);

	if (del !== null) {
		const p = profileRepo.findById(del);
		return (
			<Box flexDirection="column">
				<Header title={t('profiles.title')} />
				<Box padding={1}>
					<Confirm
						message={t('profiles.confirmDelete', {name: p?.name || ''})}
						onConfirm={() => {
							profileRepo.delete(del);
							setDel(null);
							setTick(x => x + 1);
							showToast({kind: 'success', message: t('profiles.deleted')});
						}}
						onCancel={() => setDel(null)}
					/>
				</Box>
			</Box>
		);
	}

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('profiles.title')} />
			<Box padding={1} flexDirection="column" flexGrow={1}>
				<Menu
					searchable
					searchPlaceholder={t('search.placeholder')}
					emptyText={t('profiles.empty')}
					items={rows.map(p => {
						const c = certRepo.findById(p.cert_id);
						return {
							label: `📦 ${p.name}`,
							value: p.id,
							hint: `${p.format} · cert: ${c?.name || 'missing'} · ${p.created_at.slice(0, 10)}`,
						};
					})}
					onSelect={(id) => push({kind: 'export-profile', id})}
					onCancel={pop}
					onAction={(input, _key, item) => {
						if ((input === 'd' || input === 'D') && item) setDel(item.value as number);
						else if ((input === 't' || input === 'T') && item) {
							push({kind: 'transfer-entity', transferKind: 'profile', id: item.value as number});
						}
					}}
				/>
			</Box>
			<FunctionBar
				keys={[
					{key: 'Enter', label: t('fbar.export')},
					{key: 'T', label: t('fbar.transfer')},
					{key: '/', label: t('fbar.search')},
					{key: 'D', label: t('fbar.delete')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}
