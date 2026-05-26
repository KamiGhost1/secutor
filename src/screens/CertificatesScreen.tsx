import React, {useState, useMemo} from 'react';
import {Box, Text} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Menu} from '../components/Menu.js';
import {Confirm} from '../components/Confirm.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {certRepo, CertType} from '../storage/repos.js';
import {expiryStatusOfRow, expiryColor, expiryIcon} from '../certs/expiry.js';

export function CertificatesScreen({filter}: {filter?: CertType}) {
	const {pop, push, showToast} = useApp();
	const t = useT();
	const [tick, setTick] = useState(0);
	const [pendingDelete, setPendingDelete] = useState<number | null>(null);

	const rows = useMemo(
		() => certRepo.list(filter ? {type: filter} : undefined),
		[filter, tick],
	);

	const title =
		filter === 'ca'
			? t('certs.title.ca')
			: filter === 'server'
			? t('certs.title.server')
			: filter === 'client'
			? t('certs.title.client')
			: t('certs.title.all');

	if (pendingDelete !== null) {
		const row = certRepo.findById(pendingDelete);
		return (
			<Box flexDirection="column">
				<Header title={title} />
				<Box padding={1}>
					<Confirm
						message={t('certs.confirmDelete', {name: row?.name || ''})}
						onConfirm={() => {
							certRepo.delete(pendingDelete);
							setPendingDelete(null);
							setTick(x => x + 1);
							showToast({kind: 'success', message: t('certs.deleted')});
						}}
						onCancel={() => setPendingDelete(null)}
					/>
				</Box>
			</Box>
		);
	}

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={title} />
			<Box padding={1} flexDirection="column" flexGrow={1}>
				<Menu
					searchable
					searchPlaceholder={t('search.placeholder')}
					emptyText={t('certs.empty')}
					items={rows.map(r => {
						const status = expiryStatusOfRow(r);
						return {
							label: `${expiryIcon(status)} ${typeIcon(r.type)} ${r.name}`,
							value: r.id,
							hint: `CN=${r.common_name}${
								r.san ? ` · SAN ${JSON.parse(r.san).join(',')}` : ''
							} · ${r.not_after.slice(0, 10)}`,
							status,
						};
					})}
					itemRenderer={(it: any, focused) => (
						<Box>
							<Text
								color={focused ? 'black' : expiryColor(it.status)}
								backgroundColor={focused ? 'cyan' : undefined}
								bold={focused}
							>
								{focused ? '▶ ' : '  '}
								{it.label}
								{it.hint ? `  · ${it.hint}` : ''}
							</Text>
						</Box>
					)}
					onSelect={(id) => push({kind: 'cert-details', id})}
					onCancel={pop}
					onAction={(input, _key, item) => {
						if ((input === 'd' || input === 'D') && item) {
							setPendingDelete(item.value as number);
						} else if ((input === 'v' || input === 'V') && item) {
							push({kind: 'cert-details', id: item.value as number});
						}
					}}
				/>
			</Box>
			<FunctionBar
				keys={[
					{key: 'Enter', label: t('fbar.details')},
					{key: '/', label: t('fbar.search')},
					{key: 'D', label: t('fbar.delete')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}

function typeIcon(t: CertType): string {
	if (t === 'ca') return '🏛 ';
	if (t === 'server') return '🖥 ';
	return '👤';
}
