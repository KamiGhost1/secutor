import React, {useState} from 'react';
import fs from 'fs';
import {Box, Text} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Menu} from '../components/Menu.js';
import {Confirm} from '../components/Confirm.js';
import {FileExplorer} from '../components/FileExplorer.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {certRepo, profileRepo} from '../storage/repos.js';
import {buildCRL, collectSubtreePems} from '../certs/generator.js';

type CertFormat = 'cert' | 'key' | 'bundle' | 'chain' | 'crl' | 'subtree';

function buildChain(id: number): {pems: string[]; complete: boolean} {
	const root = certRepo.findById(id);
	if (!root) return {pems: [], complete: false};
	const pems = [root.cert_pem];
	let cur = root;
	const seen = new Set<number>();
	while (cur.issuer_id && !seen.has(cur.issuer_id)) {
		seen.add(cur.issuer_id);
		const parent = certRepo.findById(cur.issuer_id);
		if (!parent) break;
		pems.push(parent.cert_pem);
		cur = parent;
	}
	return {pems, complete: cur.issuer_id === null};
}

export function ExportCertScreen({id}: {id: number}) {
	const {pop, showToast} = useApp();
	const t = useT();
	const row = certRepo.findById(id);
	const [fmt, setFmt] = useState<CertFormat | null>(null);
	const [chainWarn, setChainWarn] = useState(false);

	if (!row) {
		return (
			<Box flexDirection="column">
				<Header title={t('export.notFound')} />
				<Box padding={1}>
					<Text color="red">{t('export.certNotFound')}</Text>
				</Box>
				<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	const chainPreview = buildChain(id);
	const isCa = row.type === 'ca';
	const subtreePreview = isCa ? collectSubtreePems(id) : null;
	const revokedDirect = isCa ? certRepo.listRevokedBy(id) : [];

	const handleFormatSelect = (v: CertFormat) => {
		if (v === 'chain' && !chainPreview.complete && chainPreview.pems.length > 1) {
			setChainWarn(true);
		} else {
			setFmt(v);
		}
	};

	if (!fmt && !chainWarn) {
		const chainHint =
			chainPreview.pems.length <= 1
				? undefined
				: chainPreview.complete
				? t('export.chainHintOk', {n: chainPreview.pems.length})
				: t('export.chainHintWarn', {n: chainPreview.pems.length});

		const items: Array<{label: string; value: CertFormat; hint?: string}> = [
			{label: t('export.cert'), value: 'cert'},
			{label: t('export.key'), value: 'key'},
			{label: t('export.bundle'), value: 'bundle'},
			{label: t('export.chain'), value: 'chain', hint: chainHint},
		];
		if (isCa) {
			items.push({
				label: t('export.subtree'),
				value: 'subtree',
				hint: t('export.subtreeHint', {n: subtreePreview!.length}),
			});
			items.push({
				label: t('export.crl'),
				value: 'crl',
				hint: t('export.crlHint', {n: revokedDirect.length}),
			});
		}

		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('export.title', {name: row.name})} />
				<Box padding={1}>
					<Menu
						items={items.map(i => ({label: i.label, value: i.value, hint: i.hint}))}
						onSelect={(v) => handleFormatSelect(v as CertFormat)}
						onCancel={pop}
					/>
				</Box>
				<FunctionBar keys={[{key: 'Enter', label: t('fbar.pick')}, {key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	if (chainWarn) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('export.title', {name: row.name})} />
				<Box padding={1}>
					<Confirm
						message={t('export.chainWarn', {n: chainPreview.pems.length})}
						onConfirm={() => {setChainWarn(false); setFmt('chain');}}
						onCancel={() => setChainWarn(false)}
					/>
				</Box>
				<FunctionBar keys={[{key: 'Y', label: t('fbar.pick')}, {key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	const ext =
		fmt === 'cert' ? '.crt'
		: fmt === 'key' ? '.key'
		: fmt === 'bundle' ? '.pem'
		: fmt === 'crl' ? '.crl'
		: fmt === 'subtree' ? '-subtree.pem'
		: '-chain.pem';
	const defaultName = `${row.name}${ext}`;

	const data: string | Buffer = (() => {
		if (fmt === 'cert') return row.cert_pem;
		if (fmt === 'key') return row.key_pem;
		if (fmt === 'bundle') return row.cert_pem + row.key_pem;
		if (fmt === 'subtree') return collectSubtreePems(id).join('');
		if (fmt === 'crl') {
			try {
				return buildCRL(id);
			} catch (e: any) {
				showToast({kind: 'error', message: e.message});
				return '';
			}
		}
		return buildChain(id).pems.join('');
	})();

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('export.saveTitle', {name: row.name, fmt: fmt ?? ''})} />
			<Box padding={1} flexDirection="column" flexGrow={1}>
				<FileExplorer
					mode="save"
					defaultFileName={defaultName}
					title={t('files.whereToSave')}
					onSelect={(target) => {
						try {
							fs.writeFileSync(target, data);
							showToast({kind: 'success', message: t('export.savedToast', {path: target})});
							pop();
						} catch (e: any) {
							showToast({kind: 'error', message: e.message});
						}
					}}
					onCancel={() => setFmt(null)}
				/>
			</Box>
		</Box>
	);
}

export function ExportProfileScreen({id}: {id: number}) {
	const {pop, showToast} = useApp();
	const t = useT();
	const p = profileRepo.findById(id);

	if (!p) {
		return (
			<Box flexDirection="column">
				<Header title={t('export.notFound')} />
				<Box padding={1}>
					<Text color="red">{t('export.profileNotFound')}</Text>
				</Box>
				<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('export.profileTitle', {name: p.name})} />
			<Box padding={1} flexDirection="column" flexGrow={1}>
				<FileExplorer
					mode="save"
					defaultFileName={`${p.name}.p12`}
					title={t('files.whereToSave')}
					onSelect={(target) => {
						try {
							fs.writeFileSync(target, p.data);
							showToast({kind: 'success', message: t('export.savedToast', {path: target})});
							pop();
						} catch (e: any) {
							showToast({kind: 'error', message: e.message});
						}
					}}
					onCancel={pop}
				/>
			</Box>
		</Box>
	);
}
