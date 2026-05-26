import React, {useState} from 'react';
import fs from 'fs';
import path from 'path';
import {Box, Text} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Menu} from '../components/Menu.js';
import {Confirm} from '../components/Confirm.js';
import {FileExplorer} from '../components/FileExplorer.js';
import {TextField} from '../components/TextField.js';
import {Button} from '../components/Button.js';
import {useArrowFocus} from '../components/Form.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {certRepo, profileRepo} from '../storage/repos.js';
import {buildCRL, collectSubtreePems} from '../certs/generator.js';
import {copyToClipboard} from '../utils/clipboard.js';
import {buildWebConfig, bundleAsText, WebConfigFormat, WebConfigBundle} from '../certs/configExport.js';
import {readSettings} from '../storage/settings.js';

type TextFormat = 'cert' | 'key' | 'bundle' | 'chain' | 'crl' | 'subtree';
type CertFormat = TextFormat | WebConfigFormat;

const WEB_FORMATS: CertFormat[] = ['nginx', 'traefik-file', 'traefik-acme'];
function isWebFormat(f: CertFormat): f is WebConfigFormat {
	return WEB_FORMATS.includes(f);
}

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

function defaultServerNames(row: {common_name: string; san: string | null}): string[] {
	const out: string[] = [];
	if (row.common_name) out.push(row.common_name);
	if (row.san) {
		try {
			const sans = JSON.parse(row.san) as string[];
			for (const s of sans) if (!out.includes(s)) out.push(s);
		} catch {}
	}
	return out;
}

function defaultInstallDir(fmt: WebConfigFormat, name: string): string {
	if (fmt === 'nginx') return `/etc/nginx/certs/${name}`;
	return `/etc/traefik/certs/${name}`;
}

export function ExportCertScreen({id}: {id: number}) {
	const {pop, showToast} = useApp();
	const t = useT();
	const row = certRepo.findById(id);
	const [fmt, setFmt] = useState<CertFormat | null>(null);
	const [chainWarn, setChainWarn] = useState(false);
	const [webStep, setWebStep] = useState<'domain' | 'action' | 'save' | null>(null);
	const [actionStep, setActionStep] = useState(false);
	const [serverNames, setServerNames] = useState('');
	const [installDir, setInstallDir] = useState('');
	const [acmeEmail, setAcmeEmail] = useState('');

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
			setFmt(v);
			return;
		}
		if (isWebFormat(v)) {
			const names = defaultServerNames(row);
			setServerNames(names.join(' '));
			setInstallDir(defaultInstallDir(v, row.name));
			setAcmeEmail(names[0] ? `admin@${names[0]}` : '');
			setFmt(v);
			setWebStep('domain');
			return;
		}
		setFmt(v);
		setActionStep(true);
	};

	// Format-selection screen
	if (!fmt) {
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
		if (readSettings().showWebConfigs) {
			items.push(
				{label: t('export.nginx'), value: 'nginx', hint: t('export.nginxHint')},
				{label: t('export.traefikFile'), value: 'traefik-file', hint: t('export.traefikFileHint')},
				{label: t('export.traefikAcme'), value: 'traefik-acme', hint: t('export.traefikAcmeHint')},
			);
		}
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

	// Chain incompleteness confirmation
	if (chainWarn) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('export.title', {name: row.name})} />
				<Box padding={1}>
					<Confirm
						message={t('export.chainWarn', {n: chainPreview.pems.length})}
						onConfirm={() => {setChainWarn(false); setActionStep(true);}}
						onCancel={() => {setChainWarn(false); setFmt(null);}}
					/>
				</Box>
				<FunctionBar keys={[{key: 'Y', label: t('fbar.pick')}, {key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	// Web-config domain/install-dir step
	if (isWebFormat(fmt) && webStep === 'domain') {
		return (
			<WebDomainForm
				fmt={fmt}
				serverNames={serverNames}
				setServerNames={setServerNames}
				installDir={installDir}
				setInstallDir={setInstallDir}
				acmeEmail={acmeEmail}
				setAcmeEmail={setAcmeEmail}
				certName={row.name}
				onSubmit={() => setWebStep('action')}
				onCancel={() => {setFmt(null); setWebStep(null);}}
			/>
		);
	}

	// Save vs Copy action menu
	if (actionStep || (isWebFormat(fmt) && webStep === 'action')) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('export.title', {name: row.name})} />
				<Box padding={1}>
					<Menu
						items={[
							{label: t('export.actionSave'), value: 'save', hint: t('export.actionSaveHint')},
							{label: t('export.actionCopy'), value: 'copy', hint: t('export.actionCopyHint')},
						]}
						onSelect={(v) => {
							if (v === 'copy') {
								try {
									const text = buildTextForCopy(fmt, row, id, serverNames, installDir, acmeEmail, showToast, t);
									if (!text) return;
									const res = copyToClipboard(text);
									if (res.ok) {
										showToast({kind: 'success', message: t('export.copiedToast', {via: res.via})});
										pop();
									} else {
										showToast({kind: 'error', message: t('export.copyFail', {error: res.error})});
									}
								} catch (e: any) {
									showToast({kind: 'error', message: e.message});
								}
							} else {
								if (isWebFormat(fmt)) setWebStep('save');
								else setActionStep(false);
							}
						}}
						onCancel={() => {
							if (isWebFormat(fmt)) setWebStep('domain');
							else {setActionStep(false); setFmt(null);}
						}}
					/>
				</Box>
				<FunctionBar keys={[{key: 'Enter', label: t('fbar.pick')}, {key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	// Save flow for web bundles -> ask for destination folder
	if (isWebFormat(fmt) && webStep === 'save') {
		const bundle = buildWebConfig(fmt, {
			name: row.name,
			serverNames: serverNames.split(/\s+/).filter(Boolean),
			certPem: row.cert_pem,
			keyPem: row.key_pem,
			chainPem: buildChain(id).pems.join(''),
			installDir,
			acmeEmail,
		});
		const defaultFolderName = row.name;
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('export.saveBundleTitle', {name: row.name, fmt})} />
				<Box padding={1} flexDirection="column" flexGrow={1}>
					<Text color="gray">{t('export.saveBundleHint', {n: bundle.files.length})}</Text>
					<FileExplorer
						mode="save"
						defaultFileName={defaultFolderName}
						title={t('export.pickFolder')}
						onSelect={(target) => {
							try {
								fs.mkdirSync(target, {recursive: true});
								for (const f of bundle.files) {
									const p = path.join(target, f.name);
									fs.writeFileSync(p, f.content, f.mode != null ? {mode: f.mode} : undefined);
								}
								showToast({
									kind: 'success',
									message: t('export.savedBundleToast', {dir: target, n: bundle.files.length}),
								});
								pop();
							} catch (e: any) {
								showToast({kind: 'error', message: e.message});
							}
						}}
						onCancel={() => setWebStep('action')}
					/>
				</Box>
			</Box>
		);
	}

	// Text-format save: single file
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
		if (fmt === 'chain') return buildChain(id).pems.join('');
		return '';
	})();

	const ext =
		fmt === 'cert' ? '.crt'
		: fmt === 'key' ? '.key'
		: fmt === 'bundle' ? '.pem'
		: fmt === 'crl' ? '.crl'
		: fmt === 'subtree' ? '-subtree.pem'
		: '-chain.pem';
	const defaultName = `${row.name}${ext}`;

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('export.saveTitle', {name: row.name, fmt})} />
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
					onCancel={() => setActionStep(true)}
				/>
			</Box>
		</Box>
	);
}

function buildTextForCopy(
	fmt: CertFormat,
	row: {name: string; cert_pem: string; key_pem: string},
	id: number,
	serverNames: string,
	installDir: string,
	acmeEmail: string,
	showToast: (toast: {kind: 'error'; message: string}) => void,
	t: (key: any, vars?: any) => string,
): string | null {
	if (fmt === 'cert') return row.cert_pem;
	if (fmt === 'key') return row.key_pem;
	if (fmt === 'bundle') return row.cert_pem + row.key_pem;
	if (fmt === 'chain') return buildChain(id).pems.join('');
	if (fmt === 'subtree') return collectSubtreePems(id).join('');
	if (fmt === 'crl') {
		try {
			return buildCRL(id).toString('base64');
		} catch (e: any) {
			showToast({kind: 'error', message: e.message});
			return null;
		}
	}
	const bundle: WebConfigBundle = buildWebConfig(fmt, {
		name: row.name,
		serverNames: serverNames.split(/\s+/).filter(Boolean),
		certPem: row.cert_pem,
		keyPem: row.key_pem,
		chainPem: buildChain(id).pems.join(''),
		installDir,
		acmeEmail,
	});
	return bundleAsText(bundle);
}

function WebDomainForm({
	fmt,
	serverNames,
	setServerNames,
	installDir,
	setInstallDir,
	acmeEmail,
	setAcmeEmail,
	certName,
	onSubmit,
	onCancel,
}: {
	fmt: WebConfigFormat;
	serverNames: string;
	setServerNames: (v: string) => void;
	installDir: string;
	setInstallDir: (v: string) => void;
	acmeEmail: string;
	setAcmeEmail: (v: string) => void;
	certName: string;
	onSubmit: () => void;
	onCancel: () => void;
}) {
	useArrowFocus();
	const t = useT();
	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('export.webDomainTitle', {name: certName, fmt})} />
			<Box padding={1} flexDirection="column">
				<TextField
					id="names"
					label={t('export.serverNames')}
					value={serverNames}
					onChange={setServerNames}
					autoFocus
					placeholder="example.com www.example.com"
				/>
				<Box marginTop={1}>
					<TextField
						id="dir"
						label={t('export.installDir')}
						value={installDir}
						onChange={setInstallDir}
						placeholder="/etc/nginx/certs/example"
					/>
				</Box>
				{fmt === 'traefik-acme' && (
					<Box marginTop={1}>
						<TextField
							id="email"
							label={t('export.acmeEmail')}
							value={acmeEmail}
							onChange={setAcmeEmail}
							placeholder="admin@example.com"
						/>
					</Box>
				)}
				<Box marginTop={1}>
					<Button id="next" label={t('common.next')} onPress={onSubmit} />
					<Box marginLeft={2}>
						<Button id="cancel" label={t('common.cancel')} onPress={onCancel} />
					</Box>
				</Box>
				<Box marginTop={1}>
					<Text color="gray">{t('export.webDomainHint')}</Text>
				</Box>
			</Box>
			<FunctionBar
				keys={[
					{key: 'Tab/↑↓', label: t('fbar.fields')},
					{key: 'Enter', label: t('common.next')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
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
