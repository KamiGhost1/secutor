import React, {useEffect, useState} from 'react';
import fs from 'fs';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Menu} from '../components/Menu.js';
import {FileExplorer} from '../components/FileExplorer.js';
import {Confirm} from '../components/Confirm.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {clientFor, getHub} from '../net/sessionCache.js';
import {AdminApi} from '../net/adminApi.js';
import {certRepo} from '../storage/repos.js';
import {decryptPrivateKey, isEncryptedKey} from '../certs/keys.js';
import {parseBundle, isBundleFile} from '../transfer/keyBundle.js';
import {dataToText} from '../transfer/keyBundle.js';

type Step =
	| {kind: 'menu'}
	| {kind: 'pick-source'}
	| {kind: 'pick-context-ca'}
	| {kind: 'pick-skb-file'}
	| {kind: 'confirm-stage'; cert: string; key: string; chain: string; meta: {fp: string; cn: string}}
	| {kind: 'staged'; fp: string; cn: string; notAfter: string; alg: string}
	| {kind: 'busy'};

export function RemoteCaRotateScreen({hubId}: {hubId: string}) {
	const {pop, push, showToast} = useApp();
	const t = useT();
	const hub = getHub(hubId);
	const [step, setStep] = useState<Step>({kind: 'menu'});
	const [confirmPromote, setConfirmPromote] = useState(false);

	useEffect(() => {
		refreshStaged();
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [hubId]);

	function refreshStaged(): void {
		try {
			const client = clientFor(hubId);
			new AdminApi(client)
				.getStagedCa()
				.then(g => {
					if (g.staged && g.fingerprint) {
						setStep({
							kind: 'staged',
							fp: g.fingerprint,
							cn: g.common_name ?? '?',
							notAfter: g.not_after ?? '?',
							alg: g.key_algorithm ?? '?',
						});
					}
				})
				.finally(() => client.close());
		} catch {}
	}

	// Esc on every step is owned by the Menu/Confirm/FileExplorer rendered
	// for that step; adding it here would pop twice on the root menu.

	if (!hub) return null;

	if (step.kind === 'menu') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={`${t('caRotate.title')} — 🌐 ${hub.name}`} />
				<Box flexGrow={1} paddingX={1}>
					<Menu
						items={[
							{label: t('caRotate.stageNew'), value: 'stage'},
							{label: t('caRotate.rollback'), value: 'rollback'},
							{label: t('caRotate.kickReissue'), value: 'reissue'},
						]}
						onSelect={v => {
							if (v === 'stage') setStep({kind: 'pick-source'});
							else if (v === 'rollback') {
								const client = clientFor(hubId);
								new AdminApi(client)
									.rollbackCa()
									.then(r => {
										showToast({kind: 'success', message: t('caRotate.rolledBack', {fp: r.restored_fingerprint.slice(0, 16)})});
										pop();
									})
									.catch(e => showToast({kind: 'error', message: e?.message ?? String(e)}))
									.finally(() => client.close());
							} else {
								// kick reissue (all-active)
								const client = clientFor(hubId);
								new AdminApi(client)
									.startReissueJob({scope: 'all-active'})
									.then(j => {
										showToast({kind: 'success', message: t('caRotate.reissueStarted', {n: String(j.total)})});
										push({kind: 'job-progress', hubId, jobId: j.id});
									})
									.catch(e => showToast({kind: 'error', message: e?.message ?? String(e)}))
									.finally(() => client.close());
							}
						}}
						onCancel={pop}
					/>
				</Box>
				<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	if (step.kind === 'pick-source') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('caRotate.pickSource')} />
				<Box flexGrow={1} paddingX={1}>
					<Menu
						items={[
							{label: t('caRotate.fromContextCa'), value: 'ctx'},
							{label: t('caRotate.fromSkb'), value: 'skb'},
						]}
						onSelect={v => {
							if (v === 'ctx') setStep({kind: 'pick-context-ca'});
							else setStep({kind: 'pick-skb-file'});
						}}
						onCancel={() => setStep({kind: 'menu'})}
					/>
				</Box>
			</Box>
		);
	}

	if (step.kind === 'pick-context-ca') {
		const cas = certRepo.list({type: 'ca'}).filter(c => !!c.key_pem);
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('caRotate.pickContextCa')} />
				<Box flexGrow={1} paddingX={1}>
					<Menu
						emptyText={t('caRotate.noCasWithKey')}
						items={cas.map(c => ({
							label: c.name,
							value: c.id,
							hint: `${c.common_name} · fp ${c.fingerprint.slice(0, 12)}…`,
						}))}
						onSelect={id => {
							const row = certRepo.findById(id as number)!;
							if (isEncryptedKey(row.key_pem)) {
								showToast({kind: 'error', message: t('caRotate.encryptedKeyTODO')});
								return;
							}
							const parent = row.issuer_id != null ? certRepo.findById(row.issuer_id) : null;
							setStep({
								kind: 'confirm-stage',
								cert: row.cert_pem,
								key: row.key_pem,
								chain: parent?.cert_pem ?? '',
								meta: {fp: row.fingerprint, cn: row.common_name},
							});
						}}
						onCancel={() => setStep({kind: 'pick-source'})}
					/>
				</Box>
			</Box>
		);
	}

	if (step.kind === 'pick-skb-file') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('caRotate.pickSkb')} />
				<Box flexGrow={1} paddingX={1}>
					<FileExplorer
						mode="open"
						title={t('caRotate.pickSkb')}
						onCancel={() => setStep({kind: 'pick-source'})}
						onSelect={p => {
							try {
								const buf = fs.readFileSync(p);
								if (!isBundleFile(buf)) {
									showToast({kind: 'error', message: t('importBundle.notBundle')});
									return;
								}
								const parsed = parseBundle(buf);
								const certItem = parsed.manifest.items.find(i => i.role === 'cert');
								const keyItem = parsed.manifest.items.find(i => i.role === 'key');
								const parentItem = parsed.manifest.items.find(i => i.role === 'parent');
								if (!certItem || !keyItem) {
									showToast({kind: 'error', message: t('caRotate.skbNeedsCertKey')});
									return;
								}
								const cert = dataToText(certItem.data);
								const key = dataToText(keyItem.data);
								if (isEncryptedKey(key)) {
									showToast({kind: 'error', message: t('caRotate.encryptedKeyTODO')});
									return;
								}
								setStep({
									kind: 'confirm-stage',
									cert,
									key,
									chain: parentItem ? dataToText(parentItem.data) : '',
									meta: {
										fp: certItem.meta?.fingerprint ?? '?',
										cn: certItem.meta?.commonName ?? '?',
									},
								});
							} catch (e: any) {
								showToast({kind: 'error', message: e?.message ?? String(e)});
							}
						}}
					/>
				</Box>
			</Box>
		);
	}

	if (step.kind === 'confirm-stage') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('caRotate.confirmStage')} />
				<Box padding={1} flexDirection="column">
					<Text>{t('caRotate.willStage', {cn: step.meta.cn, fp: step.meta.fp.slice(0, 16)})}</Text>
					<Box marginTop={1}>
						<Confirm
							message={t('caRotate.confirmStageQ')}
							onCancel={() => setStep({kind: 'pick-source'})}
							onConfirm={() => {
								setStep({kind: 'busy'});
								const client = clientFor(hubId);
								new AdminApi(client)
									.stageCa({certPem: step.cert, keyPem: step.key, chainPem: step.chain})
									.then(r => {
										showToast({kind: 'success', message: t('caRotate.staged')});
										setStep({
											kind: 'staged',
											fp: r.fingerprint, cn: r.common_name, notAfter: r.not_after, alg: r.key_algorithm,
										});
									})
									.catch(e => {
										showToast({kind: 'error', message: e?.message ?? String(e)});
										setStep({kind: 'menu'});
									})
									.finally(() => client.close());
							}}
						/>
					</Box>
				</Box>
			</Box>
		);
	}

	if (step.kind === 'staged') {
		if (confirmPromote) {
			return (
				<Box flexDirection="column" flexGrow={1}>
					<Header title={t('caRotate.title')} />
					<Box padding={1}>
						<Confirm
							message={t('caRotate.confirmPromote', {fp: step.fp.slice(0, 16)})}
							onCancel={() => setConfirmPromote(false)}
							onConfirm={() => {
								setConfirmPromote(false);
								const client = clientFor(hubId);
								new AdminApi(client)
									.promoteCa()
									.then(r => {
										showToast({
											kind: 'success',
											message: t('caRotate.promoted', {
												prev: r.previous_fingerprint.slice(0, 12),
												next: r.new_fingerprint.slice(0, 12),
											}),
										});
										setStep({kind: 'menu'});
									})
									.catch(e => showToast({kind: 'error', message: e?.message ?? String(e)}))
									.finally(() => client.close());
							}}
						/>
					</Box>
				</Box>
			);
		}
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={`${t('caRotate.title')} — ${t('caRotate.stagedHeader')}`} />
				<Box padding={1} flexDirection="column">
					<Text>{t('caRotate.stagedCn')}: <Text color="cyan">{step.cn}</Text></Text>
					<Text>{t('caRotate.stagedFp')}: <Text color="cyan">{step.fp.slice(0, 32)}…</Text></Text>
					<Text>{t('caRotate.stagedExpires')}: <Text color="gray">{step.notAfter.slice(0, 10)}</Text></Text>
					<Text>{t('caRotate.stagedAlg')}: <Text color="gray">{step.alg}</Text></Text>
				</Box>
				<Box flexGrow={1} paddingX={1}>
					<Menu
						items={[
							{label: '✓ ' + t('caRotate.promote'), value: 'promote'},
							{label: '✗ ' + t('caRotate.discard'), value: 'discard'},
						]}
						onSelect={v => {
							if (v === 'promote') setConfirmPromote(true);
							else {
								const client = clientFor(hubId);
								new AdminApi(client)
									.discardStagedCa()
									.then(() => {
										showToast({kind: 'success', message: t('caRotate.discarded')});
										setStep({kind: 'menu'});
									})
									.catch(e => showToast({kind: 'error', message: e?.message ?? String(e)}))
									.finally(() => client.close());
							}
						}}
						onCancel={() => setStep({kind: 'menu'})}
					/>
				</Box>
			</Box>
		);
	}

	// busy
	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('caRotate.title')} />
			<Box padding={1}><Text color="cyan">{t('common.empty')}…</Text></Box>
		</Box>
	);
}
