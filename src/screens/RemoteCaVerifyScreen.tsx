import React, {useState} from 'react';
import fs from 'fs';
import crypto from 'crypto';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Menu} from '../components/Menu.js';
import {FileExplorer} from '../components/FileExplorer.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {certRepo} from '../storage/repos.js';
import {clientFor, getHub} from '../net/sessionCache.js';
import {AdminApi} from '../net/adminApi.js';
import {HubError} from '../net/hubClient.js';

type Step =
	| {kind: 'pick-source'}
	| {kind: 'pick-cert-from-context'}
	| {kind: 'pick-file'}
	| {kind: 'busy'}
	| {kind: 'done'; ok: boolean; hubFp: string; alg: string; expectedFp: string};

export function RemoteCaVerifyScreen({hubId}: {hubId: string}) {
	const {pop, showToast} = useApp();
	const t = useT();
	const hub = getHub(hubId);
	const [step, setStep] = useState<Step>({kind: 'pick-source'});

	// Menu / FileExplorer own Esc on the interactive steps. For the terminal
	// 'done' step there is no such child widget, so we accept Esc here.
	useInput((_, key) => {
		if (step.kind === 'done' && key.escape) pop();
	});

	function runVerify(expectedCertPem: string) {
		const expectedFp = sha256OfPem(expectedCertPem);
		setStep({kind: 'busy'});
		let client;
		try {
			client = clientFor(hubId);
		} catch (e: any) {
			showToast({kind: 'error', message: e?.message ?? String(e)});
			setStep({kind: 'pick-source'});
			return;
		}
		const api = new AdminApi(client);
		api
			.verifyCa(expectedCertPem)
			.then(res => {
				setStep({kind: 'done', ok: res.ok, hubFp: res.hubCertFingerprint, alg: res.alg, expectedFp});
			})
			.catch(err => {
				showToast({
					kind: 'error',
					message: err instanceof HubError ? `${err.code}: ${err.message}` : String(err?.message ?? err),
				});
				setStep({kind: 'pick-source'});
			})
			.finally(() => client.close());
	}

	if (step.kind === 'pick-source') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={hub ? `${t('caVerify.title')} — 🌐 ${hub.name}` : t('caVerify.title')} />
				<Box padding={1} flexDirection="column">
					<Text color="gray">{t('caVerify.intro')}</Text>
				</Box>
				<Box flexGrow={1} paddingX={1}>
					<Menu
						title={t('caVerify.sourceTitle')}
						items={[
							{label: t('caVerify.sourceContext'), value: 'ctx'},
							{label: t('caVerify.sourceFile'), value: 'file'},
						]}
						onSelect={v => {
							if (v === 'ctx') setStep({kind: 'pick-cert-from-context'});
							else setStep({kind: 'pick-file'});
						}}
						onCancel={pop}
					/>
				</Box>
			</Box>
		);
	}

	if (step.kind === 'pick-cert-from-context') {
		const cas = certRepo.list({type: 'ca'});
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('caVerify.pickCtxCert')} />
				<Box flexGrow={1} paddingX={1}>
					<Menu
						emptyText={t('caVerify.noCas')}
						items={cas.map(c => ({
							label: c.name,
							value: c.id,
							hint: `fp ${c.fingerprint.slice(0, 12)}… · cn ${c.common_name}`,
						}))}
						onSelect={id => {
							const row = certRepo.findById(id as number);
							if (!row) return;
							runVerify(row.cert_pem);
						}}
						onCancel={() => setStep({kind: 'pick-source'})}
					/>
				</Box>
			</Box>
		);
	}

	if (step.kind === 'pick-file') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('caVerify.pickFile')} />
				<Box flexGrow={1} paddingX={1}>
					<FileExplorer
						mode="open"
						title={t('caVerify.pickFile')}
						onCancel={() => setStep({kind: 'pick-source'})}
						onSelect={p => {
							try {
								const pem = fs.readFileSync(p, 'utf8');
								if (!/-----BEGIN CERTIFICATE-----/.test(pem)) {
									showToast({kind: 'error', message: t('caVerify.notACert')});
									return;
								}
								runVerify(pem);
							} catch (e: any) {
								showToast({kind: 'error', message: e?.message ?? String(e)});
							}
						}}
					/>
				</Box>
			</Box>
		);
	}

	if (step.kind === 'busy') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('caVerify.title')} />
				<Box padding={1}><Text color="cyan">{t('caVerify.busy')}</Text></Box>
			</Box>
		);
	}

	// done
	const match = step.hubFp === step.expectedFp;
	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('caVerify.title')} />
			<Box padding={1} flexDirection="column">
				{step.ok ? (
					<Text color="green">✔ {t('caVerify.signOk', {alg: step.alg})}</Text>
				) : (
					<Text color="red">✘ {t('caVerify.signFail')}</Text>
				)}
				<Box marginTop={1} flexDirection="column">
					<Text>
						{t('caVerify.expectedFp')}: <Text color={match ? 'green' : 'yellow'}>{step.expectedFp.slice(0, 32)}…</Text>
					</Text>
					<Text>
						{t('caVerify.hubFp')}: <Text color={match ? 'green' : 'yellow'}>{step.hubFp.slice(0, 32)}…</Text>
					</Text>
					{!match && (
						<Text color="yellow">{t('caVerify.fpDiffers')}</Text>
					)}
				</Box>
			</Box>
			<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
		</Box>
	);
}

function sha256OfPem(pem: string): string {
	const body = pem.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----/g, '').replace(/\s+/g, '');
	return crypto.createHash('sha256').update(Buffer.from(body, 'base64')).digest('hex');
}
