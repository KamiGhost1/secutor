import React, {useMemo, useState} from 'react';
import {Box, Text, useInput} from 'ink';
import Spinner from 'ink-spinner';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Menu} from '../components/Menu.js';
import {Confirm} from '../components/Confirm.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {certRepo} from '../storage/repos.js';
import {parseCertPem} from '../certs/parser.js';
import {resignCertificate} from '../certs/generator.js';

type Mode = 'attach' | 'resign';

export function ReassignIssuerScreen({id}: {id: number}) {
	const {pop, replace, showToast} = useApp();
	const t = useT();
	const cert = useMemo(() => certRepo.findById(id), [id]);

	const [mode, setMode] = useState<Mode | null>(null);
	const [pickedCa, setPickedCa] = useState<number | null>(null);
	const [busy, setBusy] = useState(false);

	if (!cert) {
		useInput((_i, key) => {
			if (key.escape) pop();
		});
		return (
			<Box flexDirection="column">
				<Header title={t('reassign.title')} />
				<Box padding={1}>
					<Text color="red">{t('cert.notFound')}</Text>
				</Box>
				<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	const parsed = useMemo(() => parseCertPem(cert.cert_pem), [cert.cert_pem]);
	const issuerCN = parsed.issuer.commonName || '';

	const allCAs = useMemo(
		() => certRepo.list({type: 'ca'}).filter(c => c.id !== id),
		[id],
	);

	if (!mode) {
		const items = [
			{
				label: t('reassign.optAttach'),
				value: 'attach' as Mode,
				hint: t('reassign.optAttachHint'),
			},
			{
				label: t('reassign.optResign'),
				value: 'resign' as Mode,
				hint: t('reassign.optResignHint'),
			},
		];
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('reassign.title')} />
				<Box padding={1} flexDirection="column">
					<Box flexDirection="column" marginBottom={1}>
						<Text color="gray">{t('reassign.cert', {name: cert.name})}</Text>
						<Text color="gray">{t('reassign.currentIssuer', {cn: issuerCN || '—'})}</Text>
					</Box>
					<Menu items={items} onSelect={(v) => setMode(v as Mode)} onCancel={pop} />
				</Box>
				<FunctionBar
					keys={[
						{key: 'Enter', label: t('fbar.pick')},
						{key: 'Esc', label: t('fbar.back')},
					]}
				/>
			</Box>
		);
	}

	if (busy) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('reassign.title')} />
				<Box padding={2}>
					<Spinner type="dots" />
					<Text> {t('reassign.busy')}</Text>
				</Box>
			</Box>
		);
	}

	const eligible =
		mode === 'attach'
			? allCAs
			: allCAs.filter(c => !!c.key_pem);

	if (eligible.length === 0) {
		useInput((_i, key) => {
			if (key.escape) setMode(null);
		});
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('reassign.title')} />
				<Box padding={1}>
					<Text color="yellow">
						{mode === 'attach' ? t('reassign.noCaForAttach') : t('reassign.noCaForResign')}
					</Text>
				</Box>
				<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	if (pickedCa === null) {
		const items = eligible.map(c => {
			const cnMatches = c.common_name === issuerCN;
			let prefix: string;
			if (mode === 'attach') prefix = cnMatches ? '✓ ' : '· ';
			else prefix = c.key_pem ? '🔑 ' : '🔒 ';
			const hintParts: string[] = [`CN=${c.common_name}`];
			if (mode === 'attach' && cnMatches) hintParts.push(t('reassign.dnMatch'));
			if (mode === 'attach' && !cnMatches) hintParts.push(t('reassign.dnMismatch'));
			if (mode === 'resign' && !c.key_pem) hintParts.push(t('issue.caNoKey'));
			return {
				label: `${prefix}${c.name}`,
				value: c.id,
				hint: hintParts.join(' · '),
				disabled: mode === 'resign' && !c.key_pem,
			};
		});
		// Put DN-matching CAs first when attaching, so the suggested choice is on top.
		if (mode === 'attach') {
			items.sort((a, b) => {
				const am = a.hint?.includes(t('reassign.dnMatch')) ? 0 : 1;
				const bm = b.hint?.includes(t('reassign.dnMatch')) ? 0 : 1;
				return am - bm;
			});
		}
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('reassign.title')} />
				<Box padding={1} flexDirection="column">
					<Box flexDirection="column" marginBottom={1}>
						<Text color="gray">
							{mode === 'attach' ? t('reassign.attachExplain') : t('reassign.resignExplain')}
						</Text>
						<Text color="gray">{t('reassign.currentIssuer', {cn: issuerCN || '—'})}</Text>
					</Box>
					<Menu items={items} onSelect={(v) => setPickedCa(v as number)} onCancel={() => setMode(null)} />
				</Box>
				<FunctionBar
					keys={[
						{key: 'Enter', label: t('fbar.pick')},
						{key: 'Esc', label: t('fbar.back')},
					]}
				/>
			</Box>
		);
	}

	const targetCa = certRepo.findById(pickedCa)!;
	const dnMismatch = mode === 'attach' && targetCa.common_name !== issuerCN;
	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('reassign.title')} />
			<Box padding={1} flexDirection="column">
				<Confirm
					message={
						mode === 'attach'
							? dnMismatch
								? t('reassign.confirmAttachWarn', {ca: targetCa.name, expected: issuerCN, actual: targetCa.common_name})
								: t('reassign.confirmAttach', {ca: targetCa.name})
							: t('reassign.confirmResign', {ca: targetCa.name})
					}
					onConfirm={async () => {
						setBusy(true);
						try {
							if (mode === 'attach') {
								certRepo.relinkIssuer(id, pickedCa);
							} else {
								const result = await new Promise<ReturnType<typeof resignCertificate>>((res, rej) => {
									setTimeout(() => {
										try {
											res(resignCertificate(id, pickedCa));
										} catch (e) {
											rej(e);
										}
									}, 10);
								});
								certRepo.replaceCert(id, {
									cert_pem: result.certPem,
									issuer_id: pickedCa,
									serial: result.serial,
									not_before: result.notBefore.toISOString(),
									not_after: result.notAfter.toISOString(),
									fingerprint: result.fingerprint,
								});
							}
							showToast({
								kind: 'success',
								message: mode === 'attach' ? t('reassign.attached') : t('reassign.resigned'),
							});
							replace({kind: 'cert-details', id});
						} catch (e: any) {
							setBusy(false);
							showToast({kind: 'error', message: e.message});
						}
					}}
					onCancel={() => setPickedCa(null)}
				/>
			</Box>
		</Box>
	);
}
