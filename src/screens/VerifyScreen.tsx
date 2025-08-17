import React, {useMemo, useState} from 'react';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Menu} from '../components/Menu.js';
import {TextField} from '../components/TextField.js';
import {Button} from '../components/Button.js';
import {useArrowFocus} from '../components/Form.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {certRepo} from '../storage/repos.js';
import {verifyCertById, VerifyResult} from '../certs/verify.js';

export function VerifyScreen() {
	const {pop} = useApp();
	const t = useT();
	const certs = useMemo(() => certRepo.list(), []);
	const [selected, setSelected] = useState<number | null>(null);

	if (selected === null) {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('verify.pick')} />
				<Box padding={1}>
					<Menu
						items={certs.map(c => ({
							label: `${typeIcon(c.type)} ${c.name}`,
							value: c.id,
							hint: `CN=${c.common_name}`,
						}))}
						onSelect={setSelected}
						onCancel={pop}
					/>
				</Box>
				<FunctionBar keys={[{key: 'Enter', label: t('fbar.pick')}, {key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	return <VerifyForm id={selected} onBack={() => setSelected(null)} />;
}

function VerifyForm({id, onBack}: {id: number; onBack: () => void}) {
	useArrowFocus();
	const t = useT();
	const {pop} = useApp();
	const [sni, setSni] = useState('');
	const [result, setResult] = useState<VerifyResult | null>(null);

	useInput((_input, key) => {
		if (key.escape) pop();
	});

	const run = () => {
		setResult(verifyCertById(id, sni.trim() || undefined));
	};

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('verify.title')} />
			<Box padding={1} flexDirection="column">
				<TextField id="sni" label={t('verify.sni')} value={sni} onChange={setSni} autoFocus placeholder={t('verify.sniPlaceholder')} />
				<Box marginTop={1}>
					<Button id="run" label={t('verify.cta')} onPress={run} />
					<Box marginLeft={2}>
						<Button id="back" label={t('verify.toList')} onPress={onBack} />
					</Box>
				</Box>
				{result && (
					<Box marginTop={1} flexDirection="column" borderStyle="round" borderColor={result.ok ? 'green' : 'red'} paddingX={1}>
						<Text bold color={result.ok ? 'green' : 'red'}>
							{result.ok ? '✔ OK' : `✘ ${result.reason}`}
						</Text>
						<Text>{t('verify.chain', {chain: result.chain.join(' → ')})}</Text>
						<Text>
							{t('verify.validity', {
								from: result.notBefore.toISOString().slice(0, 10),
								to: result.notAfter.toISOString().slice(0, 10),
							})}
						</Text>
						{result.sni && (
							<Text color={result.sni.matched ? 'green' : 'red'}>
								{result.sni.matched
									? t('verify.sniMatch', {name: result.sni.requested})
									: t('verify.sniMiss', {name: result.sni.requested})}
							</Text>
						)}
					</Box>
				)}
			</Box>
			<FunctionBar
				keys={[
					{key: 'Enter', label: t('fbar.run')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}

function typeIcon(type: string): string {
	if (type === 'ca') return '🏛 ';
	if (type === 'server') return '🖥 ';
	return '👤';
}
