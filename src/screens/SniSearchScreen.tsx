import React, {useState} from 'react';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {TextField} from '../components/TextField.js';
import {Button} from '../components/Button.js';
import {useArrowFocus} from '../components/Form.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {certRepo, CertRow} from '../storage/repos.js';

export function SniSearchScreen() {
	useArrowFocus();
	const {pop} = useApp();
	const t = useT();
	const [q, setQ] = useState('');
	const [results, setResults] = useState<CertRow[]>([]);
	const [done, setDone] = useState(false);

	useInput((_input, key) => {
		if (key.escape) pop();
	});

	const run = () => {
		if (!q.trim()) {
			setResults([]);
			setDone(true);
			return;
		}
		const all = certRepo.list({type: 'server'});
		const found = all.filter(c => {
			if (c.common_name.toLowerCase() === q.toLowerCase()) return true;
			if (!c.san) return false;
			try {
				const sans = JSON.parse(c.san) as string[];
				return sans.some(s => matchHost(s, q));
			} catch {
				return false;
			}
		});
		setResults(found);
		setDone(true);
	};

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('sni.title')} />
			<Box padding={1} flexDirection="column">
				<TextField id="q" label={t('sni.q')} value={q} onChange={setQ} autoFocus onSubmit={run} placeholder={t('sni.qPlaceholder')} />
				<Box marginTop={1}>
					<Button id="run" label={t('common.search')} onPress={run} />
				</Box>
				{done && (
					<Box marginTop={1} flexDirection="column">
						<Text bold>{t('sni.results', {n: results.length})}</Text>
						{results.length === 0 ? (
							<Text color="yellow">{t('sni.notFound', {q})}</Text>
						) : (
							results.map(r => (
								<Box key={r.id}>
									<Text>
										<Text color="cyan">{r.name}</Text> · CN={r.common_name}
										{r.san ? ` · SAN ${r.san}` : ''} · {r.not_after.slice(0, 10)}
									</Text>
								</Box>
							))
						)}
					</Box>
				)}
			</Box>
			<FunctionBar
				keys={[
					{key: 'Enter', label: t('fbar.search')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}

function matchHost(pattern: string, host: string): boolean {
	const p = pattern.toLowerCase();
	const h = host.toLowerCase();
	if (p === h) return true;
	if (p.startsWith('*.')) {
		const suffix = p.slice(1);
		const idx = h.indexOf('.');
		if (idx > 0 && h.slice(idx) === suffix) return true;
	}
	return false;
}
