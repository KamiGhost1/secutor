import React, {useState} from 'react';
import fs from 'fs';
import {Box, Text, useInput} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {FileExplorer} from '../components/FileExplorer.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {exportContextPath} from '../storage/contextStore.js';
import {persist} from '../storage/db.js';

export function ExportContextScreen() {
	const {pop, contextName, showToast} = useApp();
	const t = useT();
	const [done, setDone] = useState(false);

	useInput((_input, key) => {
		if (key.escape) pop();
	});

	if (done) {
		return null;
	}

	if (!contextName) {
		return (
			<Box flexDirection="column">
				<Header title={t('exportCtx.title')} />
				<Box padding={1}>
					<Text color="red">{t('exportCtx.noContext')}</Text>
				</Box>
				<FunctionBar keys={[{key: 'Esc', label: t('fbar.back')}]} />
			</Box>
		);
	}

	persist();
	const src = exportContextPath(contextName);
	const defaultName = `${contextName}-${new Date().toISOString().slice(0, 10)}${
		src.endsWith('.enc') ? '.cmgr' : '.sqlite'
	}`;

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('exportCtx.title')} />
			<Box padding={1}>
				<Text color="gray">{t('exportCtx.source', {path: src})}</Text>
			</Box>
			<Box padding={1} flexDirection="column" flexGrow={1}>
				<FileExplorer
					mode="save"
					defaultFileName={defaultName}
					title={t('files.whereToSave')}
					onSelect={(target) => {
						try {
							fs.copyFileSync(src, target);
							setDone(true);
							showToast({kind: 'success', message: t('files.savedAs', {path: target})});
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
