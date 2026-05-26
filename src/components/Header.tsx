import React from 'react';
import {Box, Text} from 'ink';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {VERSION} from '../version.js';

export function Header({title}: {title: string}) {
	const {contextName} = useApp();
	const t = useT();
	return (
		<Box
			borderStyle="single"
			borderColor="cyan"
			paddingX={1}
			justifyContent="space-between"
		>
			<Text bold color="cyan">
				{t('app.headerPrefix')} <Text color="gray">v{VERSION}</Text> · {title}
			</Text>
			<Text color="gray">
				{t('app.contextLabel')}:{' '}
				<Text color={contextName ? 'green' : 'yellow'}>
					{contextName || t('app.noneContext')}
				</Text>
			</Text>
		</Box>
	);
}
