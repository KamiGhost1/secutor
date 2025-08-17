import React from 'react';
import {Box, Text, useInput} from 'ink';
import {useT} from '../i18n/LocaleProvider.js';

export function Confirm({
	message,
	onConfirm,
	onCancel,
}: {
	message: string;
	onConfirm: () => void;
	onCancel: () => void;
}) {
	const t = useT();
	useInput((input, key) => {
		if (key.escape || input === 'n' || input === 'N') onCancel();
		else if (key.return || input === 'y' || input === 'Y') onConfirm();
	});
	return (
		<Box
			borderStyle="double"
			borderColor="yellow"
			paddingX={2}
			paddingY={1}
			flexDirection="column"
		>
			<Text color="yellow" bold>
				{message}
			</Text>
			<Text color="gray">{t('common.confirmYesNo')}</Text>
		</Box>
	);
}
