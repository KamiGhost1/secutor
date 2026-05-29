import React from 'react';
import {Box, Text, useInput} from 'ink';
import {useT} from '../i18n/LocaleProvider.js';

/**
 * Yes/no prompt. **Owns Esc and `n`/`y` on the screen it lives on.**
 *
 * GOTCHA — see the note next to `Menu.onCancel`. Do NOT also add a
 * screen-level `useInput((_, k) => { if (k.escape) pop() })` while a
 * `<Confirm onCancel={...} />` is mounted: Ink fires both handlers on
 * the same Esc and you'll pop the route stack twice.
 */
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
