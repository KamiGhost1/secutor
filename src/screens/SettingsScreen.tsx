import React from 'react';
import {Box} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Menu} from '../components/Menu.js';
import {useApp} from '../state/AppContext.js';
import {useLocale, useT, Locale} from '../i18n/LocaleProvider.js';

export function SettingsScreen() {
	const {pop, showToast} = useApp();
	const t = useT();
	const {locale, setLocale} = useLocale();

	const items = [
		{label: `${locale === 'en' ? '✔ ' : '  '}English`, value: 'en' as Locale},
		{label: `${locale === 'ru' ? '✔ ' : '  '}Русский`, value: 'ru' as Locale},
	];

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('settings.title')} />
			<Box padding={1} flexDirection="column" flexGrow={1}>
				<Menu
					title={t('settings.language')}
					items={items}
					onSelect={(v) => {
						setLocale(v);
						showToast({
							kind: 'success',
							message: makeChangedToast(v),
						});
					}}
					onCancel={pop}
				/>
			</Box>
			<FunctionBar
				keys={[
					{key: 'Enter', label: t('common.apply')},
					{key: 'Esc', label: t('common.back')},
				]}
			/>
		</Box>
	);
}

function makeChangedToast(loc: Locale): string {
	if (loc === 'ru') return 'Язык изменён на Русский';
	return 'Language changed to English';
}
