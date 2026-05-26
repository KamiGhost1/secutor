import React, {useState} from 'react';
import {Box} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Menu} from '../components/Menu.js';
import {useApp} from '../state/AppContext.js';
import {useLocale, useT, Locale} from '../i18n/LocaleProvider.js';
import {readSettings, updateSetting, Settings} from '../storage/settings.js';

type ItemValue =
	| {kind: 'locale'; loc: Locale}
	| {kind: 'toggle'; key: keyof Settings};

export function SettingsScreen() {
	const {pop, showToast} = useApp();
	const t = useT();
	const {locale, setLocale} = useLocale();
	const [settings, setSettings] = useState<Settings>(() => readSettings());

	const items: Array<{label: string; value: ItemValue; hint?: string}> = [
		{
			label: `${locale === 'en' ? '✔ ' : '  '}English`,
			value: {kind: 'locale', loc: 'en'},
		},
		{
			label: `${locale === 'ru' ? '✔ ' : '  '}Русский`,
			value: {kind: 'locale', loc: 'ru'},
		},
		{
			label: `${settings.showWebConfigs ? '✔ ' : '  '}${t('settings.showWebConfigs')}`,
			value: {kind: 'toggle', key: 'showWebConfigs'},
			hint: t('settings.showWebConfigsHint'),
		},
	];

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('settings.title')} />
			<Box padding={1} flexDirection="column" flexGrow={1}>
				<Menu
					title={t('settings.title')}
					items={items}
					onSelect={(v) => {
						if (v.kind === 'locale') {
							setLocale(v.loc);
							showToast({kind: 'success', message: makeChangedToast(v.loc)});
						} else {
							const next = !settings[v.key];
							const updated = updateSetting(v.key, next);
							setSettings(updated);
							showToast({
								kind: 'success',
								message: t(next ? 'settings.toggledOn' : 'settings.toggledOff'),
							});
						}
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
