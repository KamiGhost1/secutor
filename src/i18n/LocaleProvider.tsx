import React, {createContext, useContext, useEffect, useMemo, useState} from 'react';
import fs from 'fs';
import path from 'path';
import {rootDir, ensureRoot} from '../storage/paths.js';
import {en, StringKey, Strings} from './locales/en.js';
import {ru} from './locales/ru.js';
import {de} from './locales/de.js';
import {es} from './locales/es.js';
import {fr} from './locales/fr.js';
import {zh} from './locales/zh.js';

export type Locale = 'en' | 'ru' | 'de' | 'es' | 'fr' | 'zh';

const DICT: Record<Locale, Strings> = {en, ru, de, es, fr, zh};

const SUPPORTED_LOCALES: Locale[] = ['en', 'ru', 'de', 'es', 'fr', 'zh'];

function localeFile(): string {
	return path.join(rootDir(), 'locale.json');
}

function readLocaleFromDisk(): Locale {
	try {
		const raw = JSON.parse(fs.readFileSync(localeFile(), 'utf8'));
		if (SUPPORTED_LOCALES.includes(raw?.locale)) return raw.locale as Locale;
	} catch {}
	return 'en';
}

function writeLocaleToDisk(loc: Locale): void {
	try {
		ensureRoot();
		fs.writeFileSync(localeFile(), JSON.stringify({locale: loc}));
	} catch {}
}

export type TFn = (key: StringKey, vars?: Record<string, string | number>) => string;

function makeT(loc: Locale): TFn {
	return (key, vars) => {
		const dict = DICT[loc] || en;
		const tmpl = (dict[key] ?? en[key] ?? key) as string;
		if (!vars) return tmpl;
		return tmpl.replace(/\{(\w+)\}/g, (_m, k) => String(vars[k] ?? ''));
	};
}

type LocaleCtx = {
	locale: Locale;
	setLocale: (l: Locale) => void;
	t: TFn;
};

const Ctx = createContext<LocaleCtx | null>(null);

export function LocaleProvider({children}: {children: React.ReactNode}) {
	const [locale, setLocaleState] = useState<Locale>(() => readLocaleFromDisk());

	const setLocale = (l: Locale) => {
		setLocaleState(l);
		writeLocaleToDisk(l);
	};

	const value = useMemo<LocaleCtx>(
		() => ({locale, setLocale, t: makeT(locale)}),
		[locale],
	);
	return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useT(): TFn {
	const ctx = useContext(Ctx);
	if (!ctx) return makeT('en');
	return ctx.t;
}

export function useLocale(): {locale: Locale; setLocale: (l: Locale) => void} {
	const ctx = useContext(Ctx);
	if (!ctx) return {locale: 'en', setLocale: () => {}};
	return {locale: ctx.locale, setLocale: ctx.setLocale};
}
