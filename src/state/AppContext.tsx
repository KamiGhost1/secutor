import React, {createContext, useContext, useMemo, useState, useCallback} from 'react';

export type Screen =
	| {kind: 'contexts'}
	| {kind: 'unlock'; name: string}
	| {kind: 'set-password'; name: string}
	| {kind: 'main'}
	| {kind: 'certificates'; filter?: 'ca' | 'server' | 'client'}
	| {kind: 'cert-details'; id: number}
	| {kind: 'reassign-issuer'; id: number}
	| {kind: 'renew-cert'; id: number}
	| {kind: 'create-ca'}
	| {kind: 'issue-intermediate-ca'}
	| {kind: 'issue-cert'; certType: 'server' | 'client'}
	| {kind: 'profiles'}
	| {kind: 'create-profile'; certId?: number}
	| {kind: 'verify'}
	| {kind: 'export-context'}
	| {kind: 'import-context'}
	| {kind: 'import-cert'}
	| {kind: 'import-profile'}
	| {kind: 'export-cert'; id: number}
	| {kind: 'export-profile'; id: number}
	| {kind: 'sni-search'}
	| {kind: 'audit'}
	| {kind: 'sign-file'}
	| {kind: 'verify-signature'}
	| {kind: 'ssh-keys'}
	| {kind: 'create-ssh-key'}
	| {kind: 'ssh-key-details'; id: number}
	| {kind: 'settings'};

export type Toast = {kind: 'info' | 'error' | 'success'; message: string};

type AppCtx = {
	screens: Screen[];
	current: Screen;
	push: (s: Screen) => void;
	pop: () => void;
	replace: (s: Screen) => void;
	resetTo: (s: Screen) => void;
	contextName: string | null;
	setContextName: (n: string | null) => void;
	toast: Toast | null;
	showToast: (t: Toast) => void;
	clearToast: () => void;
	exit: () => void;
};

const Context = createContext<AppCtx | null>(null);

export function AppProvider({
	initialScreen,
	onExit,
	children,
}: {
	initialScreen: Screen;
	onExit: () => void;
	children: React.ReactNode;
}) {
	const [screens, setScreens] = useState<Screen[]>([initialScreen]);
	const [contextName, setContextName] = useState<string | null>(null);
	const [toast, setToast] = useState<Toast | null>(null);

	const push = useCallback((s: Screen) => setScreens(p => [...p, s]), []);
	const pop = useCallback(
		() => setScreens(p => (p.length > 1 ? p.slice(0, -1) : p)),
		[],
	);
	const replace = useCallback(
		(s: Screen) => setScreens(p => [...p.slice(0, -1), s]),
		[],
	);
	const resetTo = useCallback((s: Screen) => setScreens([s]), []);
	const showToast = useCallback((t: Toast) => {
		setToast(t);
		setTimeout(() => setToast(null), 3500);
	}, []);
	const clearToast = useCallback(() => setToast(null), []);

	const value = useMemo<AppCtx>(
		() => ({
			screens,
			current: screens[screens.length - 1],
			push,
			pop,
			replace,
			resetTo,
			contextName,
			setContextName,
			toast,
			showToast,
			clearToast,
			exit: onExit,
		}),
		[screens, push, pop, replace, resetTo, contextName, toast, showToast, clearToast, onExit],
	);

	return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useApp(): AppCtx {
	const ctx = useContext(Context);
	if (!ctx) throw new Error('AppContext not provided');
	return ctx;
}
