import {useEffect} from 'react';
import {fkeyBus, FKeyEvent} from './inputProxy.js';

export function useFunctionKey(
	name: 'f1' | 'f2' | 'f3' | 'f4' | 'f5' | 'f6' | 'f7' | 'f8' | 'f9' | 'f10' | 'f11' | 'f12',
	handler: () => void,
	deps: ReadonlyArray<unknown> = [],
): void {
	useEffect(() => {
		const cb = (e: FKeyEvent) => {
			if (e.name === name) handler();
		};
		fkeyBus.on('fkey', cb);
		return () => {
			fkeyBus.off('fkey', cb);
		};
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, deps);
}
