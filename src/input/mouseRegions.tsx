import React, {createContext, useCallback, useContext, useEffect, useRef} from 'react';
import {DOMElement, measureElement} from 'ink';
import {mouseBus, MouseEvent} from './inputProxy.js';

export type WheelDir = 'up' | 'down';

export type RegionHandlers = {
	onClick?: (rel: {x: number; y: number}) => void;
	onWheel?: (dir: WheelDir, rel: {x: number; y: number}) => void;
	onDrag?: (rel: {x: number; y: number}) => void;
};

type Region = {
	id: number;
	getBox: () => {top: number; left: number; width: number; height: number} | null;
	handlers: RegionHandlers;
};

type Ctx = {
	register: (r: Omit<Region, 'id'>) => number;
	unregister: (id: number) => void;
	updateHandlers: (id: number, h: RegionHandlers) => void;
};

const MouseCtx = createContext<Ctx | null>(null);

export function MouseProvider({children}: {children: React.ReactNode}) {
	const regions = useRef<Map<number, Region>>(new Map());
	const nextId = useRef(1);

	const register = useCallback((r: Omit<Region, 'id'>) => {
		const id = nextId.current++;
		regions.current.set(id, {...r, id});
		return id;
	}, []);

	const unregister = useCallback((id: number) => {
		regions.current.delete(id);
	}, []);

	const updateHandlers = useCallback((id: number, h: RegionHandlers) => {
		const r = regions.current.get(id);
		if (r) r.handlers = h;
	}, []);

	useEffect(() => {
		const handler = (ev: MouseEvent) => {
			// iterate in reverse registration order so newest (innermost) wins
			const list = Array.from(regions.current.values()).reverse();
			for (const r of list) {
				const box = r.getBox();
				if (!box) continue;
				if (
					ev.x >= box.left + 1 &&
					ev.x <= box.left + box.width &&
					ev.y >= box.top + 1 &&
					ev.y <= box.top + box.height
				) {
					const rel = {x: ev.x - box.left - 1, y: ev.y - box.top - 1};
					if (ev.kind === 'press' && ev.button === 'left' && r.handlers.onClick) {
						r.handlers.onClick(rel);
						return;
					}
					if ((ev.kind === 'wheel-up' || ev.kind === 'wheel-down') && r.handlers.onWheel) {
						r.handlers.onWheel(ev.kind === 'wheel-up' ? 'up' : 'down', rel);
						return;
					}
					if (ev.kind === 'drag' && r.handlers.onDrag) {
						r.handlers.onDrag(rel);
						return;
					}
				}
			}
		};
		mouseBus.on('mouse', handler);
		return () => {
			mouseBus.off('mouse', handler);
		};
	}, []);

	return (
		<MouseCtx.Provider value={{register, unregister, updateHandlers}}>
			{children}
		</MouseCtx.Provider>
	);
}

export function useMouseRegion(
	ref: React.MutableRefObject<DOMElement | null>,
	handlers: RegionHandlers,
): void {
	const ctx = useContext(MouseCtx);
	const idRef = useRef<number>(0);
	const handlersRef = useRef<RegionHandlers>(handlers);
	handlersRef.current = handlers;

	useEffect(() => {
		if (!ctx) return;
		const id = ctx.register({
			getBox: () => {
				const node = ref.current;
				if (!node) return null;
				let top = 0;
				let left = 0;
				let cur: any = node;
				while (cur && cur.yogaNode) {
					top += cur.yogaNode.getComputedTop() || 0;
					left += cur.yogaNode.getComputedLeft() || 0;
					cur = cur.parentNode;
				}
				const {width, height} = measureElement(node);
				if (!width || !height) return null;
				return {top, left, width, height};
			},
			handlers: {
				onClick: (rel) => handlersRef.current.onClick?.(rel),
				onWheel: (d, rel) => handlersRef.current.onWheel?.(d, rel),
				onDrag: (rel) => handlersRef.current.onDrag?.(rel),
			},
		});
		idRef.current = id;
		return () => {
			ctx.unregister(id);
		};
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, []);
}
