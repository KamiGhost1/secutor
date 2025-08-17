import React, {useEffect, useRef, useState} from 'react';
import {Box, DOMElement, Text, useInput, Key} from 'ink';
import {useMouseRegion} from '../input/mouseRegions.js';
import {useTerminalSize} from '../state/useTerminalSize.js';

export type MenuItem<V> = {
	label: string;
	value: V;
	hint?: string;
	disabled?: boolean;
};

export function Menu<V>({
	items,
	onSelect,
	onCancel,
	onAction,
	title,
	emptyText,
	footer,
	itemRenderer,
	pageSize,
	isActive = true,
}: {
	items: MenuItem<V>[];
	onSelect: (v: V, idx: number) => void;
	onCancel?: () => void;
	onAction?: (input: string, key: Key, item: MenuItem<V> | null) => void;
	title?: string;
	emptyText?: string;
	footer?: React.ReactNode;
	itemRenderer?: (item: MenuItem<V>, focused: boolean) => React.ReactNode;
	pageSize?: number;
	isActive?: boolean;
}) {
	const findEnabled = (from: number, dir: 1 | -1, wrap: boolean): number => {
		if (!items.length) return from;
		let i = from;
		for (let n = 0; n < items.length; n++) {
			i = i + dir;
			if (i < 0 || i >= items.length) {
				if (!wrap) return from;
				i = (i + items.length) % items.length;
			}
			if (!items[i]?.disabled) return i;
		}
		return from;
	};
	const findEnabledFrom = (from: number, dir: 1 | -1): number => {
		if (!items.length) return 0;
		if (!items[from]?.disabled) return from;
		const found = findEnabled(from, dir, true);
		return found;
	};
	const stepBy = (from: number, delta: number): number => {
		const target = Math.max(0, Math.min(items.length - 1, from + delta));
		if (!items[target]?.disabled) return target;
		const dir = delta >= 0 ? 1 : -1;
		const found = findEnabled(target, dir as 1 | -1, false);
		// If we couldn't find a non-disabled item in the direction we were paging,
		// search backwards from `target` so we still move closer to the goal.
		if (found === target && items[target]?.disabled) {
			return findEnabled(target, (-dir) as 1 | -1, false);
		}
		return found;
	};

	const [idx, setIdx] = useState(() => findEnabledFrom(0, 1));
	const listRef = useRef<DOMElement | null>(null);
	const startRef = useRef(0);
	const {rows} = useTerminalSize();
	// Overhead: header (3) + padding (2) + fbar (3) = 8; leave buffer for title/counter
	const effectivePageSize = pageSize ?? Math.max(3, rows - 8);

	useEffect(() => {
		if (idx >= items.length && items.length > 0) setIdx(items.length - 1);
	}, [items.length, idx]);

	useInput(
		(input, key) => {
			if (!items.length) {
				if (key.escape && onCancel) onCancel();
				else if (onAction) onAction(input, key, null);
				return;
			}
			if (key.upArrow) setIdx(i => findEnabled(i, -1, true));
			else if (key.downArrow) setIdx(i => findEnabled(i, 1, true));
			else if (key.pageUp) setIdx(i => stepBy(i, -effectivePageSize));
			else if (key.pageDown) setIdx(i => stepBy(i, effectivePageSize));
			else if (input === 'g' && !key.ctrl) setIdx(findEnabledFrom(0, 1));
			else if (input === 'G') setIdx(findEnabledFrom(items.length - 1, -1));
			else if (key.return) {
				const item = items[idx];
				if (item && !item.disabled) onSelect(item.value, idx);
			} else if (key.escape && onCancel) onCancel();
			else if (onAction) onAction(input, key, items[idx] || null);
		},
		{isActive},
	);

	useMouseRegion(listRef, {
		onWheel: (dir) => {
			if (!items.length) return;
			setIdx(i => findEnabled(i, dir === 'up' ? -1 : 1, false));
		},
		onClick: (rel) => {
			if (!items.length) return;
			const clicked = startRef.current + rel.y;
			if (clicked < 0 || clicked >= items.length) return;
			const item = items[clicked];
			if (!item || item.disabled) {
				setIdx(clicked);
				return;
			}
			if (clicked === idx) onSelect(item.value, clicked);
			else setIdx(clicked);
		},
	});

	const start = Math.max(
		0,
		Math.min(idx - Math.floor(effectivePageSize / 2), Math.max(0, items.length - effectivePageSize)),
	);
	startRef.current = start;
	const visible = items.slice(start, start + effectivePageSize);

	return (
		<Box flexDirection="column">
			{title && (
				<Text bold color="cyan">
					{title}
				</Text>
			)}
			<Box ref={listRef} flexDirection="column">
				{items.length === 0 ? (
					<Box paddingY={1}>
						<Text color="gray">{emptyText || '— empty —'}</Text>
					</Box>
				) : (
					visible.map((it, i) => {
						const realIdx = start + i;
						const focused = realIdx === idx;
						if (itemRenderer) {
							return (
								<Box key={realIdx}>{itemRenderer(it, focused)}</Box>
							);
						}
						return (
							<Box key={realIdx}>
								<Text
									color={
										it.disabled ? 'gray' : focused ? 'black' : 'white'
									}
									backgroundColor={focused ? 'cyan' : undefined}
									bold={focused}
								>
									{focused ? '▶ ' : '  '}
									{it.label}
									{it.hint ? `  · ${it.hint}` : ''}
								</Text>
							</Box>
						);
					})
				)}
			</Box>
			{items.length > effectivePageSize && (
				<Text color="gray">
					{idx + 1}/{items.length}
				</Text>
			)}
			{footer && <Box marginTop={1}>{footer}</Box>}
		</Box>
	);
}
