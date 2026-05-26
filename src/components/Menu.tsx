import React, {useEffect, useMemo, useRef, useState} from 'react';
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
	searchable = false,
	searchPlaceholder,
	searchCorpus,
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
	searchable?: boolean;
	searchPlaceholder?: string;
	searchCorpus?: (item: MenuItem<V>) => string;
}) {
	const [searchMode, setSearchMode] = useState(false);
	const [query, setQuery] = useState('');

	const corpus = searchCorpus ?? ((it: MenuItem<V>) => `${it.label} ${it.hint ?? ''}`);
	const filtered = useMemo(() => {
		if (!query) return items.map((it, i) => ({it, origIdx: i}));
		const q = query.toLowerCase();
		return items
			.map((it, i) => ({it, origIdx: i}))
			.filter(({it}) => corpus(it).toLowerCase().includes(q));
	}, [items, query, corpus]);

	const findEnabled = (from: number, dir: 1 | -1, wrap: boolean): number => {
		if (!filtered.length) return from;
		let i = from;
		for (let n = 0; n < filtered.length; n++) {
			i = i + dir;
			if (i < 0 || i >= filtered.length) {
				if (!wrap) return from;
				i = (i + filtered.length) % filtered.length;
			}
			if (!filtered[i]?.it.disabled) return i;
		}
		return from;
	};
	const findEnabledFrom = (from: number, dir: 1 | -1): number => {
		if (!filtered.length) return 0;
		if (!filtered[from]?.it.disabled) return from;
		const found = findEnabled(from, dir, true);
		return found;
	};
	const stepBy = (from: number, delta: number): number => {
		const target = Math.max(0, Math.min(filtered.length - 1, from + delta));
		if (!filtered[target]?.it.disabled) return target;
		const dir = delta >= 0 ? 1 : -1;
		const found = findEnabled(target, dir as 1 | -1, false);
		if (found === target && filtered[target]?.it.disabled) {
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
		if (idx >= filtered.length && filtered.length > 0) setIdx(filtered.length - 1);
		else if (filtered.length === 0) setIdx(0);
	}, [filtered.length, idx]);

	useInput(
		(input, key) => {
			if (!filtered.length) {
				if (searchMode) {
					if (key.escape) {
						setSearchMode(false);
						setQuery('');
						return;
					}
					if (key.backspace || key.delete) {
						setQuery(q => q.slice(0, -1));
						return;
					}
					if (input && !key.ctrl && !key.meta && input.length === 1) {
						setQuery(q => q + input);
						return;
					}
					return;
				}
				if (searchable && input === '/') {
					setSearchMode(true);
					return;
				}
				if (key.escape && onCancel) onCancel();
				else if (onAction) onAction(input, key, null);
				return;
			}
			if (key.upArrow) setIdx(i => findEnabled(i, -1, true));
			else if (key.downArrow) setIdx(i => findEnabled(i, 1, true));
			else if (key.pageUp) setIdx(i => stepBy(i, -effectivePageSize));
			else if (key.pageDown) setIdx(i => stepBy(i, effectivePageSize));
			else if (key.return) {
				const entry = filtered[idx];
				if (entry && !entry.it.disabled) onSelect(entry.it.value, entry.origIdx);
			} else if (searchMode) {
				if (key.escape) {
					setSearchMode(false);
					setQuery('');
					setIdx(findEnabledFrom(0, 1));
				} else if (key.backspace || key.delete) {
					setQuery(q => q.slice(0, -1));
					setIdx(0);
				} else if (input && !key.ctrl && !key.meta && input.length === 1) {
					setQuery(q => q + input);
					setIdx(0);
				}
			} else if (searchable && input === '/') {
				setSearchMode(true);
			} else if (input === 'g' && !key.ctrl) setIdx(findEnabledFrom(0, 1));
			else if (input === 'G') setIdx(findEnabledFrom(filtered.length - 1, -1));
			else if (key.escape && onCancel) onCancel();
			else if (onAction) {
				const entry = filtered[idx];
				onAction(input, key, entry?.it || null);
			}
		},
		{isActive},
	);

	useMouseRegion(listRef, {
		onWheel: (dir) => {
			if (!filtered.length) return;
			setIdx(i => findEnabled(i, dir === 'up' ? -1 : 1, false));
		},
		onClick: (rel) => {
			if (!filtered.length) return;
			const clicked = startRef.current + rel.y;
			if (clicked < 0 || clicked >= filtered.length) return;
			const entry = filtered[clicked];
			if (!entry || entry.it.disabled) {
				setIdx(clicked);
				return;
			}
			if (clicked === idx) onSelect(entry.it.value, entry.origIdx);
			else setIdx(clicked);
		},
	});

	const start = Math.max(
		0,
		Math.min(idx - Math.floor(effectivePageSize / 2), Math.max(0, filtered.length - effectivePageSize)),
	);
	startRef.current = start;
	const visible = filtered.slice(start, start + effectivePageSize);

	return (
		<Box flexDirection="column">
			{title && (
				<Text bold color="cyan">
					{title}
				</Text>
			)}
			{(searchMode || query) && (
				<Box>
					<Text color={searchMode ? 'yellow' : 'gray'}>
						{'/'}
						{query}
						{searchMode ? '▏' : ''}
					</Text>
					{!query && searchMode && searchPlaceholder && (
						<Text color="gray"> {searchPlaceholder}</Text>
					)}
				</Box>
			)}
			<Box ref={listRef} flexDirection="column">
				{filtered.length === 0 ? (
					<Box paddingY={1}>
						<Text color="gray">{query ? '— no matches —' : (emptyText || '— empty —')}</Text>
					</Box>
				) : (
					visible.map((entry, i) => {
						const realIdx = start + i;
						const focused = realIdx === idx;
						const it = entry.it;
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
			{filtered.length > effectivePageSize && (
				<Text color="gray">
					{idx + 1}/{filtered.length}
					{query ? ` (filtered from ${items.length})` : ''}
				</Text>
			)}
			{footer && <Box marginTop={1}>{footer}</Box>}
		</Box>
	);
}
