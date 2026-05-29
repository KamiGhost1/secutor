import React, {useEffect, useMemo, useRef, useState} from 'react';
import fs from 'fs';
import path from 'path';
import os from 'os';
import {Box, DOMElement, Text, useInput} from 'ink';
import TextInput from 'ink-text-input';
import {useMouseRegion} from '../input/mouseRegions.js';
import {useT} from '../i18n/LocaleProvider.js';

export type FileExplorerMode = 'open' | 'save';

type Entry = {name: string; isDir: boolean; size: number; mtime: Date};

function listDir(dir: string): Entry[] {
	try {
		const items = fs.readdirSync(dir, {withFileTypes: true});
		const entries: Entry[] = items.map(d => {
			let st: fs.Stats | null = null;
			try {
				st = fs.statSync(path.join(dir, d.name));
			} catch {}
			return {
				name: d.name,
				isDir: d.isDirectory(),
				size: st?.size ?? 0,
				mtime: st?.mtime ?? new Date(0),
			};
		});
		entries.sort((a, b) => {
			if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
			return a.name.localeCompare(b.name);
		});
		return entries;
	} catch {
		return [];
	}
}

function formatSize(n: number): string {
	if (n < 1024) return `${n}B`;
	if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}K`;
	if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)}M`;
	return `${(n / 1024 / 1024 / 1024).toFixed(1)}G`;
}

export function FileExplorer({
	mode,
	startDir,
	defaultFileName,
	onSelect,
	onCancel,
	title,
	pageSize = 14,
	filter,
}: {
	mode: FileExplorerMode;
	startDir?: string;
	defaultFileName?: string;
	onSelect: (fullPath: string) => void;
	/**
	 * **Owns Esc on the screen it lives on.** Don't also add a screen-level
	 * `useInput((_, k) => { if (k.escape) pop() })` while this widget is
	 * mounted — Ink's useInput is global, both handlers fire on one Esc,
	 * and the route stack pops twice. See the same note next to
	 * `Menu.onCancel` / `Confirm.onCancel`.
	 */
	onCancel: () => void;
	title?: string;
	pageSize?: number;
	filter?: (e: Entry) => boolean;
}) {
	const t = useT();
	const initialCwd = startDir && fs.existsSync(startDir) ? startDir : os.homedir();
	const [cwd, setCwd] = useState<string>(initialCwd);
	const [entries, setEntries] = useState<Entry[]>(() => listDir(initialCwd));
	const [idx, setIdx] = useState(0);
	const [filename, setFilename] = useState(defaultFileName || '');
	const [editingName, setEditingName] = useState(false);

	const filtered = useMemo(
		() => (filter ? entries.filter(filter) : entries),
		[entries, filter],
	);

	const listRef = useRef<DOMElement | null>(null);
	const startRef = useRef(0);

	useEffect(() => {
		setEntries(listDir(cwd));
		setIdx(0);
	}, [cwd]);

	useInput(
		(input, key) => {
			if (editingName) return;
			if (key.escape) return onCancel();

			if (key.upArrow) setIdx(i => (i - 1 + filtered.length) % Math.max(1, filtered.length));
			else if (key.downArrow) setIdx(i => (i + 1) % Math.max(1, filtered.length));
			else if (key.pageUp) setIdx(i => Math.max(0, i - pageSize));
			else if (key.pageDown) setIdx(i => Math.min(filtered.length - 1, i + pageSize));
			else if (input === 'h' || key.leftArrow) {
				const parent = path.dirname(cwd);
				if (parent !== cwd) setCwd(parent);
			} else if (key.return || input === 'l' || key.rightArrow) {
				const e = filtered[idx];
				if (!e) return;
				if (e.isDir) setCwd(path.join(cwd, e.name));
				else if (mode === 'open') onSelect(path.join(cwd, e.name));
				else {
					setFilename(e.name);
				}
			} else if (input === 'n' && mode === 'save') {
				setEditingName(true);
			} else if (input === 's' && mode === 'save' && filename) {
				onSelect(path.join(cwd, filename));
			} else if (input === '~') {
				setCwd(os.homedir());
			} else if (input === '/') {
				setCwd(path.parse(cwd).root || '/');
			}
		},
		{isActive: !editingName},
	);

	useMouseRegion(listRef, {
		onWheel: (dir) => {
			if (!filtered.length) return;
			if (dir === 'up') setIdx(i => Math.max(0, i - 1));
			else setIdx(i => Math.min(filtered.length - 1, i + 1));
		},
		onClick: (rel) => {
			if (!filtered.length) return;
			const clicked = startRef.current + rel.y;
			if (clicked < 0 || clicked >= filtered.length) return;
			const e = filtered[clicked];
			if (clicked === idx) {
				if (e.isDir) setCwd(path.join(cwd, e.name));
				else if (mode === 'open') onSelect(path.join(cwd, e.name));
				else setFilename(e.name);
			} else {
				setIdx(clicked);
			}
		},
	});

	const start = Math.max(
		0,
		Math.min(idx - Math.floor(pageSize / 2), Math.max(0, filtered.length - pageSize)),
	);
	startRef.current = start;
	const visible = filtered.slice(start, start + pageSize);

	return (
		<Box flexDirection="column">
			<Box>
				<Text bold color="cyan">
					{title || (mode === 'open' ? t('files.openTitle') : t('files.saveTitle'))}
				</Text>
			</Box>
			<Box>
				<Text color="gray">{cwd}</Text>
			</Box>
			<Box ref={listRef} flexDirection="column" borderStyle="single" borderColor="gray" paddingX={1}>
				{visible.length === 0 ? (
					<Text color="gray">— empty —</Text>
				) : (
					visible.map((e, i) => {
						const realIdx = start + i;
						const focused = realIdx === idx;
						const name = e.isDir ? e.name + '/' : e.name;
						return (
							<Box key={realIdx} justifyContent="space-between">
								<Text
									color={focused ? 'black' : e.isDir ? 'cyan' : 'white'}
									backgroundColor={focused ? 'cyan' : undefined}
									bold={focused}
								>
									{focused ? '▶ ' : '  '}
									{name}
								</Text>
								<Text color="gray">
									{e.isDir ? '<DIR>' : formatSize(e.size)}
								</Text>
							</Box>
						);
					})
				)}
			</Box>
			{mode === 'save' && (
				<Box marginTop={1}>
					<Text color="gray">{t('files.filename')}: </Text>
					{editingName ? (
						<TextInput
							value={filename}
							onChange={setFilename}
							onSubmit={() => setEditingName(false)}
						/>
					) : (
						<Text color={filename ? 'white' : 'gray'}>
							{filename || t('files.pressNToEnter')}
						</Text>
					)}
				</Box>
			)}
			<Box marginTop={1}>
				<Text color="gray">
					{t('files.help', {save: mode === 'save' ? 'n/s · ' : ''})}
				</Text>
			</Box>
		</Box>
	);
}
