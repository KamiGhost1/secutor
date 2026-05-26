import React from 'react';
import {Box, Text, useFocus, useInput} from 'ink';
import {KeyAlgorithm, SIGNING_ALGORITHMS} from '../certs/keys.js';

export type AlgorithmPickerProps = {
	label: string;
	value: KeyAlgorithm;
	onChange: (v: KeyAlgorithm) => void;
	/** Restrict the cycle to a subset (e.g. signing-only). Defaults to all signing algorithms. */
	choices?: KeyAlgorithm[];
	id?: string;
	autoFocus?: boolean;
	/**
	 * If true (default), arrow-left/right also cycles. Useful inside a column-of-fields
	 * form where the user is already navigating up/down through fields.
	 */
	arrowCycles?: boolean;
};

const DEFAULT_CHOICES: KeyAlgorithm[] = SIGNING_ALGORITHMS;

const PRETTY: Record<KeyAlgorithm, string> = {
	'rsa-2048': 'RSA 2048',
	'rsa-3072': 'RSA 3072',
	'rsa-4096': 'RSA 4096',
	'ecdsa-p256': 'ECDSA P-256',
	'ecdsa-p384': 'ECDSA P-384',
	'ed25519': 'Ed25519',
	'x25519': 'X25519',
};

/**
 * Inline single-line algorithm chooser. Cycle with Ctrl-K or ←/→ when focused.
 * Designed to drop into a column-of-fields form alongside `<TextField>`s.
 */
export function AlgorithmPicker({
	label,
	value,
	onChange,
	choices = DEFAULT_CHOICES,
	id,
	autoFocus,
	arrowCycles = true,
}: AlgorithmPickerProps) {
	const {isFocused} = useFocus({id, autoFocus});

	useInput(
		(input, key) => {
			const cycle = (delta: 1 | -1) => {
				const idx = Math.max(0, choices.indexOf(value));
				const next = (idx + delta + choices.length) % choices.length;
				onChange(choices[next]!);
			};
			if (key.ctrl && (input === 'k' || input === 'K')) cycle(1);
			else if (arrowCycles && key.leftArrow) cycle(-1);
			else if (arrowCycles && key.rightArrow) cycle(1);
		},
		{isActive: isFocused},
	);

	return (
		<Box flexDirection="row">
			<Box width={20} flexShrink={0}>
				<Text color={isFocused ? 'cyan' : 'gray'}>
					{isFocused ? '› ' : '  '}
					{label}
				</Text>
			</Box>
			<Box
				borderStyle={isFocused ? 'bold' : 'single'}
				borderColor={isFocused ? 'cyan' : 'gray'}
				paddingX={1}
				width={40}
			>
				<Text>
					{PRETTY[value] ?? value}
					<Text color="gray">  ·  Ctrl+K / ←/→</Text>
				</Text>
			</Box>
		</Box>
	);
}
