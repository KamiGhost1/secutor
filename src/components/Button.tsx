import React, {useRef} from 'react';
import {Box, DOMElement, Text, useFocus, useInput, useFocusManager} from 'ink';
import {useMouseRegion} from '../input/mouseRegions.js';
import {useReportFocus} from './ScrollableForm.js';

export function Button({
	label,
	onPress,
	id,
	autoFocus,
	color = 'white',
	disabled,
}: {
	label: string;
	onPress: () => void;
	id?: string;
	autoFocus?: boolean;
	color?: string;
	disabled?: boolean;
}) {
	const {isFocused} = useFocus({id, autoFocus, isActive: !disabled});
	useReportFocus(id, isFocused);
	const fm = useFocusManager();
	const ref = useRef<DOMElement | null>(null);

	useInput(
		(input, key) => {
			if (disabled) return;
			if (isFocused && (key.return || input === ' ')) onPress();
		},
		{isActive: isFocused},
	);

	useMouseRegion(ref, {
		onClick: () => {
			if (disabled) return;
			if (id) fm.focus(id);
			onPress();
		},
	});

	return (
		<Box
			ref={ref}
			borderStyle={isFocused ? 'bold' : 'single'}
			borderColor={isFocused ? 'cyan' : disabled ? 'gray' : 'white'}
			paddingX={1}
			flexShrink={0}
		>
			<Text
				color={disabled ? 'gray' : isFocused ? 'cyan' : color}
				bold={isFocused}
			>
				{isFocused ? '› ' : '  '}
				{label}
				{isFocused ? ' ‹' : '  '}
			</Text>
		</Box>
	);
}
