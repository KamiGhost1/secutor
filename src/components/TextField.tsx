import React, {useRef} from 'react';
import {Box, Text, useFocus, useInput} from 'ink';
import TextInput from 'ink-text-input';

export type TextFieldProps = {
	label: string;
	value: string;
	onChange: (v: string) => void;
	onSubmit?: (v: string) => void;
	placeholder?: string;
	mask?: string;
	id?: string;
	autoFocus?: boolean;
	width?: number;
};

export function TextField({
	label,
	value,
	onChange,
	onSubmit,
	placeholder,
	mask,
	id,
	autoFocus,
	width = 40,
}: TextFieldProps) {
	const {isFocused} = useFocus({id, autoFocus});
	// ink-text-input only suppresses Ctrl+C; other Ctrl+letter combos are inserted
	// as plain letters into the input. Track ctrl presses on this focused field and
	// filter them out before the change reaches the consumer.
	const lastCtrlRef = useRef(false);
	useInput(
		(_input, key) => {
			lastCtrlRef.current = key.ctrl;
		},
		{isActive: isFocused},
	);
	const filteredOnChange = (next: string) => {
		if (lastCtrlRef.current) return;
		onChange(next);
	};
	return (
		<Box flexDirection="row">
			<Box width={20} flexShrink={0}>
				<Text color={isFocused ? 'cyan' : 'gray'} wrap="truncate-end">
					{isFocused ? '› ' : '  '}
					{label}
				</Text>
			</Box>
			<Box
				borderStyle={isFocused ? 'bold' : 'single'}
				borderColor={isFocused ? 'cyan' : 'gray'}
				paddingX={1}
				width={width}
			>
				{isFocused ? (
					<TextInput
						value={value}
						onChange={filteredOnChange}
						onSubmit={onSubmit}
						placeholder={placeholder}
						mask={mask}
					/>
				) : (
					<Text color={value ? 'white' : 'gray'}>
						{value ? (mask ? mask.repeat(value.length) : value) : placeholder || ' '}
					</Text>
				)}
			</Box>
		</Box>
	);
}

export function PasswordField(props: Omit<TextFieldProps, 'mask'>) {
	return <TextField {...props} mask="•" />;
}
