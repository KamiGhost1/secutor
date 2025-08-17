import React, {useState, useCallback} from 'react';
import {Box, Text, useFocusManager, useInput} from 'ink';

export type FieldDef = {
	id: string;
	label: string;
	placeholder?: string;
	password?: boolean;
	required?: boolean;
	default?: string;
	validate?: (v: string, all: Record<string, string>) => string | null;
};

export type FormHandle = {
	values: Record<string, string>;
	setValue: (id: string, v: string) => void;
};

export function useFormState(fields: FieldDef[]): FormHandle {
	const [values, setValues] = useState<Record<string, string>>(() => {
		const init: Record<string, string> = {};
		for (const f of fields) init[f.id] = f.default ?? '';
		return init;
	});
	const setValue = useCallback(
		(id: string, v: string) => setValues(prev => ({...prev, [id]: v})),
		[],
	);
	return {values, setValue};
}

export function FormError({message}: {message: string | null}) {
	if (!message) return null;
	return (
		<Box>
			<Text color="red">⚠ {message}</Text>
		</Box>
	);
}

export function FocusHint() {
	return (
		<Text color="gray">
			↑/↓ или Tab — между полями · Enter — действие · Esc — назад
		</Text>
	);
}

export function useArrowFocus() {
	const fm = useFocusManager();
	useInput((_input, key) => {
		if (key.upArrow) fm.focusPrevious();
		else if (key.downArrow) fm.focusNext();
	});
}
