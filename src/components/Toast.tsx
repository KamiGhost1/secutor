import React from 'react';
import {Box, Text} from 'ink';
import {useApp} from '../state/AppContext.js';

export function ToastBar() {
	const {toast} = useApp();
	if (!toast) return null;
	const color =
		toast.kind === 'error'
			? 'red'
			: toast.kind === 'success'
			? 'green'
			: 'cyan';
	return (
		<Box paddingX={1}>
			<Text color={color}>● {toast.message}</Text>
		</Box>
	);
}
