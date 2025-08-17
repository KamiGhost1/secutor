import React from 'react';
import {Box, Text} from 'ink';

export type FKey = {key: string; label: string; color?: string};

export function FunctionBar({keys}: {keys: FKey[]}) {
	return (
		<Box borderStyle="single" borderColor="gray" paddingX={1}>
			{keys.map((k, i) => (
				<Box key={i} marginRight={2}>
					<Text color="yellow" bold>
						{k.key}
					</Text>
					<Text> </Text>
					<Text color={k.color || 'white'}>{k.label}</Text>
				</Box>
			))}
		</Box>
	);
}
