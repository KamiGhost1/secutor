import React, {
	createContext,
	useCallback,
	useContext,
	useEffect,
	useMemo,
	useState,
} from 'react';
import {Box, Text} from 'ink';
import {useTerminalSize} from '../state/useTerminalSize.js';

/**
 * Lightweight focus-tracking + scrolling for long forms.
 *
 * Tall forms used to overflow short terminals and Yoga responded by shrinking
 * each row — borders collapsed, inputs slid off the edge. `<ScrollableForm>`
 * wraps the rows in a fixed-height viewport that clips overflow, and slides
 * the inner column up/down to keep the currently focused field on screen.
 *
 * All children are kept mounted, so Ink's focus manager can still Tab to
 * fields outside the visible window — the form just scrolls them into view
 * once they take focus.
 *
 * Focus reporting is opt-in: focusable widgets call `useReportFocus(id, isFocused)`
 * and, when a `<ScrollableForm>` wraps them, the form learns which row is
 * active. Without a provider above, the hook is a no-op (so widgets remain
 * usable in screens that don't need scrolling).
 */

type FormFocusReporter = (id: string) => void;

const FormFocusCtx = createContext<FormFocusReporter | null>(null);

export function useReportFocus(id: string | undefined, isFocused: boolean): void {
	const report = useContext(FormFocusCtx);
	useEffect(() => {
		if (report && id && isFocused) report(id);
	}, [report, id, isFocused]);
}

/**
 * Walk a React subtree and collect every string `id` prop found on it (the
 * element itself and any descendant). Used so that focusable widgets nested
 * inside a wrapper row — e.g. the two `<Button>`s that share the bottom
 * "Submit / Cancel" row — still resolve back to their parent row's index in
 * `ScrollableForm`. Without this, pressing Up at the top field wraps focus
 * onto the Submit button but the viewport stays parked at row 0.
 *
 * Exported for unit testing.
 */
export function collectDescendantIds(node: React.ReactNode): string[] {
	const out: string[] = [];
	const walk = (n: React.ReactNode): void => {
		if (n == null || typeof n === 'boolean') return;
		if (Array.isArray(n)) {
			n.forEach(walk);
			return;
		}
		if (!React.isValidElement(n)) return;
		const props = n.props as {id?: unknown; children?: React.ReactNode};
		if (typeof props.id === 'string') out.push(props.id);
		if (props.children !== undefined) {
			React.Children.forEach(props.children, walk);
		}
	};
	walk(node);
	return out;
}

/**
 * Pure helper: given the currently focused row, how many rows tall the
 * viewport is, and the total row count, return how many rows to shift the
 * inner column upward so the focused row lands near the middle of the
 * viewport (and never outside it). Exported for unit testing.
 */
export function computeScrollOffset(
	focusedIdx: number,
	totalRows: number,
	maxRows: number,
): number {
	if (totalRows <= maxRows) return 0;
	const half = Math.floor(maxRows / 2);
	return Math.max(0, Math.min(totalRows - maxRows, focusedIdx - half));
}

export type ScrollableFormProps = {
	children: React.ReactNode;
	/**
	 * Fixed vertical height (in terminal rows) for each child slot.
	 * Bordered widgets (TextField, AlgorithmPicker, Button) all need 3 rows;
	 * decorative single-line children (gray hint texts) get padded out.
	 * Default: 3.
	 */
	rowHeight?: number;
	/**
	 * Approximate number of terminal rows consumed by the surrounding chrome
	 * — header, outer padding, error line, submit-button row, function bar.
	 * Used to derive `maxRows` from the live terminal height when `maxRows`
	 * isn't given explicitly. Default: 12.
	 */
	chromeLines?: number;
	/**
	 * Hard override for the number of rows visible at once. When supplied,
	 * `chromeLines` is ignored.
	 */
	maxRows?: number;
};

/**
 * Layout sketch:
 *
 *   ┌─────────── form ──────────────┐
 *   │ ▲ N more above                │ ← shown only when scrolled past top
 *   │ ┌── viewport ────────────────┐│
 *   │ │ <row i>                    ││
 *   │ │ <row i+1>                  ││  height = maxRows * rowHeight,
 *   │ │ ...                        ││  overflow="hidden"
 *   │ └────────────────────────────┘│
 *   │ ▼ M more below                │ ← shown only when scrolled past bottom
 *   └───────────────────────────────┘
 *
 * Inner column is shifted by `marginTop = -scrollOffset * rowHeight` so the
 * focused field stays within the clip rect.
 */
export function ScrollableForm({
	children,
	rowHeight = 3,
	chromeLines = 12,
	maxRows,
}: ScrollableFormProps) {
	const {rows: termRows} = useTerminalSize();

	const childArr = useMemo(
		// React.Children.toArray already strips null / false / undefined; the
		// extra guard here just keeps TypeScript happy and tolerates any
		// stray empty fragments callers might pass in.
		() => React.Children.toArray(children).filter(c => c != null),
		[children],
	);

	const idToIndex = useMemo(() => {
		// Map every focusable id — including ones nested inside row wrappers
		// such as the bottom Submit/Cancel button row — back to its top-level
		// row index. Without the recursive walk, focus wrapping around onto a
		// nested Button would not move the scroll viewport.
		const m = new Map<string, number>();
		childArr.forEach((c, i) => {
			for (const id of collectDescendantIds(c)) m.set(id, i);
		});
		return m;
	}, [childArr]);

	const [focusedIdx, setFocusedIdx] = useState(0);
	const reportFocus = useCallback<FormFocusReporter>(
		id => {
			const i = idToIndex.get(id);
			if (i != null) setFocusedIdx(i);
		},
		[idToIndex],
	);

	const computedMaxRows =
		maxRows ?? Math.max(2, Math.floor((termRows - chromeLines) / rowHeight));
	const totalRows = childArr.length;
	const needScroll = totalRows > computedMaxRows;

	const scrollOffset = needScroll
		? computeScrollOffset(focusedIdx, totalRows, computedMaxRows)
		: 0;

	const viewportHeight = needScroll
		? computedMaxRows * rowHeight
		: totalRows * rowHeight;
	const hiddenAbove = scrollOffset;
	const hiddenBelow = needScroll
		? Math.max(0, totalRows - scrollOffset - computedMaxRows)
		: 0;

	return (
		<FormFocusCtx.Provider value={reportFocus}>
			<Box flexDirection="column" flexShrink={0}>
				{hiddenAbove > 0 && (
					<Box flexShrink={0}>
						<Text color="gray">
							▲ {hiddenAbove} more above
						</Text>
					</Box>
				)}
				<Box
					height={viewportHeight}
					overflow="hidden"
					flexDirection="column"
					flexShrink={0}
				>
					<Box
						flexDirection="column"
						marginTop={-scrollOffset * rowHeight}
						flexShrink={0}
					>
						{childArr.map((c, i) => (
							<Box
								key={i}
								height={rowHeight}
								flexShrink={0}
								flexDirection="column"
							>
								{c}
							</Box>
						))}
					</Box>
				</Box>
				{hiddenBelow > 0 && (
					<Box flexShrink={0}>
						<Text color="gray">
							▼ {hiddenBelow} more below
						</Text>
					</Box>
				)}
			</Box>
		</FormFocusCtx.Provider>
	);
}
