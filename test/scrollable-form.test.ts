import {test} from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';

import {
	computeScrollOffset,
	collectDescendantIds,
} from '../src/components/ScrollableForm.js';

// `computeScrollOffset(focusedIdx, totalRows, maxRows)` decides how many rows
// the inner column of the ScrollableForm should be shifted up so the focused
// field stays inside the clipping viewport. The rules:
//
//   - if all rows fit (`totalRows <= maxRows`) the offset is 0
//   - otherwise the focused row tries to land near the middle of the viewport
//   - clamped to [0, totalRows - maxRows] so we never scroll past either edge
//
// These tests pin those invariants for typical CreateCAScreen / IssueCert
// shapes (≈ 14 rows in a 5-row viewport).

test('returns 0 when everything fits', () => {
	assert.equal(computeScrollOffset(0, 5, 5), 0);
	assert.equal(computeScrollOffset(4, 5, 5), 0);
	assert.equal(computeScrollOffset(0, 3, 10), 0);
});

test('focusing the first row never scrolls', () => {
	assert.equal(computeScrollOffset(0, 14, 5), 0);
});

test('focusing a middle row centers it in the viewport', () => {
	// maxRows=5 → half=2; focusedIdx=7 → 7-2 = 5
	assert.equal(computeScrollOffset(7, 14, 5), 5);
	// maxRows=4 → half=2; focusedIdx=6 → 6-2 = 4
	assert.equal(computeScrollOffset(6, 14, 4), 4);
});

test('focusing the last row clamps to bottom edge (no over-scroll)', () => {
	// totalRows=14, maxRows=5 → max offset = 9
	assert.equal(computeScrollOffset(13, 14, 5), 9);
	assert.equal(computeScrollOffset(12, 14, 5), 9);
});

test('does not return a negative offset when focus is near the top', () => {
	// focusedIdx=1, half=2, clamped to 0 not -1
	assert.equal(computeScrollOffset(1, 14, 5), 0);
});

test('handles maxRows=1 sanely (focused row is the only visible one)', () => {
	assert.equal(computeScrollOffset(0, 10, 1), 0);
	assert.equal(computeScrollOffset(5, 10, 1), 5);
	assert.equal(computeScrollOffset(9, 10, 1), 9);
});

// ----------------------------------------------------------------------
// collectDescendantIds — needed so focus wrapping around to a nested Button
// (the Submit/Cancel row) still moves the scroll viewport.
// ----------------------------------------------------------------------

test('collectDescendantIds picks up a top-level id', () => {
	const node = React.createElement('div', {id: 'name'});
	assert.deepEqual(collectDescendantIds(node), ['name']);
});

test('collectDescendantIds walks into nested children (button row case)', () => {
	const submit = React.createElement('div', {id: 'submit'});
	const cancel = React.createElement('div', {id: 'cancel'});
	const innerWrap = React.createElement('div', {}, cancel);
	const buttonRow = React.createElement('div', {}, submit, innerWrap);
	assert.deepEqual(collectDescendantIds(buttonRow), ['submit', 'cancel']);
});

test('collectDescendantIds tolerates null/false/array nodes', () => {
	const a = React.createElement('div', {id: 'a'});
	const b = React.createElement('div', {id: 'b'});
	const wrap = React.createElement('div', {}, null, false, [a, b]);
	assert.deepEqual(collectDescendantIds(wrap), ['a', 'b']);
});

test('collectDescendantIds ignores non-string id props', () => {
	const node = React.createElement('div', {id: 42, children: []});
	assert.deepEqual(collectDescendantIds(node), []);
});
