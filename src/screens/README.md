# Screens — author's checklist

## Esc / `useInput` gotcha — read this before adding a new screen

Ink's `useInput` is **process-global, not focus-scoped**. Every mounted
`useInput` callback fires for every keypress. That means if your screen does

```tsx
useInput((_, key) => { if (key.escape) pop(); });

return (
  <Menu items={...} onCancel={pop} />
);
```

…then **one Esc keypress calls `pop()` twice** — the user lands two screens
back instead of one. The same bug fires for `<FileExplorer onCancel={pop} />`
and `<Confirm onCancel={pop} />`.

### Rule

Let the child widget own Esc. Only add a screen-level `useInput((_, k) =>
{ if (k.escape) pop() })` for states where **no** Menu/FileExplorer/Confirm
is mounted — and gate it on that state so it doesn't double-fire once the
widget appears.

### Templates

**Always-has-Menu screen:**

```tsx
// Esc is owned by Menu.onCancel — don't duplicate it here.
useInput((input, _key) => {
  if (input === 'a') push({kind: 'add-something'});
});

return <Menu items={items} onSelect={...} onCancel={pop} />;
```

**Loading-then-Menu screen:**

```tsx
useInput((input, key) => {
  if (rows == null && key.escape) { pop(); return; } // only while loading
  if (input === 'r') setTick(t => t + 1);
});

return rows == null
  ? <Text>loading…</Text>
  : <Menu items={rows.map(...)} onSelect={...} onCancel={pop} />;
```

**Multi-step screen with a terminal "done" view:**

```tsx
// Menu / FileExplorer own Esc on interactive steps. The terminal 'done'
// view renders only Text, so Esc lives here.
useInput((_, key) => {
  if (step.kind === 'done' && key.escape) pop();
});
```

## Other recurring gotchas

- **Mutation of `ctx.ca`**: `CaStore.promote()` does `Object.assign(ca,
  newFields)`. Don't cache `ctx.ca.certPem` into a local — re-read the
  field at use-site so post-promote requests see the new bytes.
- **`process.env.SECUTOR_HOME` is lazy**: paths in `src/storage/paths.ts`
  resolve via `rootDir()`/`contextsDir()`/`metaFile()` (functions, not
  constants). Tests can swap `SECUTOR_HOME` between cases and the next
  call sees the new value. Do not capture `rootDir()` into a module-level
  const.
- **`useArrowFocus()` takes no args** (see `components/Form.tsx`). It
  wires `↑/↓` to ink's focus manager and returns void. Earlier code
  destructured a fake tuple from it — TS catches that, don't be tempted
  to recreate.
