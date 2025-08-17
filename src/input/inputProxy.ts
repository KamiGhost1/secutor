import {PassThrough} from 'stream';
import {EventEmitter} from 'events';

export type MouseEvent = {
	kind: 'press' | 'release' | 'wheel-up' | 'wheel-down' | 'drag';
	button?: 'left' | 'middle' | 'right';
	x: number; // 1-based column
	y: number; // 1-based row
};

export type FKeyEvent = {name: string};

export const mouseBus = new EventEmitter();
export const fkeyBus = new EventEmitter();

const MOUSE_RE = /\x1b\[<(\d+);(\d+);(\d+)([Mm])/g;
const FKEY_RE = /\x1b\[(11|12|13|14|15|17|18|19|20|21|23|24)~/g;
const FKEY_NAME: Record<string, string> = {
	'11': 'f1', '12': 'f2', '13': 'f3', '14': 'f4',
	'15': 'f5', '17': 'f6', '18': 'f7', '19': 'f8',
	'20': 'f9', '21': 'f10', '23': 'f11', '24': 'f12',
};

function decodeMouse(buttonCode: number, x: number, y: number, mOrM: string): MouseEvent {
	if (buttonCode === 64) return {kind: 'wheel-up', x, y};
	if (buttonCode === 65) return {kind: 'wheel-down', x, y};
	const drag = (buttonCode & 32) !== 0;
	const btn = buttonCode & 3;
	const button = btn === 0 ? 'left' : btn === 1 ? 'middle' : 'right';
	if (drag) return {kind: 'drag', button, x, y};
	return {kind: mOrM === 'M' ? 'press' : 'release', button, x, y};
}

function parseChunk(str: string): {
	filtered: string;
	mouseEvents: MouseEvent[];
	fkeyEvents: FKeyEvent[];
} {
	const mouseEvents: MouseEvent[] = [];
	const fkeyEvents: FKeyEvent[] = [];

	let filtered = str.replace(MOUSE_RE, (_m, b, x, y, mm) => {
		mouseEvents.push(decodeMouse(parseInt(b, 10), parseInt(x, 10), parseInt(y, 10), mm));
		return '';
	});

	filtered = filtered.replace(FKEY_RE, (_m, code) => {
		fkeyEvents.push({name: FKEY_NAME[code]});
		return '';
	});

	return {filtered, mouseEvents, fkeyEvents};
}

export function createInputProxy(): NodeJS.ReadStream {
	const proxy: any = new PassThrough();
	proxy.isTTY = true;
	proxy.setRawMode = (mode: boolean) => {
		try {
			(process.stdin as any).setRawMode?.(mode);
		} catch {}
		return proxy;
	};
	proxy.ref = () => {
		try {
			(process.stdin as any).ref();
		} catch {}
		return proxy;
	};
	proxy.unref = () => {
		try {
			(process.stdin as any).unref();
		} catch {}
		return proxy;
	};

	process.stdin.on('data', (chunk: Buffer) => {
		const str = chunk.toString('binary');
		const {filtered, mouseEvents, fkeyEvents} = parseChunk(str);
		if (filtered) proxy.write(Buffer.from(filtered, 'binary'));
		for (const e of mouseEvents) mouseBus.emit('mouse', e);
		for (const e of fkeyEvents) fkeyBus.emit('fkey', e);
	});

	return proxy as NodeJS.ReadStream;
}

const ENABLE = '\x1b[?1000h\x1b[?1006h';
const DISABLE = '\x1b[?1006l\x1b[?1000l';

export function enableMouse(): void {
	process.stdout.write(ENABLE);
}

export function disableMouse(): void {
	process.stdout.write(DISABLE);
}
