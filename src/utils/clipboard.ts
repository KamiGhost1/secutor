import {spawnSync} from 'child_process';

type Candidate = {cmd: string; args: string[]};

function candidates(): Candidate[] {
	if (process.platform === 'darwin') {
		return [{cmd: 'pbcopy', args: []}];
	}
	if (process.platform === 'win32') {
		return [{cmd: 'clip', args: []}];
	}
	const list: Candidate[] = [];
	if (process.env.WAYLAND_DISPLAY) {
		list.push({cmd: 'wl-copy', args: []});
	}
	list.push({cmd: 'xclip', args: ['-selection', 'clipboard']});
	list.push({cmd: 'xsel', args: ['--clipboard', '--input']});
	if (!process.env.WAYLAND_DISPLAY) {
		list.push({cmd: 'wl-copy', args: []});
	}
	return list;
}

export function copyToClipboard(text: string): {ok: true; via: string} | {ok: false; error: string} {
	const errors: string[] = [];
	for (const c of candidates()) {
		try {
			const res = spawnSync(c.cmd, c.args, {input: text, encoding: 'utf8'});
			if (res.error) {
				errors.push(`${c.cmd}: ${(res.error as NodeJS.ErrnoException).code || res.error.message}`);
				continue;
			}
			if (res.status === 0) return {ok: true, via: c.cmd};
			errors.push(`${c.cmd}: exit ${res.status} ${res.stderr?.trim() || ''}`);
		} catch (e: any) {
			errors.push(`${c.cmd}: ${e.message}`);
		}
	}
	return {ok: false, error: errors.join('; ') || 'no clipboard helper found'};
}
