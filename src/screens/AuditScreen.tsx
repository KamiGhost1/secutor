import React, {useMemo, useState} from 'react';
import {Box, Text} from 'ink';
import {Header} from '../components/Header.js';
import {FunctionBar} from '../components/FunctionBar.js';
import {Menu} from '../components/Menu.js';
import {Confirm} from '../components/Confirm.js';
import {useApp} from '../state/AppContext.js';
import {useT} from '../i18n/LocaleProvider.js';
import {certRepo} from '../storage/repos.js';
import {
	auditCertificates,
	AuditReport,
	Finding,
	FindingKind,
	Severity,
	sortFindings,
} from '../certs/audit.js';

type Mode =
	| {kind: 'list'}
	| {kind: 'confirm-all'; count: number}
	| {kind: 'confirm-one'; finding: Finding};

const KIND_LABEL: Record<FindingKind, string> = {
	'parse-error': 'audit.kind.parseError',
	'key-mismatch': 'audit.kind.keyMismatch',
	'meta-drift': 'audit.kind.metaDrift',
	'issuer-not-set': 'audit.kind.issuerNotSet',
	'issuer-missing': 'audit.kind.issuerMissing',
	'issuer-dn-mismatch': 'audit.kind.issuerDnMismatch',
	'signature-invalid': 'audit.kind.signatureInvalid',
	expired: 'audit.kind.expired',
	'not-yet-valid': 'audit.kind.notYetValid',
};

function severityColor(s: Severity): string {
	if (s === 'error') return 'red';
	if (s === 'warn') return 'yellow';
	return 'cyan';
}

function severityIcon(s: Severity): string {
	if (s === 'error') return '✘';
	if (s === 'warn') return '⚠';
	return 'ℹ';
}

const EMPTY_REPORT: AuditReport = {
	findings: [],
	scanned: 0,
	byCert: new Map(),
};

export function AuditScreen() {
	const {pop, showToast} = useApp();
	const t = useT();
	const [tick, setTick] = useState(0);
	const [mode, setMode] = useState<Mode>({kind: 'list'});
	const [scanError, setScanError] = useState<string | null>(null);

	const report = useMemo<AuditReport>(() => {
		try {
			const rows = certRepo.list();
			setScanError(null);
			return auditCertificates(rows);
		} catch (e: any) {
			// Defend against a malformed row crashing the entire screen — show
			// the error inline instead of bubbling up to React.
			setScanError(e?.message || String(e));
			return EMPTY_REPORT;
		}
	}, [tick]);

	const sorted = useMemo(() => sortFindings(report.findings), [report]);
	const fixable = useMemo(() => sorted.filter(f => !!f.fix), [sorted]);

	const counts = useMemo(() => {
		let err = 0,
			warn = 0,
			info = 0;
		for (const f of report.findings) {
			if (f.severity === 'error') err++;
			else if (f.severity === 'warn') warn++;
			else info++;
		}
		return {err, warn, info};
	}, [report]);

	const applyFix = (f: Finding): boolean => {
		if (!f.fix) return false;
		try {
			if (f.fix.kind === 'refresh-meta') {
				certRepo.refreshMeta(f.certId, f.fix.metadata);
			} else if (f.fix.kind === 'relink-issuer') {
				certRepo.relinkIssuer(f.certId, f.fix.newIssuerId);
			}
			return true;
		} catch (e: any) {
			showToast({kind: 'error', message: e.message || 'fix failed'});
			return false;
		}
	};

	const applyAll = () => {
		let n = 0;
		for (const f of fixable) {
			if (applyFix(f)) n++;
		}
		showToast({kind: 'success', message: t('audit.toastFixed', {n})});
		setTick(x => x + 1);
		setMode({kind: 'list'});
	};

	const applyOne = (f: Finding) => {
		if (applyFix(f)) {
			showToast({kind: 'success', message: t('audit.toastFixedOne')});
			setTick(x => x + 1);
		}
		setMode({kind: 'list'});
	};

	if (mode.kind === 'confirm-all') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('audit.title')} />
				<Box padding={1}>
					<Confirm
						message={t('audit.confirmAll', {n: mode.count})}
						onConfirm={applyAll}
						onCancel={() => setMode({kind: 'list'})}
					/>
				</Box>
				<FunctionBar
					keys={[
						{key: 'Y', label: t('common.yes')},
						{key: 'N', label: t('common.no')},
						{key: 'Esc', label: t('fbar.back')},
					]}
				/>
			</Box>
		);
	}

	if (mode.kind === 'confirm-one') {
		return (
			<Box flexDirection="column" flexGrow={1}>
				<Header title={t('audit.title')} />
				<Box padding={1} flexDirection="column">
					<Confirm
						message={describeFix(mode.finding, t)}
						onConfirm={() => applyOne(mode.finding)}
						onCancel={() => setMode({kind: 'list'})}
					/>
				</Box>
				<FunctionBar
					keys={[
						{key: 'Y', label: t('common.yes')},
						{key: 'N', label: t('common.no')},
						{key: 'Esc', label: t('fbar.back')},
					]}
				/>
			</Box>
		);
	}

	const items = sorted.map(f => ({
		label: `${severityIcon(f.severity)} ${f.certName} · ${t(
			(KIND_LABEL[f.kind] || 'audit.kind.parseError') as any,
		)}`,
		value: f,
		hint: f.fix ? t('audit.fixAvailable') : t('audit.noAutoFix'),
	}));

	return (
		<Box flexDirection="column" flexGrow={1}>
			<Header title={t('audit.title')} />
			<Box paddingX={1} flexDirection="column">
				<Text>
					{t('audit.summary', {
						scanned: report.scanned,
						err: counts.err,
						warn: counts.warn,
						info: counts.info,
					})}
				</Text>
				<Text color="gray">
					{t('audit.fixableSummary', {n: fixable.length})}
				</Text>
				{scanError && (
					<Text color="red">⚠ {t('audit.scanError', {err: scanError})}</Text>
				)}
			</Box>
			<Box paddingX={1} flexDirection="column" flexGrow={1}>
				<Menu
					items={items}
					emptyText={t('audit.allHealthy')}
					itemRenderer={(it, focused) => {
						const f = it.value;
						return (
							<Box>
								<Text
									color={focused ? 'black' : severityColor(f.severity)}
									backgroundColor={focused ? 'cyan' : undefined}
									bold={focused}
								>
									{focused ? '▶ ' : '  '}
									{it.label}
									{it.hint ? `  · ${it.hint}` : ''}
								</Text>
							</Box>
						);
					}}
					onSelect={f => {
						if (f.fix) setMode({kind: 'confirm-one', finding: f});
						else
							showToast({
								kind: 'info',
								message: f.detail || f.message,
							});
					}}
					onCancel={pop}
					onAction={(input, _key, item) => {
						if ((input === 'f' || input === 'F') && fixable.length > 0) {
							setMode({kind: 'confirm-all', count: fixable.length});
						} else if (input === 'r' || input === 'R') {
							setTick(x => x + 1);
						} else if (
							(input === 'd' || input === 'D') &&
							item &&
							item.value
						) {
							const f = item.value;
							showToast({
								kind: 'info',
								message: `${f.message}${f.detail ? ': ' + f.detail : ''}`,
							});
						}
					}}
				/>
			</Box>
			<FunctionBar
				keys={[
					{key: 'Enter', label: t('audit.fbarFixOne')},
					{key: 'F', label: t('audit.fbarFixAll', {n: fixable.length})},
					{key: 'D', label: t('audit.fbarDetails')},
					{key: 'R', label: t('audit.fbarRescan')},
					{key: 'Esc', label: t('fbar.back')},
				]}
			/>
		</Box>
	);
}

function describeFix(f: Finding, t: ReturnType<typeof useT>): string {
	if (!f.fix) return f.message;
	if (f.fix.kind === 'refresh-meta') {
		return t('audit.confirmRefresh', {name: f.certName, drift: f.detail || ''});
	}
	if (f.fix.kind === 'relink-issuer') {
		if (f.fix.newIssuerId === null) {
			return t('audit.confirmUnlink', {name: f.certName});
		}
		return t('audit.confirmRelink', {
			name: f.certName,
			ca: f.fix.newIssuerName || `id=${f.fix.newIssuerId}`,
		});
	}
	return f.message;
}
