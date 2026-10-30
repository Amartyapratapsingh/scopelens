import { useCallback, useEffect, useRef, useState } from 'react';
import {
  ArrowLeft, ArrowRight, ArrowUpRight, ArrowsClockwise, Circle,
  Clock, Globe, MagnifyingGlass, Plus, ShieldCheck, SquaresFour,
  WarningCircle, X,
} from '@phosphor-icons/react';
import { api, ApiError, connectLocalWorkspace, dashboardApi, type ScanView, type ScopeView, type Summary, type Finding } from './api';
import { AssessmentView } from './AssessmentView';
import { LiveTerminal, TerminalView, useScanEvents } from './LiveTerminal';
import { SystemMap } from './SystemMap';
import { ProductPreview } from './ProductPreview';
import { TestAccountDialog } from './TestAccountDialog';
import { websiteScope } from './scan-url';
import { Panel, Stat, StackedBars, BarList, Gauge, bucketize, palette, severityColor } from './charts';
import { scanName, targetName } from './names';
import './dashboard.css';

type View = 'Overview' | 'Assessments' | 'Websites';
type Filter = 'all' | 'running' | 'completed' | 'partial' | 'failed';
type TimeRange = '24h' | '7d' | '30d' | 'all';
type RefreshInterval = 'off' | '5s' | '15s' | '1m';
const timeRanges: { value: TimeRange; label: string; ms: number | null }[] = [
  { value: '24h', label: 'Last 24 hours', ms: 86400000 },
  { value: '7d', label: 'Last 7 days', ms: 7 * 86400000 },
  { value: '30d', label: 'Last 30 days', ms: 30 * 86400000 },
  { value: 'all', label: 'All loaded', ms: null },
];
const refreshIntervals: { value: RefreshInterval; label: string; ms: number }[] = [
  { value: 'off', label: 'Off', ms: 0 }, { value: '5s', label: '5s', ms: 5000 },
  { value: '15s', label: '15s', ms: 15000 }, { value: '1m', label: '1m', ms: 60000 },
];
const initialRange = () => timeRanges.find(item => item.value === new URLSearchParams(location.search).get('range'))?.value ?? '7d';
const initialRefresh = () => refreshIntervals.find(item => item.value === new URLSearchParams(location.search).get('refresh'))?.value ?? '15s';
const outcomeSeries = [
  { key: 'completed', label: 'Completed', color: palette.green },
  { key: 'partial', label: 'Partial', color: palette.yellow },
  { key: 'failed', label: 'Failed', color: palette.red },
  { key: 'cancelled', label: 'Cancelled', color: palette.gray },
  { key: 'running', label: 'Running', color: palette.blue },
];
const outcome = (scan: ScanView) => scan.status === 'completed_partial' ? 'partial' : terminal.has(scan.status) ? scan.status : 'running';
const relativeTime = (value: string, now: number) => {
  const seconds = Math.max(0, Math.floor((now - Date.parse(value)) / 1000));
  if (!Number.isFinite(seconds)) return '—';
  return seconds < 60 ? `${seconds}s ago` : seconds < 3600 ? `${Math.floor(seconds / 60)}m ago` : seconds < 86400 ? `${Math.floor(seconds / 3600)}h ago` : `${Math.floor(seconds / 86400)}d ago`;
};
const mmss = (seconds: number) => `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(Math.floor(seconds % 60)).padStart(2, '0')}`;
const finishedSeconds = (scan: ScanView) => {
  if (!scan.finished_at) return null;
  const seconds = (Date.parse(scan.finished_at) - Date.parse(scan.started_at || scan.created_at)) / 1000;
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : null;
};
const terminal = new Set(['completed', 'completed_partial', 'failed', 'cancelled']);
const navigation = [
  { label: 'Overview', icon: SquaresFour },
  { label: 'Assessments', icon: ShieldCheck },
  { label: 'Websites', icon: Globe },
] as const;
const filters: { value: Filter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'running', label: 'Running' },
  { value: 'completed', label: 'Completed' },
  { value: 'partial', label: 'Partial' },
  { value: 'failed', label: 'Failed / cancelled' },
];
const readable = (value: string) => value.replaceAll('_', ' ');
const date = (value: string) => new Date(value).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
const errorText = (error: unknown) => error instanceof ApiError && [401, 403].includes(error.status)
  ? 'An authorized operator session is needed to access your assessments. This workspace does not include a sign-in screen yet.'
  : 'We couldn’t reach your assessment data. Check the backend connection and try again.';

function routeView() {
  const params = new URLSearchParams(location.search);
  if (params.has('scan')) return 'Assessments';
  return params.get('view') === 'assessments' ? 'Assessments' : params.get('view') === 'websites' ? 'Websites' : 'Overview';
}
function duration(scan: ScanView, now: number) {
  const start = Date.parse(scan.started_at || scan.created_at);
  const end = scan.finished_at ? Date.parse(scan.finished_at) : now;
  if (!Number.isFinite(start) || !Number.isFinite(end)) return '—';
  const seconds = Math.max(0, Math.floor((end - start) / 1000));
  return `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
}
function matchesFilter(scan: ScanView, filter: Filter) {
  if (filter === 'all') return true;
  if (filter === 'running') return !terminal.has(scan.status);
  if (filter === 'completed') return scan.status === 'completed';
  if (filter === 'partial') return scan.status === 'completed_partial';
  return scan.status === 'failed' || scan.status === 'cancelled';
}
function Status({ value }: { value: string }) {
  return <span className={`dash-status status-${value}`}><Circle size={7} weight="fill" />{value === 'completed_partial' ? 'partial' : readable(value)}</span>;
}
type TargetOption = { origin: string; name: string; count: number };
function initialTarget() {
  const params = new URLSearchParams(location.search);
  if (params.has('target')) return params.get('target') || '';
  try { return localStorage.getItem('scopelens.target') || ''; } catch { return ''; }
}
function TargetPicker({ value, options, onChange }: { value: string; options: TargetOption[]; onChange: (origin: string) => void }) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [index, setIndex] = useState(0);
  const root = useRef<HTMLDivElement>(null);
  const matches = [{ origin: '', name: 'All websites', count: options.reduce((n, item) => n + item.count, 0) }, ...options].filter(item => (item.name + ' ' + item.origin).toLowerCase().includes(query.toLowerCase()));
  const active = Math.min(index, Math.max(0, matches.length - 1));
  const label = options.find(item => item.origin === value)?.name || value || 'All websites';
  useEffect(() => { if (open) document.getElementById('target-option-' + active)?.scrollIntoView({ block: 'nearest' }); }, [open, active]);
  function choose(origin: string) { onChange(origin); setOpen(false); setQuery(''); }
  useEffect(() => {
    const outside = (event: PointerEvent) => { if (!root.current?.contains(event.target as Node)) setOpen(false); };
    document.addEventListener('pointerdown', outside);
    return () => document.removeEventListener('pointerdown', outside);
  }, []);
  return <div ref={root} className="dash-target-picker"><div className="dash-target-input"><input role="combobox" aria-label="Focus website" aria-expanded={open} aria-controls="target-options" aria-autocomplete="list" aria-activedescendant={open && matches.length ? 'target-option-' + active : undefined} value={open ? query : label} onFocus={() => { setOpen(true); setQuery(''); setIndex(0); }} onChange={event => { setQuery(event.target.value); setIndex(0); setOpen(true); }} onBlur={event => { if (!root.current?.contains(event.relatedTarget)) setOpen(false); }} onKeyDown={event => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); if (!open) { setOpen(true); setQuery(''); setIndex(0); } else setIndex(current => event.key === 'ArrowDown' ? Math.min(current + 1, matches.length - 1) : Math.max(0, current - 1)); }
    if (event.key === 'Enter' && open && matches[active]) { event.preventDefault(); choose(matches[active].origin); }
    if (event.key === 'Escape') { event.preventDefault(); setOpen(false); setQuery(''); }
  }} /><span aria-hidden="true">▾</span></div>{open && <ul id="target-options" role="listbox" aria-label="Websites" className="dash-target-options">{matches.map((item, i) => <li key={item.origin} id={'target-option-' + i} role="option" aria-selected={value === item.origin} className={active === i ? 'is-active' : ''} onPointerDown={event => event.preventDefault()} onMouseMove={() => setIndex(i)} onClick={() => choose(item.origin)}><div><strong>{item.name}</strong>{item.origin && <small>{item.origin}</small>}</div><span>{item.count}</span></li>)}{!matches.length && <li className="dash-target-no-match">No matching websites</li>}</ul>}</div>;
}
function TargetLive({ scan }: { scan: ScanView }) {
  const { events, connection } = useScanEvents(scan.id);
  const running = !terminal.has(scan.status) && scan.status !== 'paused';
  return <><Panel title={running ? 'System map · live' : 'Last run · replay'} meta={`${scan.id.slice(0, 8)} · click a component for its logs`} className="ops-span-12 dash-target-map"><SystemMap events={events} running={running} header={false} onSelect={node => { location.assign(`/dashboard?scan=${encodeURIComponent(scan.id)}&node=${node}`); }} /></Panel><Panel title={running ? 'Live log' : 'Last run · replay'} className="ops-span-12 dash-target-log" flush><TerminalView events={events} connection={connection} running={running} title={running ? 'Target · live log' : 'Target · last run replay'} /></Panel></>;
}
function TargetDashboard({ origin, scans, ranged, scopes, now, refreshKey, refreshMs, onAssess, onClear, onSelect, busy }: { origin: string; scans: ScanView[]; ranged: ScanView[]; scopes: ScopeView[]; now: number; refreshKey: number; refreshMs: number; onAssess: (id: string) => void; onClear: () => void; onSelect: (id: string) => void; busy: boolean }) {
  const versions = scopes.filter(scope => scope.origin === origin).sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at) || b.version - a.version);
  const scope = versions.find(item => !item.expired);
  const latest = scans[0];
  const finished = scans.find(scan => terminal.has(scan.status));
  const live = scans.find(scan => !terminal.has(scan.status) && scan.status !== 'paused') || latest;
  const [detail, setDetail] = useState<{ summary: Summary | null; findings: Finding[] | null; error: boolean } | null>(null);
  useEffect(() => {
    let disposed = false;
    setDetail(null);
    if (!finished) return;
    const load = async () => {
      const [summary, findings] = await Promise.allSettled([dashboardApi.summary(finished.id), dashboardApi.findings(finished.id)]);
      if (!disposed) setDetail({ summary: summary.status === 'fulfilled' ? summary.value : null, findings: findings.status === 'fulfilled' ? findings.value : null, error: summary.status === 'rejected' || findings.status === 'rejected' });
    };
    void load();
    const poll = () => { if (!document.hidden) void load(); };
    const timer = refreshMs ? window.setInterval(poll, refreshMs) : undefined;
    return () => { disposed = true; clearInterval(timer); };
  }, [finished?.id, refreshKey, refreshMs]);
  const durations = ranged.map(finishedSeconds).filter((n): n is number => n !== null).sort((a, b) => a - b);
  const mid = Math.floor(durations.length / 2);
  const median = durations.length ? durations.length % 2 ? durations[mid]! : (durations[mid - 1]! + durations[mid]!) / 2 : null;
  const settled = ranged.filter(scan => terminal.has(scan.status));
  const counts = ranged.map(scan => scan.findings_count);
  const severity = detail?.findings ? detail.findings.reduce<Record<string, number>>((result, finding) => { result[finding.severity] = (result[finding.severity] || 0) + 1; return result; }, {}) : detail?.summary?.severity_counts;
  const name = targetName(origin, versions.find(item => item.lab_binding?.service) || versions[0]);
  return <>
    <Panel title="Target focus" meta={scans.length + ' loaded assessments'} className="ops-span-12" actions={<><button className="ops-btn is-primary" disabled={!scope || busy} title={!scope ? 'No unexpired scope is available for this target.' : undefined} onClick={() => scope && onAssess(scope.id)}>Assess now</button><button className="ops-btn" onClick={onClear}>Clear focus</button></>}><div className="dash-target-header"><h2>{name}</h2><a href={origin} target="_blank" rel="noreferrer">{origin} <ArrowUpRight size={12} /></a><div className="dash-target-meta"><span className="dash-authority-badge">{[...new Set(versions.map(item => item.authority_domain))].join(' / ') || 'Unregistered'}</span><span>{[...new Set(versions.map(item => item.allowed_check_profile))].join(' · ') || latest?.profile}</span><span>{scope ? 'Scope expires ' + date(versions[0]!.authorization_expires_at) : 'expired'}</span></div></div></Panel>
    <Panel title="Assessments" className="ops-span-2"><Stat label="In selected range" value={ranged.length} sub="Loaded assessments" /></Panel>
    <Panel title="Latest findings" className="ops-span-2"><Stat label="Latest scan" value={latest?.findings_count ?? '—'} color={palette.orange} sub={latest ? readable(latest.status) : 'No scans yet'} /></Panel>
    <Panel title="Findings trend" className="ops-span-2"><Stat label="Best / worst in range" value={counts.length ? Math.min(...counts) + ' / ' + Math.max(...counts) : '—'} spark={[...counts].reverse()} color={palette.orange} /></Panel>
    <Panel title="Success rate" className="ops-span-2"><Stat label="Completed / terminal" value={settled.length ? Math.round(settled.filter(scan => scan.status === 'completed').length / settled.length * 100) : '—'} unit={settled.length ? '%' : undefined} color={palette.green} sub={settled.length + ' terminal assessments'} /></Panel>
    <Panel title="Median duration" className="ops-span-2"><Stat label="Finished in range" value={median === null ? '—' : mmss(median)} color={palette.purple} /></Panel>
    <Panel title="Last scanned" className="ops-span-2"><Stat label="Latest assessment" value={latest ? relativeTime(latest.created_at, now) : '—'} sub={latest ? date(latest.created_at) : 'No scans yet'} color={palette.gray} /></Panel>
    {live ? <TargetLive key={live.id} scan={live} /> : <Panel title="Last run · replay" className="ops-span-12"><p className="dash-chart-empty">No assessment log yet. Start an assessment for this target.</p></Panel>}
    <Panel title="Latest assessment" meta={finished ? date(finished.created_at) : 'No finished assessment'} className="ops-span-6" actions={finished && <button className="ops-btn" onClick={() => onSelect(finished.id)}>Open assessment <ArrowRight size={14} /></button>}>{finished ? detail ? <><div className="dash-target-summary">{severity && <BarList items={['critical', 'high', 'medium', 'low', 'info', 'informational'].filter(key => key !== 'informational' || severity[key]).map(key => ({ label: key, value: severity[key] || 0, color: severityColor[key] }))} />}{detail.summary && <Gauge value={detail.summary.coverage_percent} label="Coverage" />}</div>{detail.error && <p className="dash-error">Some assessment details are unavailable.</p>}</> : <p className="dash-chart-empty">Loading assessment details…</p> : <p className="dash-chart-empty">No finished assessment yet.</p>}</Panel>
    <Panel title="Findings trend" meta="Selected range" className="ops-span-6"><StackedBars points={[...ranged].reverse().map(scan => ({ label: new Date(scan.created_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }), values: { findings: scan.findings_count } }))} series={[{ key: 'findings', label: 'Findings', color: palette.orange }]} /></Panel>
  </>;
}
type PlatformReadiness = { status: string; schema_revision: string };
type PlatformExecution = {
  execution_enabled: boolean;
  dispatch_implemented: boolean;
  detail: string;
  score_version?: string;
  default_profile?: string;
};
type PlatformChecks = {
  health: boolean;
  readiness: PlatformReadiness | null;
  execution: PlatformExecution | null;
  checkedAt: number;
};
type PlatformTone = 'good' | 'warning' | 'bad' | 'neutral';

async function platformResponse(path: string, signal: AbortSignal) {
  const response = await fetch(path, { credentials: 'same-origin', cache: 'no-store', signal });
  if (!response.ok) throw new Error(`Platform check failed: ${response.status}`);
  return response;
}

function PlatformStatus({ interval, refreshKey }: { interval: number; refreshKey: number }) {
  const [checks, setChecks] = useState<PlatformChecks>({ health: false, readiness: null, execution: null, checkedAt: 0 });
  const [clock, setClock] = useState(Date.now());
  useEffect(() => {
    let disposed = false;
    let inFlight = false;
    let controller: AbortController | null = null;
    const load = async () => {
      if (document.hidden || inFlight) return;
      inFlight = true;
      controller = new AbortController();
      const signal = controller.signal;
      const timeout = window.setTimeout(() => controller?.abort(), 10000);
      try {
        const [health, readiness, execution] = await Promise.allSettled([
          platformResponse('/healthz', signal),
          platformResponse('/readyz', signal).then(async response => {
            const data = await response.json() as PlatformReadiness;
            if (!data || typeof data.status !== 'string' || typeof data.schema_revision !== 'string') throw new Error('Invalid readiness response');
            return data;
          }),
          platformResponse('/api/system/execution', signal).then(async response => {
            const data = await response.json() as PlatformExecution;
            if (!data || typeof data.execution_enabled !== 'boolean' || typeof data.dispatch_implemented !== 'boolean') throw new Error('Invalid execution response');
            return data;
          }),
        ]);
        if (disposed) return;
        const checkedAt = Date.now();
        setChecks({
          health: health.status === 'fulfilled',
          readiness: readiness.status === 'fulfilled' ? readiness.value : null,
          execution: execution.status === 'fulfilled' ? execution.value : null,
          checkedAt,
        });
        setClock(checkedAt);
      } finally {
        clearTimeout(timeout);
        inFlight = false;
      }
    };
    const visibility = () => { if (!document.hidden) { setClock(Date.now()); if (interval) void load(); } };
    void load();
    const poll = interval ? window.setInterval(() => { void load(); }, interval) : null;
    const tick = window.setInterval(() => { if (!document.hidden) setClock(Date.now()); }, 1000);
    document.addEventListener('visibilitychange', visibility);
    return () => {
      disposed = true;
      if (poll !== null) clearInterval(poll);
      clearInterval(tick);
      controller?.abort();
      document.removeEventListener('visibilitychange', visibility);
    };
  }, [interval, refreshKey]);

  const checking = checks.checkedAt === 0;
  const execution = checks.execution;
  const enforcing = execution ? execution.execution_enabled && execution.dispatch_implemented : undefined;
  const allGood = checks.health && checks.readiness?.status === 'ready' && enforcing && !!checks.readiness.schema_revision && !!execution?.score_version && !!execution.default_profile;
  const flag = (label: string, enabled: boolean | undefined, enabledText: string): { label: string; value: string; tone: PlatformTone; dot: boolean } => ({
    label,
    value: checking ? 'checking' : enabled === undefined ? 'unavailable' : enabled ? enabledText : 'disabled',
    tone: checking ? 'neutral' : enabled === undefined ? 'bad' : enabled ? 'good' : 'warning',
    dot: true,
  });
  const metadata = (label: string, value: string | undefined): { label: string; value: string; tone: PlatformTone; dot: boolean } => ({
    label, value: checking ? 'checking' : value || 'unavailable', tone: checking || value ? 'neutral' : 'bad', dot: false,
  });
  const chips = [
    { label: 'API', value: checking ? 'checking' : checks.health && checks.readiness?.status === 'ready' ? 'ready' : 'unavailable', tone: (checking ? 'neutral' : checks.health && checks.readiness?.status === 'ready' ? 'good' : 'bad') as PlatformTone, dot: true },
    metadata('Schema', checks.readiness?.schema_revision ? `r${checks.readiness.schema_revision}` : undefined),
    flag('Execution', execution?.execution_enabled, 'enabled'),
    flag('Dispatch', execution?.dispatch_implemented, 'live'),
    flag('Scope broker', enforcing, 'enforcing'),
    flag('Forward proxy', enforcing, 'only egress'),
    metadata('Score engine', execution?.score_version),
    metadata('Default profile', execution?.default_profile),
  ];
  const age = Math.max(0, Math.floor((clock - checks.checkedAt) / 1000));
  return <Panel title={<span className="dash-platform-title"><Circle className={allGood ? 'dash-platform-ready' : 'dash-platform-idle'} size={7} weight="fill" />Platform</span>} meta={<span className="dash-platform-age">{checking ? 'Checking…' : `checked ${age}s ago`}</span>} className="ops-span-12 dash-platform">
    <div className="dash-platform-chips" title={execution?.detail || undefined}>{chips.map(chip => <span key={chip.label} className={`dash-platform-chip platform-${chip.tone}`}><span>{chip.label}</span>{chip.dot && <Circle size={6} weight="fill" />}<code>{chip.value}</code></span>)}</div>
  </Panel>;
}

const scanPhases = [
  { label: 'Queue', statuses: ['queued'] },
  { label: 'Explore', statuses: ['recon', 'planning'] },
  { label: 'Assess', statuses: ['testing'] },
  { label: 'Verify', statuses: ['confirming'] },
  { label: 'Report', statuses: ['reporting'] },
];
function ScanPhaseStepper({ status }: { status: string }) {
  const current = scanPhases.findIndex(phase => phase.statuses.includes(status));
  return <ol className="dash-mini-stepper" aria-label="Assessment phases">{scanPhases.map((phase, index) => <li key={phase.label} title={`${phase.label}${index === current ? ' · current' : index < current ? ' · complete' : ''}`} aria-current={index === current ? 'step' : undefined} className={index === current ? 'is-current' : index < current ? 'is-complete' : ''}><span aria-hidden="true" /><span className="sr-only">{phase.label}{index === current ? ', current phase' : index < current ? ', complete' : ''}</span></li>)}</ol>;
}

function AssessmentTable({ scans, scopes, now, onSelect, empty }: {
  scans: ScanView[]; scopes: ScopeView[]; now: number; onSelect: (id: string) => void; empty: string;
}) {
  if (!scans.length) return <div className="dash-history-empty">{empty}</div>;
  return <div className="dash-table-wrap"><table className="dash-table">
    <thead><tr><th>Target</th><th>Profile</th><th>Status</th><th className="dash-number-column">Findings</th><th className="dash-number-column">Started</th><th className="dash-number-column">Duration</th></tr></thead>
    <tbody>{scans.map(scan => <tr key={scan.id} onClick={() => onSelect(scan.id)}>
      <td className="dash-website-cell"><button type="button" className="dash-site-link" aria-label={`Open assessment for ${scanName(scan, scopes)}`} onClick={event => { event.stopPropagation(); onSelect(scan.id); }}><span>{scanName(scan, scopes)}</span><small>{scan.target_origin}</small></button></td>
      <td className="dash-profile-cell">{scan.profile}</td>
      <td className="dash-status-cell"><Status value={scan.status} /></td>
      <td className="dash-number-column dash-finding-cell"><strong className={scan.findings_count ? 'dash-findings-count has-findings' : 'dash-findings-count'}>{scan.findings_count}</strong><span className="dash-mobile-label"> findings</span></td>
      <td className="dash-number-column dash-date-cell"><time dateTime={scan.created_at} title={date(scan.created_at)}>{relativeTime(scan.created_at, now)}</time></td>
      <td className="dash-number-column dash-duration-cell">{scan.finished_at ? duration(scan, now) : '—'}</td>
    </tr>)}</tbody>
  </table></div>;
}

export function Dashboard() {
  const [view, setView] = useState<View>(routeView);
  const [target, setTarget] = useState(initialTarget);
  const [range, setRange] = useState<TimeRange>(initialRange);
  const [refreshInterval, setRefreshInterval] = useState<RefreshInterval>(initialRefresh);
  const [refreshKey, setRefreshKey] = useState(0);
  const refreshMs = refreshIntervals.find(item => item.value === refreshInterval)!.ms;
  const [selected, setSelected] = useState<string | null>(() => new URLSearchParams(location.search).get('scan'));
  const [scans, setScans] = useState<ScanView[]>([]);
  const [scopes, setScopes] = useState<ScopeView[]>([]);
  const [state, setState] = useState<'loading' | 'ready' | 'error'>('loading');
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<Filter>('all');
  const [historyLimit, setHistoryLimit] = useState(25);
  const [websiteSearch, setWebsiteSearch] = useState('');
  const [accountOrigin, setAccountOrigin] = useState<string | null>(null);
  const [startOpen, setStartOpen] = useState(() => new URLSearchParams(location.search).has('website'));
  const [startMode, setStartMode] = useState<'url' | 'scope'>('url');
  const [website, setWebsite] = useState(() => new URLSearchParams(location.search).get('website') ?? '');
  const [scopeId, setScopeId] = useState('');
  const [accountOpen, setAccountOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState('');
  const [now, setNow] = useState(Date.now());
  const startDialog = useRef<HTMLDialogElement>(null);
  const startTrigger = useRef<HTMLElement | null>(null);
  const newAssessmentButton = useRef<HTMLButtonElement>(null);
  const submitting = useRef(false);
  const pendingScope = useRef<{ key: string; id: string } | null>(null);
  const generation = useRef(0);

  const refresh = useCallback(async () => {
    const ticket = ++generation.current;
    try {
      await connectLocalWorkspace();
      const [nextScans, nextScopes] = await Promise.all([api.listScans(), api.listScopes()]);
      if (ticket !== generation.current) return;
      setScans(nextScans);
      setScopes(nextScopes);
      setError('');
      setState('ready');
      setNow(Date.now());
    } catch (cause) {
      if (ticket !== generation.current) return;
      setError(errorText(cause));
      setState('error');
      setScans([]);
      setScopes([]);
    }
  }, []);
  useEffect(() => { void refresh(); return () => { generation.current++; }; }, [refresh]);
  useEffect(() => {
    if (!refreshMs) return;
    const poll = () => { if (!document.hidden) void refresh(); };
    const timer = window.setInterval(poll, refreshMs);
    document.addEventListener('visibilitychange', poll);
    return () => { clearInterval(timer); document.removeEventListener('visibilitychange', poll); };
  }, [refresh, refreshMs]);
  useEffect(() => {
    const url = new URL(location.href);
    if (target) url.searchParams.set('target', target);
    else url.searchParams.delete('target');
    try { if (target) localStorage.setItem('scopelens.target', target); else localStorage.removeItem('scopelens.target'); } catch { /* Storage may be disabled. */ }
    url.searchParams.set('range', range);
    url.searchParams.set('refresh', refreshInterval);
    history.replaceState(null, '', url);
  }, [range, refreshInterval, target]);
  const hasRunningScans = scans.some(scan => !terminal.has(scan.status) && scan.status !== 'paused');
  useEffect(() => {
    if (!hasRunningScans) return;
    const tick = () => { if (!document.hidden) setNow(Date.now()); };
    tick();
    const timer = window.setInterval(tick, 1000);
    document.addEventListener('visibilitychange', tick);
    return () => { clearInterval(timer); document.removeEventListener('visibilitychange', tick); };
  }, [hasRunningScans]);
  useEffect(() => {
    const sync = () => {
      setView(routeView());
      setRange(initialRange());
      setTarget(new URLSearchParams(location.search).get('target') || '');
      setRefreshInterval(initialRefresh());
      setSelected(new URLSearchParams(location.search).get('scan'));
      const draft = new URLSearchParams(location.search).get('website');
      if (draft !== null) { setWebsite(draft); setStartMode('url'); setStartOpen(true); }
    };
    window.addEventListener('popstate', sync);
    return () => window.removeEventListener('popstate', sync);
  }, []);
  useEffect(() => {
    const dialog = startDialog.current;
    if (!dialog) return;
    if (startOpen && !dialog.open) {
      dialog.showModal();
      dialog.querySelector<HTMLInputElement>('#scan-website-url')?.focus();
    }
    else if (!startOpen && dialog.open) dialog.close();
  }, [startOpen]);

  function setRoute(nextView: View, scanId: string | null = null) {
    setView(nextView);
    setSelected(scanId);
    if (nextView === 'Assessments' && !scanId) setHistoryLimit(25);
    const url = new URL(location.href);
    url.searchParams.delete('website');
    if (scanId) url.searchParams.set('scan', scanId);
    else url.searchParams.delete('scan');
    if (nextView === 'Overview' && !scanId) url.searchParams.delete('view');
    else url.searchParams.set('view', nextView.toLowerCase());
    history.replaceState(null, '', url);
  }
  function closeStart() {
    setStartOpen(false);
    setActionError('');
    const url = new URL(location.href);
    if (url.searchParams.has('website')) {
      url.searchParams.delete('website');
      history.replaceState(null, '', url);
    }
  }
  function openStart(mode: 'url' | 'scope' = 'url', id = '') {
    startTrigger.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setStartMode(mode);
    setScopeId(id || scopes.find(scope => !scope.expired)?.id || '');
    setActionError('');
    setStartOpen(true);
  }
  async function startScope(id: string) {
    if (!id || submitting.current) return;
    submitting.current = true;
    setBusy(true);
    setActionError('');
    try {
      await connectLocalWorkspace();
      const scan = await api.createScan(id);
      setScans(previous => [scan, ...previous.filter(item => item.id !== scan.id)]);
      setRoute('Assessments', scan.id);
      closeStart();
      void refresh();
    } catch (cause) {
      setActionError(cause instanceof ApiError ? cause.message : 'The assessment could not be started.');
    } finally { submitting.current = false; setBusy(false); }
  }
  async function scanWebsite(event: React.FormEvent) {
    event.preventDefault();
    if (submitting.current) return;
    setActionError('');
    let body: ReturnType<typeof websiteScope>;
    try { body = websiteScope(website); }
    catch (cause) { setActionError((cause as Error).message); return; }
    submitting.current = true;
    setBusy(true);
    try {
      await connectLocalWorkspace();
      const key = JSON.stringify([body.scheme, body.host, body.port, body.allowed_path_prefixes]);
      if (pendingScope.current?.key !== key) {
        const scope = await dashboardApi.register(body);
        pendingScope.current = { key, id: scope.id };
      }
      const scan = await api.createScan(pendingScope.current.id);
      pendingScope.current = null;
      setScans(previous => [scan, ...previous.filter(item => item.id !== scan.id)]);
      setRoute('Assessments', scan.id);
      closeStart();
      void refresh();
    } catch (cause) {
      setActionError(cause instanceof ApiError ? cause.message : 'Could not confirm scan startup. Check assessment history before retrying.');
      void refresh();
    } finally { submitting.current = false; setBusy(false); }
  }

  const selectedScan = scans.find(scan => scan.id === selected);
  const availableScopes = scopes.filter(scope => !scope.expired);
  const query = search.trim().toLowerCase();
  const sortedScans = [...scans].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
  const scansCapped = scans.length >= 100;
  const assessmentCount = scansCapped ? '100+' : scans.length;
  const targetScans = target ? sortedScans.filter(scan => scan.target_origin === target) : sortedScans;
  const targetOrigins = [...new Set([...scopes.map(scope => scope.origin), ...scans.map(scan => scan.target_origin)])];
  if (target && !targetOrigins.includes(target)) targetOrigins.push(target);
  const targetOptions = targetOrigins.map(origin => ({ origin, name: targetName(origin, scopes.find(scope => scope.origin === origin && scope.lab_binding?.service) || scopes.find(scope => scope.origin === origin)), count: scans.filter(scan => scan.target_origin === origin).length })).sort((a, b) => a.name.localeCompare(b.name));
  const filtered = targetScans.filter(scan => matchesFilter(scan, filter) && `${scanName(scan, scopes)} ${scan.target_origin} ${scan.profile} ${scan.status}`.toLowerCase().includes(query));
  const scopeGroups = new Map<string, ScopeView[]>();
  for (const scope of scopes) {
    const group = scopeGroups.get(scope.origin) ?? [];
    group.push(scope);
    scopeGroups.set(scope.origin, group);
  }
  const websites = [...scopeGroups.entries()].map(([origin, versions]) => {
    const newestFirst = [...versions].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at) || b.version - a.version);
    const assessScope = newestFirst.find(scope => !scope.expired);
    return {
      origin, versions, assessScope, nameScope: newestFirst.find(scope => scope.lab_binding?.service) ?? newestFirst[0],
      profiles: [...new Set(versions.map(scope => scope.allowed_check_profile))],
      authorities: [...new Set(versions.map(scope => scope.authority_domain))],
      scanCount: versions.reduce((total, scope) => total + scope.scan_count, 0),
      latestExpiry: versions.reduce((latest, scope) => Date.parse(scope.authorization_expires_at) > Date.parse(latest) ? scope.authorization_expires_at : latest, versions[0]!.authorization_expires_at),
    };
  }).sort((a, b) => Number(!a.assessScope) - Number(!b.assessScope) || a.origin.localeCompare(b.origin));
  const visibleWebsites = websites.filter(site => `${targetName(site.origin, site.nameScope)} ${site.origin} ${site.profiles.join(' ')} ${site.authorities.join(' ')}`.toLowerCase().includes(websiteSearch.trim().toLowerCase()));
  const rangeSpec = timeRanges.find(item => item.value === range)!;
  const rangeEnd = now;
  const loadedTimes = scans.map(scan => Date.parse(scan.created_at)).filter(Number.isFinite);
  const rangeStart = rangeSpec.ms === null ? loadedTimes.length ? Math.min(rangeEnd - 1, ...loadedTimes) : rangeEnd - 86400000 : rangeEnd - rangeSpec.ms;
  const overviewScans = targetScans.filter(scan => Date.parse(scan.created_at) >= rangeStart && Date.parse(scan.created_at) <= rangeEnd);
  const chronological = [...overviewScans].reverse();
  const rangeCapped = !target && scansCapped && overviewScans.length >= 100;
  const overviewCount = rangeCapped ? '100+' : overviewScans.length;
  const overviewFindings = overviewScans.reduce((total, scan) => total + scan.findings_count, 0);
  const active = overviewScans.filter(scan => !terminal.has(scan.status));
  const outcomes = Object.fromEntries(outcomeSeries.map(series => [series.key, overviewScans.filter(scan => outcome(scan) === series.key).length]));
  const settled = overviewScans.filter(scan => terminal.has(scan.status)).length;
  const successRate = settled ? Math.round((outcomes.completed! / settled) * 100) : null;
  const durations = chronological.map(finishedSeconds).filter((value): value is number => value !== null);
  const orderedDurations = [...durations].sort((a, b) => a - b);
  const middle = Math.floor(orderedDurations.length / 2);
  const medianDuration = orderedDurations.length ? orderedDurations.length % 2 ? orderedDurations[middle]! : (orderedDurations[middle - 1]! + orderedDurations[middle]!) / 2 : null;
  const { buckets, width: bucketWidth } = bucketize(overviewScans, scan => Date.parse(scan.created_at), rangeStart, rangeEnd, 24, outcome);
  const timeLabel = (time: number) => new Date(time).toLocaleString(undefined, rangeEnd - rangeStart <= 86400000 ? { hour: '2-digit', minute: '2-digit', hour12: false } : { month: 'short', day: 'numeric' });
  const timePoints = buckets.map((values, index) => ({ label: timeLabel(rangeStart + index * bucketWidth), values }));
  const countSpark = buckets.map(bucket => Object.values(bucket).reduce((sum, value) => sum + value, 0));
  const findingSpark = Array<number>(24).fill(0);
  for (const scan of overviewScans) {
    const index = Math.min(23, Math.max(0, Math.floor((Date.parse(scan.created_at) - rangeStart) / bucketWidth)));
    findingSpark[index] = findingSpark[index]! + scan.findings_count;
  }
  const topTargets = new Map<string, { label: string; value: number; count: number }>();
  for (const scan of overviewScans) {
    const target = topTargets.get(scan.target_origin) ?? { label: scanName(scan, scopes), value: 0, count: 0 };
    target.value += scan.findings_count;
    target.count++;
    topTargets.set(scan.target_origin, target);
  }
  const loadedNote = scansCapped ? 'Latest 100 loaded; older scans excluded' : `${scans.length} scans loaded`;
  const pageTitle = selected ? 'Assessment' : view === 'Overview' ? 'Overview' : view;

  return <div className="dash-shell">
    <a href="#workspace-main" className="skip-link">Skip to workspace</a>
    <aside className="dash-sidebar">
      <a href="/" className="brand-link"><span className="brand-mark"><ShieldCheck size={20} weight="duotone" /></span>ScopeLens</a>
      <nav aria-label="Workspace">{navigation.map(({ label, icon: Icon }) => <button key={label} type="button"
        className={view === label ? 'is-selected' : ''} aria-current={view === label ? 'page' : undefined}
        onClick={() => setRoute(label)}><Icon size={16} weight={view === label ? 'duotone' : 'regular'} />
        <span>{label}</span>{label !== 'Overview' && <small>{label === 'Assessments' ? assessmentCount : websites.length}</small>}</button>)}</nav>
      <div className="dash-sidebar-bottom"><span className={`dash-connection ${state}`}><Circle size={7} weight="fill" />{state === 'ready' ? 'Connected' : state === 'loading' ? 'Connecting' : 'Disconnected'}</span><a href="/" className="dash-home"><ArrowLeft size={16} /> Back to website</a></div>
    </aside>
    <div className="dash-body">
      <header className="dash-topbar"><div className="dash-breadcrumb">Workspace <span>/</span> <strong>{pageTitle}</strong></div>
        <div className="dash-top-actions"><TargetPicker value={target} options={targetOptions} onChange={origin => { setTarget(origin); setHistoryLimit(25); }} /><label className="sr-only" htmlFor="dashboard-range">Overview time range</label><select id="dashboard-range" className="dash-ops-control" value={range} onChange={event => { setRange(event.target.value as TimeRange); setNow(Date.now()); }}>{timeRanges.map(item => <option value={item.value} key={item.value}>{item.label}</option>)}</select>
          <label className="sr-only" htmlFor="dashboard-refresh">Refresh interval</label><select id="dashboard-refresh" className="dash-ops-control" value={refreshInterval} onChange={event => setRefreshInterval(event.target.value as RefreshInterval)}>{refreshIntervals.map(item => <option value={item.value} key={item.value}>{item.label}</option>)}</select>
          <button className="ops-btn dash-refresh" type="button" title="Refresh dashboard" aria-label="Refresh dashboard" onClick={() => { void refresh(); setRefreshKey(key => key + 1); }}><ArrowsClockwise size={16} /></button>
          <button ref={newAssessmentButton} className="ops-btn is-primary dash-new-assessment" type="button" onClick={() => openStart()}><Plus size={16} /> New assessment</button></div></header>
      <main id="workspace-main" className="dash-content" tabIndex={-1}>
        {state === 'error' && <div className="dash-banner" role="alert"><WarningCircle size={20} /><div><strong>Workspace data is unavailable</strong><p>{error}</p></div><button type="button" onClick={() => void refresh()}>Retry <ArrowsClockwise size={15} /></button></div>}
        {view === 'Overview' && <>
          <div className="dash-page-heading"><h1>Overview</h1><span className="dash-total">{rangeSpec.label} · {loadedNote}</span></div>
          <div className="ops-grid-12 dash-overview-grid">
            <PlatformStatus interval={refreshMs} refreshKey={refreshKey} />
            {target && state !== 'ready' ? <Panel title="Target focus" className="ops-span-12"><div className="dash-inline-empty">{state === 'loading' ? 'Loading website…' : 'Website details are unavailable while disconnected.'}</div></Panel> : target ? <TargetDashboard key={target} origin={target} scans={targetScans} ranged={overviewScans} scopes={scopes} now={now} refreshKey={refreshKey} refreshMs={refreshMs} onAssess={id => void startScope(id)} onClear={() => setTarget('')} onSelect={id => setRoute('Assessments', id)} busy={busy} /> : <>
            <Panel title="Assessments" className="ops-span-2"><Stat label={rangeSpec.label} value={state === 'ready' ? overviewCount : '—'} sub={rangeCapped ? 'Showing the latest 100' : scansCapped ? 'From latest 100 loaded' : 'Loaded assessments'} spark={countSpark} color={palette.cyan} /></Panel>
            <Panel title="Findings recorded" className="ops-span-2"><Stat label={scansCapped ? 'Latest 100 assessments' : 'Recorded findings'} value={state === 'ready' ? overviewFindings : '—'} sub={scansCapped ? 'Older assessments not counted' : 'Selected range'} spark={findingSpark} color={palette.orange} /></Panel>
            <Panel title="Running now" className="ops-span-2"><Stat label="Active assessments" value={state === 'ready' ? active.length : '—'} sub={active.length ? 'Live event streams' : 'No active scans in range'} color={palette.blue} /></Panel>
            <Panel title="Success rate" className="ops-span-2"><Stat label="Completed / terminal" value={state === 'ready' && successRate !== null ? successRate : '—'} unit={successRate !== null ? '%' : undefined} sub={`partial ${outcomes.partial} · failed ${outcomes.failed}`} color={palette.green} /></Panel>
            <Panel title="Median duration" className="ops-span-2"><Stat label="Finished assessments" value={state === 'ready' && medianDuration !== null ? mmss(medianDuration) : '—'} sub={`${durations.length} finished scans`} spark={durations.slice(-24)} color={palette.purple} /></Panel>
            <Panel title="Targets" className="ops-span-2"><Stat label="Unique origins" value={state === 'ready' ? new Set(overviewScans.map(scan => scan.target_origin)).size : '—'} sub="Assessed in selected range" color={palette.gray} /></Panel>
            </>}
            <Panel title="Assessments over time" meta={`${rangeSpec.label} · 24 buckets`} className="ops-span-8"><StackedBars points={timePoints} series={outcomeSeries} height={160} /></Panel>
            <Panel title="Outcome mix" meta={`${overviewScans.length} loaded scans in range`} className="ops-span-4"><BarList items={outcomeSeries.map(series => ({ label: series.label, value: outcomes[series.key]!, color: series.color, note: `${overviewScans.length ? Math.round(outcomes[series.key]! / overviewScans.length * 100) : 0}%` }))} /></Panel>
            {!target && <>
            <Panel title="Findings per assessment" meta="Last 40 in time order" className="ops-span-6"><StackedBars points={chronological.slice(-40).map(scan => ({ label: timeLabel(Date.parse(scan.created_at)), values: { findings: scan.findings_count } }))} series={[{ key: 'findings', label: 'Findings', color: palette.orange }]} height={144} /></Panel>
            <Panel title="Top targets by findings" meta="Selected range" className="ops-span-6">{topTargets.size ? <BarList items={[...topTargets.values()].sort((a, b) => b.value - a.value).slice(0, 8).map(target => ({ label: target.label, value: target.value, color: palette.orange, note: `${target.count} scans` }))} /> : <p className="dash-chart-empty">No targets in the selected range.</p>}</Panel>
            {active.length > 0 && <Panel title="Running now" meta={`${active.length} active`} className="ops-span-12"><div className="dash-running-grid">{active.map(scan => <article className="dash-running-card" key={scan.id}>
              <div className="dash-running-top"><Circle className={`dash-live-dot ${scan.status === 'paused' ? 'is-paused' : ''}`} size={7} weight="fill" /><button type="button" className="dash-running-target" onClick={() => setRoute('Assessments', scan.id)}><span>{scanName(scan, scopes)}</span><small>{scan.target_origin}</small></button><Status value={scan.status} /><span className="dash-running-elapsed"><Clock size={12} />{duration(scan, now)}</span></div>
              <div className="dash-running-context"><span className="dash-running-profile">{scan.profile}</span><ScanPhaseStepper status={scan.status} /></div>
              <div className="dash-progress" role="progressbar" aria-label={`Progress for ${scanName(scan, scopes)}`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(scan.progress_percent)}><span style={{ width: `${Math.max(0, Math.min(100, scan.progress_percent))}%` }} /></div>
              <LiveTerminal scanId={scan.id} running={scan.status !== 'paused'} compact />
            </article>)}</div></Panel>}
            </>}
            <Panel title="Recent assessments" meta={loadedNote} actions={<button className="ops-btn" onClick={() => setRoute('Assessments')}>View all <ArrowRight size={14} /></button>} flush className="ops-span-12"><AssessmentTable scans={overviewScans.slice(0, 8)} scopes={scopes} now={now} onSelect={id => setRoute('Assessments', id)} empty={state === 'loading' ? 'Loading assessments…' : 'No assessments in the selected range.'} /></Panel>
            {state === 'ready' && scans.length === 0 && <Panel title="Example assessment" meta="Illustrative data" actions={<button className="ops-btn" onClick={() => openStart()}>Start assessment</button>} className="ops-span-12"><ProductPreview standalone /></Panel>}
          </div>
        </>}
        {view === 'Assessments' && (selected ? <>
          <button className="dash-back" type="button" onClick={() => setRoute('Assessments')}><ArrowLeft size={16} /> All assessments</button>
          {selectedScan ? <AssessmentView key={selectedScan.id} scan={selectedScan} onRefresh={refresh} onSelect={id => setRoute('Assessments', id)} />
            : state === 'ready' ? <div className="dash-inline-empty">Assessment not found. Choose one from the history.</div> : <div className="dash-inline-empty">Loading assessment…</div>}
        </> : <>
          <div className="dash-page-heading"><div><h1>Assessments</h1><p>Search loaded assessments and open a scan to review its evidence.</p></div><span className="dash-total">{target ? targetScans.length + ' loaded for target' : scansCapped ? `Showing ${Math.min(historyLimit, filtered.length)} of 100+ latest` : `${scans.length} total`}</span></div>
          <Panel title="Assessment history" meta={loadedNote} flush className="dash-history"><div className="dash-history-tools"><div className="dash-filters" role="group" aria-label="Filter by status">{filters.map(item => <button key={item.value} type="button" aria-pressed={filter === item.value} className={filter === item.value ? 'is-active' : ''} onClick={() => { setFilter(item.value); setHistoryLimit(25); }}>{item.label}<span>{targetScans.filter(scan => matchesFilter(scan, item.value)).length}</span></button>)}</div>
            <label className="dash-search"><MagnifyingGlass size={17} /><span className="sr-only">Search assessments</span><input value={search} onChange={event => { setSearch(event.target.value); setHistoryLimit(25); }} placeholder="Search website, profile, status" /></label></div>
            <AssessmentTable scans={filtered.slice(0, historyLimit)} scopes={scopes} now={now} onSelect={id => setRoute('Assessments', id)} empty={query || filter !== 'all' ? 'No assessments match these filters.' : state === 'ready' ? 'No assessments yet. Start one with New assessment.' : 'Connect to load assessment history.'} /><div className="dash-history-pagination"><span role="status">Showing {Math.min(historyLimit, filtered.length)} of {filtered.length}</span>{historyLimit < filtered.length && <button className="ops-btn" type="button" onClick={() => setHistoryLimit(limit => limit + 25)}>Show 25 more</button>}</div></Panel>
        </>)}
        {view === 'Websites' && <>
          <div className="dash-page-heading"><div><h1>Websites</h1><p>Authorized targets, assessment profiles, and scope expiry.</p></div><span className="dash-total">{websites.length} websites · {scopes.length} scope versions</span></div>
          <Panel title="Registered targets" meta={`${websites.length} origins · ${scopes.length} scope versions`} flush className="dash-history">
            <div className="dash-website-tools"><span>{visibleWebsites.length} websites</span><label className="dash-search"><MagnifyingGlass size={17} /><span className="sr-only">Search websites</span><input value={websiteSearch} onChange={event => setWebsiteSearch(event.target.value)} placeholder="Search website or profile" /></label></div>
            {visibleWebsites.length ? <table className="dash-table dash-websites-table"><thead><tr><th>Website / authority</th><th>Profiles</th><th className="dash-number-column">Versions</th><th className="dash-number-column">Scans</th><th>Latest expiry</th><th>Actions</th></tr></thead><tbody>
              {visibleWebsites.map(site => <tr key={site.origin} className={!site.assessScope ? 'dash-origin-expired' : ''}>
                <td className="dash-origin-cell"><strong>{targetName(site.origin, site.nameScope)}</strong><small>{site.origin}</small><span className="dash-authority-badge">{site.authorities.join(' / ')}</span></td>
                <td className="dash-origin-profiles">{site.profiles.map(profile => <span key={profile}>{readable(profile)}</span>)}</td>
                <td className="dash-number-column dash-origin-versions"><span className="dash-origin-label">Versions </span>{site.versions.length}</td>
                <td className="dash-number-column dash-origin-scans"><span className="dash-origin-label">Scans </span>{site.scanCount}</td>
                <td className="dash-origin-expiry"><span className="dash-origin-label">Expiry </span>{site.assessScope ? date(site.latestExpiry) : <span className="dash-expired-label">expired</span>}</td>
                <td className="dash-origin-actions"><span title={!site.assessScope ? 'All scope versions have expired. Register a new scope to assess this website.' : undefined}><button className="ops-btn" type="button" disabled={!site.assessScope || busy} onClick={() => site.assessScope && void startScope(site.assessScope.id)}>Assess <ArrowRight size={15} /></button></span><button className="dash-text-button" type="button" onClick={() => { setAccountOrigin(site.origin); setAccountOpen(true); }}>Test account</button></td>
              </tr>)}
            </tbody></table> : <div className="dash-history-empty">{websiteSearch ? 'No websites match your search.' : 'No registered websites yet. Start an assessment to add one.'}</div>}
          </Panel>
          {actionError && !startOpen && <p className="dash-error dash-site-error" role="alert">{actionError}</p>}
        </>}
        <footer className="dash-footer"><ShieldCheck size={15} /> Scores reflect tested scope and coverage.<a href="/#faq">How assessments work <ArrowUpRight size={13} /></a></footer>
      </main>
    </div>
    <TestAccountDialog open={accountOpen} scopes={accountOrigin ? scopes.filter(scope => scope.origin === accountOrigin) : scopes} onClose={() => setAccountOpen(false)} />
    <dialog ref={startDialog} className="dash-dialog dash-start-dialog" aria-labelledby="start-title" onClose={() => { closeStart(); (startTrigger.current ?? newAssessmentButton.current)?.focus(); }} onCancel={() => setStartOpen(false)}>
      <div className="dash-dialog-header"><div><h2 id="start-title">New assessment</h2></div><button type="button" className="dash-icon-button" disabled={busy} aria-label="Close new assessment" onClick={closeStart}><X size={20} /></button></div>
      <div className="dash-dialog-tabs" role="tablist" aria-label="Assessment target"><button type="button" role="tab" aria-selected={startMode === 'url'} onClick={() => { setStartMode('url'); setActionError(''); }}>Website URL</button><button type="button" role="tab" aria-selected={startMode === 'scope'} onClick={() => { setStartMode('scope'); setScopeId(current => current || availableScopes[0]?.id || ''); setActionError(''); }}>Registered site</button></div>
      {startMode === 'url' ? <form onSubmit={scanWebsite}><label htmlFor="scan-website-url">Website URL</label><div className="dash-dialog-input"><Globe size={18} /><input id="scan-website-url" autoFocus value={website} onChange={event => { setWebsite(event.target.value); setActionError(''); }} required autoComplete="url" inputMode="url" placeholder="https://your-website.com" disabled={busy} /></div><p>The entered origin and path define the scope. Use a website you own or have permission to assess.</p>{actionError && <p className="dash-error" role="alert">{actionError}</p>}<button className="ops-btn is-primary dash-dialog-primary" disabled={busy}>{busy ? 'Starting assessment…' : 'Start assessment'}<ArrowRight size={16} /></button></form>
        : <form onSubmit={event => { event.preventDefault(); void startScope(scopeId); }}><label htmlFor="scope-select">Registered website</label><select id="scope-select" value={scopeId} required onChange={event => setScopeId(event.target.value)} disabled={busy || !availableScopes.length}>{availableScopes.map(scope => <option key={scope.id} value={scope.id}>{targetName(scope.origin, scope)} · {scope.origin} · {scope.allowed_check_profile}</option>)}</select><p>Uses the website’s registered profile, permissions, and request limits.</p>{!availableScopes.length && <p className="dash-error">No unexpired scopes. Enter a URL to register a new website.</p>}{actionError && <p className="dash-error" role="alert">{actionError}</p>}<button className="ops-btn is-primary dash-dialog-primary" disabled={busy || !scopeId}>{busy ? 'Starting assessment…' : 'Start assessment'}<ArrowRight size={16} /></button></form>}
    </dialog>
  </div>;
}
