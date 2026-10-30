import { Component, useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { ArrowSquareOut, Browsers, Brain, DownloadSimple, FileText, Globe, LockKey, MagnifyingGlass, SealCheck, StopCircle, WarningCircle } from '@phosphor-icons/react';
import { ApiError, dashboardApi, type ProgressEvent, type ScopeView, type BrowserView, type CategoryTile, type Evidence, type Finding, type HostInventoryEntry, type HostPriorityPlan, type ScannerResult, type ScanView, type Summary } from './api';
import { TerminalView, describe, useScanEvents } from './LiveTerminal';
import { BarList, fmt, Gauge, Panel, Stat, StackedBars, bucketize, palette, severityColor } from './charts';
import { targetName } from './names';
import { FindingRow, isConfirmed, severityKey } from './FindingRow';
import { HostInventory } from './HostInventory';
import { SystemMap, nodes, type NodeId } from './SystemMap';
import { AiReasoning, ComponentDrawer, type AiRecord } from './ComponentDrawer';
import './assessment.css';

const terminal = new Set(['completed', 'completed_partial', 'failed', 'cancelled']);
const severities = ['critical', 'high', 'medium', 'low', 'info'] as const;
const words = (value: string) => value.replaceAll('_', ' ');
const statusText: Record<string, string> = { completed_partial: 'partial', recon: 'exploring', confirming: 'verifying' };
const tabs = ['Findings', 'Coverage', 'Pipeline', 'Evidence', 'Terminal'] as const;
type Tab = typeof tabs[number];
const steps = [
  { label: 'Queue', statuses: ['queued'] }, { label: 'Explore', statuses: ['recon', 'planning'] },
  { label: 'Assess', statuses: ['testing'] }, { label: 'Verify', statuses: ['confirming'] }, { label: 'Report', statuses: ['reporting'] },
];

function duration(from: string | null, to: string | number | null) {
  if (!from) return null;
  const ms = (typeof to === 'number' ? to : to ? Date.parse(to) : Date.now()) - Date.parse(from);
  if (!Number.isFinite(ms) || ms < 0) return null;
  const s = Math.floor(ms / 1000);
  return s >= 3600 ? `${Math.floor(s / 3600)}h ${Math.floor(s % 3600 / 60)}m` : `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

type Data = {
  summary?: Summary; findings?: Finding[]; categories?: CategoryTile[]; browser?: BrowserView; scanners?: ScannerResult[];
  hosts?: HostInventoryEntry[]; priorities?: HostPriorityPlan; evidence?: Evidence[];
};
const keys = ['summary', 'findings', 'categories', 'browser', 'scanners', 'hosts', 'priorities', 'evidence'] as const;

/** One polling loop for every assessment panel. Failed parts keep their last loaded value. */
function useAssessment(scanId: string, running: boolean) {
  const [data, setData] = useState<Data>({});
  const [failed, setFailed] = useState<string[]>([]);
  const [loaded, setLoaded] = useState(false);
  const load = useCallback(async () => {
    const api = dashboardApi;
    const results = await Promise.allSettled([api.summary(scanId), api.findings(scanId), api.categories(scanId), api.browser(scanId),
      api.scanners(scanId), api.hosts(scanId), api.hostPriorities(scanId), api.evidence(scanId)]);
    const update: Data = {};
    results.forEach((r, i) => { if (r.status === 'fulfilled') Object.assign(update, { [keys[i]!]: r.value }); });
    setData(old => ({ ...old, ...update }));
    setFailed(keys.filter((_, i) => results[i]!.status === 'rejected'));
    setLoaded(true);
  }, [scanId]);
  // Poll while running, and keep retrying a finished scan until every part has loaded once.
  const settled = !running && loaded && failed.length === 0;
  useEffect(() => {
    void load();
    if (settled) return;
    const timer = setInterval(() => { if (!document.hidden) void load(); }, 5000);
    return () => clearInterval(timer);
  }, [load, settled]);
  return { data, failed, loaded, load };
}

function useNow(active: boolean) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => { if (!active) return; const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t); }, [active]);
  return now;
}

export function StatusPill({ status }: { status: string }) {
  const tone = status === 'completed' ? 'ok' : status === 'completed_partial' ? 'partial' : status === 'failed' ? 'bad' : ['cancelled', 'paused'].includes(status) ? 'muted' : 'live';
  return <span className={`status-pill tone-${tone}`}><i aria-hidden="true" />{statusText[status] ?? words(status)}</span>;
}

/** Keeps one malformed field from blanking the page; the user can retry without reloading. */
class Boundary extends Component<{ children: ReactNode }, { error: string | null }> {
  state = { error: null as string | null };
  static getDerivedStateFromError(e: unknown) { return { error: e instanceof Error ? e.message : 'Unknown error' }; }
  render() {
    if (!this.state.error) return this.props.children;
    return <div className="av-alert" role="alert"><WarningCircle size={18} /> This assessment view hit an unexpected value ({this.state.error}).
      <button type="button" className="ops-btn" onClick={() => this.setState({ error: null })}>Retry</button></div>;
  }
}

export function AssessmentView(props: { scan: ScanView; onRefresh: () => Promise<void>; onSelect: (id: string) => void }) {
  return <Boundary><AssessmentBody {...props} /></Boundary>;
}

function AssessmentBody({ scan, onRefresh, onSelect }: { scan: ScanView; onRefresh: () => Promise<void>; onSelect: (id: string) => void }) {
  const running = !terminal.has(scan.status);
  const { data, failed, loaded, load } = useAssessment(scan.id, running);
  const { events, connection } = useScanEvents(scan.id);
  const now = useNow(running);
  const [tab, setTabState] = useState<Tab>(() => {
    const value = new URLSearchParams(location.search).get('tab');
    return tabs.includes(value as Tab) ? value as Tab : 'Findings';
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  function setTab(next: Tab) {
    setTabState(next);
    const url = new URL(location.href); url.searchParams.set('tab', next); history.replaceState(null, '', url);
  }
  async function act(action: () => Promise<unknown>) {
    setBusy(true); setError('');
    try { await action(); await load(); await onRefresh(); }
    catch (e) { setError(e instanceof ApiError ? e.message : 'The action could not be completed.'); }
    finally { setBusy(false); }
  }

  const { summary, findings = [], categories = [], browser, scanners = [], hosts, evidence = [] } = data;
  const [scope, setScope] = useState<ScopeView | null>(null);
  useEffect(() => { dashboardApi.scope(scan.scope_version_id).then(setScope).catch(() => setScope(null)); }, [scan.scope_version_id]);
  const name = targetName(scan.target_origin, scope);
  const ai = useAiRecord(scan.id, running);
  const [node, setNodeState] = useState<NodeId | null>(() => {
    const value = new URLSearchParams(location.search).get('node');
    return nodes.some(n => n.id === value) ? value as NodeId : null;
  });
  function setNode(next: NodeId | null) {
    setNodeState(next);
    const url = new URL(location.href);
    if (next) url.searchParams.set('node', next); else url.searchParams.delete('node');
    history.replaceState(null, '', url);
  }
  const counted = useMemo(() => {
    const requests = events.filter(e => e.action.startsWith('broker.'));
    return {
      requests: requests.length, denied: requests.filter(e => e.allowed === false).length,
      ai: events.filter(e => e.action === 'model.complete' || e.action.startsWith('adaptive.')).length,
    };
  }, [events]);
  const proven = findings.filter(isConfirmed).length;
  const sev = Object.fromEntries(severities.map(s => [s, findings.filter(f => severityKey(f.severity) === s).length])) as Record<typeof severities[number], number>;
  const reach = summary?.reach;
  const elapsed = duration(scan.started_at ?? scan.created_at, scan.finished_at ?? now);
  const step = steps.findIndex(s => s.statuses.includes(scan.status));
  const inProfile = categories.filter(c => c.in_profile);
  const scored = inProfile.filter(c => c.score !== null).length;
  const num = (v: number | undefined) => v ?? (loaded ? 0 : '—');
  const timeline = useTimeline(events, running ? now : null);

  return <section className="av" aria-labelledby="av-title">
    <header className="av-head">
      <div className="av-id">
        <div className="av-title-row">
          <h1 id="av-title">{name}</h1>
          <StatusPill status={scan.status} />
        </div>
        <div className="av-meta">
          <a href={scan.target_origin} target="_blank" rel="noreferrer">{scan.target_origin} <ArrowSquareOut size={12} /></a>
          <span><b>profile</b> {scan.profile}</span>
          <span><b>id</b> {scan.id.slice(0, 8)}</span>
          <span><b>started</b> {new Date(scan.created_at).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</span>
          {elapsed && <span><b>{running ? 'elapsed' : 'duration'}</b> {elapsed}</span>}
          <span><b>engine</b> {scan.score_version}</span>
        </div>
      </div>
      <div className="av-actions">
        {running && <button type="button" className="ops-btn is-danger" disabled={busy} onClick={() => void act(() => dashboardApi.cancel(scan.id))}><StopCircle size={15} /> Cancel scan</button>}
        {running ? <span className="av-pending">Report unlocks when the scan finishes</span> : <>
          <a className="ops-btn" href={`/api/scans/${scan.id}/export.json`} download><DownloadSimple size={15} /> JSON</a>
          <a className="ops-btn is-primary" href={`/api/scans/${scan.id}/export.html`} download><FileText size={15} /> Download report</a>
        </>}
      </div>
    </header>

    {error && <p className="av-alert" role="alert"><WarningCircle size={18} /> {error}</p>}
    {failed.length > 0 && <p className="av-soft" role="status">Couldn’t refresh {failed.join(', ')}. Showing the last loaded data.</p>}

    {running && <div className="av-phase" role="status" aria-live="polite">
      <span className="av-live-dot" aria-hidden="true" /><strong>{steps[step]?.label ?? words(scan.status)}</strong>
      <ol className="av-steps">{steps.map((s, i) => <li key={s.label} className={i < step ? 'is-done' : i === step ? 'is-now' : ''} aria-current={i === step ? 'step' : undefined}>{s.label}</li>)}</ol>
      <span className="av-phase-meta">{counted.requests} requests · {counted.ai} AI decisions · {events.length} events</span>
    </div>}

    <div className="ops-grid-12 av-board">
      {[
        { label: 'Pages crawled', value: num(summary?.discovery?.pages_fetched), sub: hosts ? `${hosts.length} host${hosts.length === 1 ? '' : 's'} discovered` : 'discovery', color: palette.blue, spark: timeline.spark('http') },
        { label: 'Browser states', value: num(browser?.states), sub: `${browser?.actions ?? 0} Playwright actions`, color: palette.purple, spark: timeline.spark('browser') },
        { label: 'Scoped requests', value: counted.requests || num(undefined), sub: counted.denied ? `${counted.denied} denied by broker` : '0 denied by broker', color: palette.cyan, spark: timeline.spark('http') },
        { label: 'Tests executed', value: num(reach?.fully_assessed), sub: reach ? `of ${reach.planned} planned` : 'controls & probes', color: palette.green },
        { label: 'AI decisions', value: counted.ai || num(undefined), sub: 'planner & follow-ups', color: palette.cyan, spark: timeline.spark('ai') },
        { label: 'Evidence sealed', value: evidence.length || num(undefined), sub: 'SHA-256 artifacts', color: palette.yellow },
      ].map(s => <div key={s.label} className="ops-panel ops-span-2 av-kpi"><div className="ops-panel-body"><Stat {...s} /></div></div>)}

      <Panel className="ops-span-4" title="Findings by severity" meta={`${proven} proven · ${findings.length - proven} to verify`} actions={<button type="button" className="ops-btn" onClick={() => setTab('Findings')}>Open</button>}>
        <div className="av-findings-head"><strong>{summary?.findings_count ?? (loaded ? findings.length : '—')}</strong><span>findings</span></div>
        <BarList items={severities.map(s => ({ label: s === 'info' ? 'Informational' : s[0]!.toUpperCase() + s.slice(1), value: sev[s], color: severityColor[s] }))} />
      </Panel>
      <Panel className="ops-span-3" title="Coverage" meta={summary?.overall_score === null || !summary ? 'score publishes at full coverage' : `score ${summary.overall_score}/100`}>
        <Gauge value={summary?.coverage_percent ?? 0} label="of applicable checks assessed" color={(summary?.coverage_percent ?? 0) >= 80 ? palette.green : (summary?.coverage_percent ?? 0) >= 50 ? palette.yellow : palette.orange} />
        <p className="av-gauge-note">{scored} of {inProfile.length} categories scored · <button type="button" className="link-button" onClick={() => setTab('Coverage')}>by category</button></p>
      </Panel>
      <Panel className="ops-span-5" title="Activity throughput" meta={timeline.span ? `${timeline.buckets} buckets · ${timeline.bucketLabel} each` : 'waiting for events'}>
        {timeline.span ? <StackedBars height={150} points={timeline.points} series={lanes.map(l => ({ key: l.key, label: l.label, color: l.color }))} />
          : <p className="av-empty">{running ? 'Waiting for the first events…' : 'No activity was recorded.'}</p>}
      </Panel>

      <Panel className="ops-span-12" title="Component trace" meta="when each part of the system was working · one tick per event">
        <Trace timeline={timeline} />
      </Panel>

      <Panel className="ops-span-12" title="System map" meta={`${running ? 'live' : 'final state'} · click any component for its logs`} flush>
        <SystemMap events={events} scanners={scanners} evidenceCount={evidence.length} running={running} header={false} selected={node} onSelect={setNode} />
      </Panel>
      <Panel className="ops-span-12" title="AI reasoning" meta={ai ? `${ai.hypotheses.length} follow-ups · ${ai.model_calls.length} model calls · $${fmt(ai.model_calls.reduce((n, c) => n + (c.cost || 0), 0), 4)} · models propose, proof rules decide` : 'loading'}
        actions={<button type="button" className="ops-btn" onClick={() => setNode('planner')}>Model calls</button>}>
        {ai ? <AiReasoning hypotheses={ai.hypotheses} running={running} /> : <p className="av-empty">Loading AI records…</p>}
      </Panel>
      {running ? <div className="ops-span-12 av-term-cell"><TerminalView events={events} connection={connection} running title={`scopelens assess ${name}`} /></div> : <>
        <Panel className="ops-span-6" title="Findings by category × severity" meta={`${findings.length} findings · ${new Set(findings.map(f => f.category)).size} categories`}>
          <Heatmap findings={findings} />
        </Panel>
        <Panel className="ops-span-6" title="Most affected routes" meta="findings per route">
          <RouteList findings={findings} />
        </Panel>
      </>}
    </div>
    {summary?.status_reason && <p className="av-soft"><b>Run note</b> {summary.status_reason}</p>}

    <nav className="av-tabs" aria-label="Assessment sections">{tabs.map(t => <button type="button" key={t} aria-current={tab === t ? 'page' : undefined} onClick={() => setTab(t)}>
      {t}<span>{t === 'Findings' ? findings.length : t === 'Coverage' ? inProfile.length : t === 'Pipeline' ? scanners.length + 2 : t === 'Evidence' ? evidence.length : events.length}</span>
    </button>)}</nav>

    <div className="av-panel">
      {tab === 'Findings' && <FindingsTab findings={findings} scanId={scan.id} busy={busy} loaded={loaded} running={running}
        onRetest={f => void act(async () => { const next = await dashboardApi.retest(f.id); onSelect(next.scan_id); })} />}
      {tab === 'Coverage' && <CoverageTab categories={categories} summary={summary} />}
      {tab === 'Pipeline' && <PipelineTab data={data} running={running} aiCount={counted.ai} />}
      {tab === 'Evidence' && <EvidenceTab evidence={evidence} scanId={scan.id} />}
      {tab === 'Terminal' && <TerminalView events={events} connection={connection} running={running} title={`scopelens assess ${name}`} />}
    </div>
    {node && <ComponentDrawer node={node} events={events} connection={connection} running={running} scanId={scan.id} browser={browser}
      scanners={scanners} evidence={evidence} categories={categories} ai={ai} onClose={() => setNode(null)} />}
  </section>;
}

/** The AI record lives in the report's assessment_plan; it fills in while the scan runs. */
function useAiRecord(scanId: string, running: boolean) {
  const [ai, setAi] = useState<AiRecord | null>(null);
  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const r = await fetch(`/api/scans/${scanId}/export.json`, { credentials: 'same-origin', cache: 'no-store' });
        if (!r.ok) return;
        const plan = ((await r.json()) as { assessment_plan?: Partial<AiRecord> }).assessment_plan ?? {};
        if (!cancelled) setAi({ hypotheses: plan.hypotheses ?? [], model_calls: plan.model_calls ?? [], adaptive_stop: plan.adaptive_stop ?? null });
      } catch { /* Keep the last loaded record. */ }
    };
    void load();
    if (!running) return () => { cancelled = true; };
    // ponytail: the report is ~1 MB (advisory bundle); 15 s polling is fine locally, add a slim endpoint if it matters.
    const timer = setInterval(() => { if (!document.hidden) void load(); }, 15000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [scanId, running]);
  return ai;
}

const lanes = [
  { key: 'http', label: 'HTTP worker', color: palette.blue },
  { key: 'browser', label: 'Playwright', color: palette.purple },
  { key: 'ai', label: 'AI planner', color: palette.cyan },
  { key: 'evidence', label: 'Evidence & score', color: palette.yellow },
  { key: 'lifecycle', label: 'Control plane', color: palette.gray },
] as const;

/** Buckets events over the scan's own time span, for throughput, sparklines and the trace. */
function useTimeline(events: ProgressEvent[], liveNow: number | null) {
  return useMemo(() => {
    const lines = events.map(describe).filter(l => Number.isFinite(l.at));
    const start = lines[0]?.at ?? 0;
    const end = Math.max(liveNow ?? 0, lines.at(-1)?.at ?? 0, start + 1000);
    const n = 40;
    const { buckets, width } = bucketize(lines, l => l.at, start, end, n, l => l.group);
    const fmt = (ms: number) => { const s = Math.round(ms / 1000); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; };
    return {
      lines, start, end, span: lines.length ? end - start : 0, buckets: n,
      bucketLabel: width >= 1000 ? `${Math.round(width / 1000)}s` : `${Math.round(width)}ms`,
      points: buckets.map((values, i) => ({ label: `+${fmt(i * width)}`, values })),
      spark: (group: string) => buckets.map(b => b[group] ?? 0),
      fmt,
    };
  }, [events, liveNow]);
}

function Trace({ timeline }: { timeline: ReturnType<typeof useTimeline> }) {
  const { lines, start, span, fmt } = timeline;
  if (!lines.length) return <p className="av-empty">No events recorded yet.</p>;
  const pos = (t: number) => `${((t - start) / span) * 100}%`;
  return <div className="trace">
    {lanes.map(lane => {
      const own = lines.filter(l => l.group === lane.key);
      const first = own[0]?.at, last = own.at(-1)?.at;
      return <div className="trace-row" key={lane.key}>
        <span className="trace-label"><i style={{ background: lane.color }} />{lane.label}<b>{own.length}</b></span>
        <div className="trace-track">
          {first !== undefined && last !== undefined && <span className="trace-span" style={{ left: pos(first), width: `max(2px, calc(${pos(last)} - ${pos(first)}))`, background: lane.color }} />}
          {own.map(l => <span key={l.cursor} className={`trace-tick ${l.warn ? 'is-warn' : ''}`} style={{ left: pos(l.at), background: l.warn ? palette.red : lane.color }} title={`+${fmt(l.at - start)} · ${l.text}`} />)}
        </div>
      </div>;
    })}
    <div className="trace-axis"><span />{[0, .25, .5, .75, 1].map(f => <span key={f} style={{ left: `${f * 100}%` }}>+{fmt(f * span)}</span>)}</div>
  </div>;
}

function RouteList({ findings }: { findings: Finding[] }) {
  const counts = new Map<string, { n: number; worst: number }>();
  for (const f of findings) for (const route of new Set(f.locations.map(l => l.route))) {
    const rank = severities.indexOf(severityKey(f.severity) as typeof severities[number]);
    const cur = counts.get(route) ?? { n: 0, worst: 99 };
    counts.set(route, { n: cur.n + 1, worst: Math.min(cur.worst, rank) });
  }
  const top = [...counts.entries()].sort((a, b) => b[1].n - a[1].n || a[1].worst - b[1].worst).slice(0, 8);
  if (!top.length) return <p className="av-empty">No affected routes recorded.</p>;
  return <BarList items={top.map(([route, v]) => ({ label: <code>{route}</code>, value: v.n, color: severityColor[severities[v.worst] ?? 'info'], note: severities[v.worst] }))} />;
}

function Heatmap({ findings }: { findings: Finding[] }) {
  const cats = [...new Map(findings.map(f => [f.category, f.category_title ?? f.category])).entries()].sort();
  if (!cats.length) return <p className="av-empty">No findings to map.</p>;
  const max = Math.max(1, ...cats.flatMap(([c]) => severities.map(s => findings.filter(f => f.category === c && severityKey(f.severity) === s).length)));
  return <table className="heat">
    <thead><tr><th>Category</th>{severities.map(s => <th key={s}>{s === 'info' ? 'info' : s}</th>)}</tr></thead>
    <tbody>{cats.map(([c, title]) => <tr key={c}><th scope="row"><code>{c}</code> {title}</th>{severities.map(s => {
      const n = findings.filter(f => f.category === c && severityKey(f.severity) === s).length;
      return <td key={s} style={{ background: n ? `color-mix(in srgb, ${severityColor[s]} ${18 + (n / max) * 62}%, transparent)` : undefined }}>{n || ''}</td>;
    })}</tr>)}</tbody>
  </table>;
}

function FindingsTab({ findings, scanId, busy, loaded, running, onRetest }: {
  findings: Finding[]; scanId: string; busy: boolean; loaded: boolean; running: boolean; onRetest: (f: Finding) => void;
}) {
  const [severity, setSeverity] = useState<string>('all');
  const [proof, setProof] = useState<'all' | 'proven' | 'lead'>('all');
  const [query, setQuery] = useState('');
  const order = (f: Finding) => severities.indexOf(severityKey(f.severity) as typeof severities[number]);
  const list = findings
    .filter(f => severity === 'all' || severityKey(f.severity) === severity)
    .filter(f => proof === 'all' || (proof === 'proven') === isConfirmed(f))
    .filter(f => `${f.title} ${f.category_title ?? ''} ${f.check_id} ${f.locations.map(l => l.route).join(' ')}`.toLowerCase().includes(query.trim().toLowerCase()))
    .sort((a, b) => order(a) - order(b) || Number(isConfirmed(b)) - Number(isConfirmed(a)));
  return <>
    <div className="av-toolbar">
      <div className="chips" role="group" aria-label="Severity">{['all', ...severities].map(s => <button type="button" key={s} aria-pressed={severity === s} onClick={() => setSeverity(s)}>
        {s === 'all' ? 'All' : s}<span>{s === 'all' ? findings.length : findings.filter(f => severityKey(f.severity) === s).length}</span></button>)}</div>
      <div className="chips" role="group" aria-label="Proof">{([['all', 'Any proof'], ['proven', 'Proven'], ['lead', 'Needs verification']] as const).map(([id, label]) =>
        <button type="button" key={id} aria-pressed={proof === id} onClick={() => setProof(id)}>{label}</button>)}</div>
      <label className="av-search"><MagnifyingGlass size={15} /><input aria-label="Search findings" placeholder="Search title, route or check" value={query} onChange={e => setQuery(e.target.value)} /></label>
    </div>
    {list.length ? <div className="frows">{list.map((f, i) => <FindingRow key={f.id} finding={f} scanId={scanId} busy={busy} onRetest={() => onRetest(f)} defaultOpen={i === 0 && !query && severity === 'all'} />)}</div>
      : <p className="av-empty">{!loaded ? 'Loading findings…' : findings.length ? 'No findings match these filters.' : running ? 'No findings yet. They appear here as checks complete.' : 'No issues were found in the checks that ran. Review Coverage for what was and wasn’t tested.'}</p>}
  </>;
}

function CoverageTab({ categories, summary }: { categories: CategoryTile[]; summary?: Summary }) {
  const reach = summary?.reach;
  const inProfile = categories.filter(c => c.in_profile);
  const outside = categories.filter(c => !c.in_profile);
  const seg = (n: number) => reach && reach.planned ? `${(n / reach.planned) * 100}%` : '0%';
  return <>
    {reach && <div className="reach">
      <div className="reach-head"><strong>{reach.fully_assessed}</strong> of {reach.planned} planned test instances fully assessed</div>
      <div className="reach-bar" aria-hidden="true">
        <span className="r-ok" style={{ width: seg(reach.fully_assessed) }} /><span className="r-na" style={{ width: seg(reach.not_applicable) }} />
        <span className="r-block" style={{ width: seg(reach.blocked) }} /><span className="r-err" style={{ width: seg(reach.error) }} />
      </div>
      <div className="reach-legend">
        <span><i className="r-ok" />Assessed {reach.fully_assessed}</span><span><i className="r-na" />Not applicable {reach.not_applicable}</span>
        <span><i className="r-block" />Blocked {reach.blocked}</span><span><i className="r-err" />Errors {reach.error}</span><span><i />Not reached {reach.unassessed}</span>
      </div>
    </div>}
    <div className="cats">{inProfile.map(c => <article key={c.category} className={`cat state-${c.state}`}>
      <div className="cat-top"><code>{c.category}</code>{c.score === null ? <span className="cat-score is-none">Not scored yet</span> : <span className="cat-score">{c.score}<small>/100</small></span>}</div>
      <h3>{c.title}</h3>
      <div className="cat-bar" aria-hidden="true"><span style={{ width: `${Math.max(0, Math.min(100, c.coverage_percent))}%` }} /></div>
      <p className="cat-meta">{Math.round(c.coverage_percent)}% covered · {words(c.state)}</p>
      {c.reason && <p className="cat-reason">{c.reason}</p>}
    </article>)}</div>
    {outside.length > 0 && <div className="unlock">
      <h3><LockKey size={16} /> Unlocked by authenticated and stateful profiles</h3>
      <p>These categories need test accounts or a stateful profile. They are outside this scan’s profile, so they are reported separately and never counted as passed.</p>
      <div className="unlock-chips">{outside.map(c => <span key={c.category}><code>{c.category}</code>{c.title}</span>)}</div>
    </div>}
  </>;
}

function PipelineTab({ data, running, aiCount }: { data: Data; running: boolean; aiCount: number }) {
  const { summary, browser, scanners = [], hosts, priorities } = data;
  return <>
    <div className="pipe">
      <article className="pipe-card">
        <h3><Globe size={18} /> Discovery</h3>
        <p className="pipe-num">{summary?.discovery?.pages_fetched ?? '—'} <small>pages fetched</small></p>
        <p>{summary?.discovery?.stopped_by ? `Stopped by ${summary.discovery.stopped_by}.` : 'Crawl, robots.txt and sitemap discovery within scope.'}</p>
      </article>
      <article className="pipe-card">
        <h3><Browsers size={18} /> Browser exploration</h3>
        <p className="pipe-num">{browser?.states ?? '—'} <small>states · {browser?.actions ?? 0} actions</small></p>
        <p>Status: {browser ? words(browser.status) : 'loading'}.</p>
        {[...(browser?.limitations ?? []), ...(browser?.gaps ?? []).map(g => typeof g.reason === 'string' ? g.reason : Object.values(g).filter(v => typeof v === 'string' || typeof v === 'number').join(' · '))].slice(0, 3).map((x, i) => <p key={i} className="pipe-gap">{x}</p>)}
      </article>
      <article className="pipe-card">
        <h3><Brain size={18} /> AI planner</h3>
        <p className="pipe-num">{aiCount} <small>decisions recorded</small></p>
        <p>The model proposes follow-ups. Registered proof rules decide what is confirmed; scores are computed deterministically.</p>
      </article>
    </div>
    <h3 className="av-subhead">Scanner results</h3>
    {scanners.length ? <div className="tools">{scanners.map(t => <details key={t.tool} className="tool">
      <summary>
        <strong>{t.tool}</strong><code>{t.version}</code><StatusPill status={t.state === 'completed' ? 'completed' : t.state === 'partial' ? 'completed_partial' : t.state} />
        <span className="tool-count">{t.observations.length} observation{t.observations.length === 1 ? '' : 's'}{t.errors.length ? ` · ${t.errors.length} error${t.errors.length === 1 ? '' : 's'}` : ''}{t.not_in_profile_controls?.length ? ` · ${t.not_in_profile_controls.length} not in profile` : ''}</span>
      </summary>
      <ul>{t.observations.map((o, i) => { const level = o.severity ?? o.reported_severity ?? 'info'; return <li key={i}><span className={`sev-pill sev-${severityKey(level)}`}>{level}</span><span>{o.title}</span><code>{o.rule_id}</code>{o.locations && <small>{o.locations.length} location{o.locations.length === 1 ? '' : 's'}</small>}</li>; })}
        {t.errors.map((e, i) => <li key={`e${i}`} className="tool-err"><WarningCircle size={14} />{e}</li>)}
        {t.not_in_profile_controls?.map(c => <li key={`p${c.check_id}`} className="muted"><code>{c.check_id}</code><span>Not in this profile. Not tested and not counted as passed.</span></li>)}
        {!t.observations.length && !t.errors.length && !t.not_in_profile_controls?.length && <li className="muted">No observations recorded.</li>}</ul>
    </details>)}</div> : <p className="av-empty">{running ? 'Scanner results appear as each tool finishes.' : 'No scanner results were recorded.'}</p>}
    <HostInventory priorities={priorities} hosts={hosts ?? null} failed={false} discovery={summary?.discovery} running={running} />
  </>;
}

function EvidenceTab({ evidence, scanId }: { evidence: Evidence[]; scanId: string }) {
  if (!evidence.length) return <p className="av-empty">No evidence has been recorded yet.</p>;
  const bytes = evidence.reduce((n, e) => n + e.content_bytes, 0);
  return <>
    <p className="av-soft">{evidence.length} artifacts · {fmt(bytes / 1024, 1)} KB · each one redacted, hashed with SHA-256 and stored encrypted with its producer recorded.</p>
    <div className="ev-table-wrap"><table className="ev-table">
      <thead><tr><th>Capture</th><th>Producer</th><th>Trust</th><th>Hash</th><th className="num">Size</th><th><span className="sr-only">Download</span></th></tr></thead>
      <tbody>{evidence.map(e => <tr key={e.id}>
        <td><span className="ev-sum">{e.summary || e.origin}</span><small>{new Date(e.captured_at).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })}</small></td>
        <td><code>{e.producer}</code></td>
        <td>{e.trusted ? <span className="ev-trust ok"><SealCheck size={13} weight="fill" /> trusted</span> : <span className="ev-trust">observation</span>}</td>
        <td><code title={e.content_hash}>{e.content_hash.slice(0, 12)}…</code></td>
        <td className="num">{fmt((e.content_bytes ?? 0) / 1024, 1)} KB</td>
        <td><a className="ev-dl" href={`/api/scans/${scanId}/evidence/${encodeURIComponent(e.id)}/download`} aria-label={`Download ${e.summary || e.id}`}><DownloadSimple size={15} /></a></td>
      </tr>)}</tbody>
    </table></div>
  </>;
}
