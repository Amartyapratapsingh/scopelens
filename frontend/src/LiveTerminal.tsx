import { useEffect, useMemo, useRef, useState } from 'react';
import { eventTypes, type ProgressEvent } from './api';
import './terminal.css';

export type Connection = 'connecting' | 'live' | 'reconnecting';

/** One EventSource per scan. The server replays history, so late subscribers still get the full log. */
export function useScanEvents(scanId: string, limit = 1000) {
  const [events, setEvents] = useState<ProgressEvent[]>([]);
  const [connection, setConnection] = useState<Connection>('connecting');
  useEffect(() => {
    setEvents([]);
    setConnection('connecting');
    const source = new EventSource(`/api/scans/${encodeURIComponent(scanId)}/events`);
    let pending: ProgressEvent[] = [];
    let timer = 0;
    // History replays arrive in a burst; batch them into one render.
    const flush = () => {
      timer = 0;
      const batch = pending;
      pending = [];
      setEvents(old => {
        const merged = new Map(old.map(e => [e.cursor, e]));
        for (const e of batch) merged.set(e.cursor, e);
        return [...merged.values()].sort((a, b) => a.cursor - b.cursor).slice(-limit);
      });
    };
    const receive = (event: MessageEvent) => {
      try {
        const item = JSON.parse(event.data) as ProgressEvent;
        if (!Number.isSafeInteger(item.cursor) || typeof item.action !== 'string') return;
        pending.push(item);
        if (!timer) timer = window.setTimeout(flush, 60);
      } catch { /* Malformed events never become activity. */ }
    };
    eventTypes.forEach(type => source.addEventListener(type, receive as EventListener));
    source.onmessage = receive;
    source.onopen = () => setConnection('live');
    source.onerror = () => setConnection('reconnecting');
    return () => { source.close(); clearTimeout(timer); };
  }, [scanId, limit]);
  return { events, connection };
}

type Group = 'http' | 'browser' | 'ai' | 'evidence' | 'lifecycle';
const groups: { id: Group | 'all'; label: string }[] = [
  { id: 'all', label: 'All' }, { id: 'http', label: 'HTTP' }, { id: 'browser', label: 'Browser' },
  { id: 'ai', label: 'AI' }, { id: 'evidence', label: 'Evidence & score' }, { id: 'lifecycle', label: 'Lifecycle' },
];
const bad = new Set(['denied', 'blocked', 'error', 'failed', 'cancelled']);
const words = (value?: string) => (value ?? '').replaceAll('_', ' ');

export interface TerminalLine { cursor: number; at: number; group: Group; tag: string; text: string; warn: boolean; full?: string }
// Probe payloads can be hundreds of characters; the full route stays available on hover.
const clip = (value: string, max = 96) => value.length > max ? `${value.slice(0, max - 1)}…` : value;

/** Turns a raw progress event into a readable log line. Unknown actions still render verbatim. */
export function describe(e: ProgressEvent): TerminalLine {
  const at = e.at ? Date.parse(e.at) : NaN;
  const warn = bad.has(e.outcome) || e.allowed === false;
  const base = { cursor: e.cursor, at, warn };
  const reason = e.reason && e.reason !== e.outcome && e.reason !== 'allowed' ? ` · ${e.reason}` : '';
  switch (e.action) {
    case 'broker.admit':
      return { ...base, group: 'http', tag: 'http', full: e.route, text: `${e.method ?? 'GET'} ${clip(e.route || '/')}  →  ${e.allowed === false ? 'DENIED by scope broker' : 'in scope'}${e.allowed === false ? reason : ''}` };
    case 'browser.open': return { ...base, group: 'browser', tag: 'browser', text: `Playwright session opened${reason}` };
    case 'browser.admit': return { ...base, group: 'browser', tag: 'browser', text: `action checked against scope · ${words(e.outcome)}${reason}` };
    case 'browser.complete': return { ...base, group: 'browser', tag: 'browser', text: `page state captured${e.route ? ` · ${e.route}` : ''}${reason}` };
    case 'browser.close': return { ...base, group: 'browser', tag: 'browser', text: 'session closed · states and network evidence saved' };
    case 'model.complete': return { ...base, group: 'ai', tag: 'ai', text: `planner decision · ${words(e.outcome)}${reason}` };
    case 'adaptive.plan': return { ...base, group: 'ai', tag: 'ai', text: `follow-up plan recorded · ${words(e.outcome)}${reason}` };
    case 'adaptive.complete': return { ...base, group: 'ai', tag: 'ai', text: `follow-up result · ${words(e.outcome)}${reason}` };
    case 'evidence.record': return { ...base, group: 'evidence', tag: 'evidence', text: `artifact sealed · ${words(e.outcome)}${reason}` };
    case 'score.ready': return { ...base, group: 'evidence', tag: 'score', text: `scorecard computed · coverage ${e.coverage_percent ?? '?'}% · ${e.verdict ?? words(e.outcome)}` };
    case 'scan.create': return { ...base, group: 'lifecycle', tag: 'scan', text: `assessment created · ${words(e.outcome)}` };
    case 'scan.cancel': return { ...base, group: 'lifecycle', tag: 'scan', text: `cancellation · ${words(e.outcome)}${reason}` };
    case 'scan.reconcile': return { ...base, group: 'lifecycle', tag: 'scan', text: `recovery check · ${words(e.outcome)}${reason}` };
    case 'outbox.dispatch': return { ...base, group: 'lifecycle', tag: 'queue', text: `worker dispatched${e.logical_id ? ` · ${e.logical_id}` : ''} · ${words(e.outcome)}` };
    case 'task.admit': return { ...base, group: 'lifecycle', tag: 'worker', text: `task ${words(e.task_state || e.outcome)}${e.logical_id ? ` · ${e.logical_id}` : ''}` };
    case 'task.settle': return { ...base, group: 'lifecycle', tag: e.outcome === 'succeeded' ? 'done' : 'worker', text: `task ${words(e.task_state || e.outcome)}${e.status ? ` → ${words(e.status)}` : ''}${reason}` };
    case 'retest.request': return { ...base, group: 'lifecycle', tag: 'retest', text: `retest requested${reason}` };
    case 'retest.complete': return { ...base, group: 'lifecycle', tag: 'retest', text: `retest result · ${words(e.outcome)}${reason}` };
    default: return { ...base, group: 'lifecycle', tag: e.type.split('.')[0] || 'event', text: `${e.action} · ${words(e.outcome)}${reason}` };
  }
}

/** Structured key=value view of an event, most useful fields first. */
const fieldOrder = ['cursor', 'type', 'outcome', 'method', 'route', 'allowed', 'reason', 'logical_id', 'task_state', 'status', 'coverage_percent', 'verdict', 'at'] as const;
function fields(e: ProgressEvent): [string, string][] {
  return fieldOrder.filter(k => e[k] !== undefined && e[k] !== null && e[k] !== '').map(k => [k, String(e[k])]);
}

const clock = (ms: number) => {
  if (!Number.isFinite(ms) || ms < 0) return '--:--';
  const s = Math.floor(ms / 1000);
  return `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
};
const connectionText = (connection: Connection, running: boolean) =>
  !running ? 'Replayed from saved log' : connection === 'live' ? 'Streaming live' : connection === 'connecting' ? 'Connecting…' : 'Reconnecting…';

export function TerminalView({ events, connection, running, compact = false, title, verboseDefault = false }: {
  events: ProgressEvent[]; connection: Connection; running: boolean; compact?: boolean; title: string; verboseDefault?: boolean;
}) {
  const [filter, setFilter] = useState<Group | 'all'>('all');
  const [verbose, setVerbose] = useState(verboseDefault);
  const [open, setOpen] = useState<number | null>(null);
  const raw = useMemo(() => new Map(events.map(e => [e.cursor, e])), [events]);
  const [follow, setFollow] = useState(true);
  const body = useRef<HTMLDivElement>(null);
  const lines = useMemo(() => events.map(describe), [events]);
  const counts = useMemo(() => lines.reduce<Record<string, number>>((acc, l) => ({ ...acc, [l.group]: (acc[l.group] ?? 0) + 1 }), {}), [lines]);
  const visible = filter === 'all' ? lines : lines.filter(l => l.group === filter);
  // ponytail: render cap keeps huge logs smooth; the full log stays in the report export.
  const shown = visible.slice(compact ? -40 : -600);
  const start = lines.find(l => Number.isFinite(l.at))?.at ?? NaN;
  const denied = lines.filter(l => l.warn).length;
  useEffect(() => {
    if (follow && body.current) body.current.scrollTop = body.current.scrollHeight;
  }, [shown.length, follow, filter]);
  return <section className={`term ${compact ? 'term-compact' : ''} ${running ? 'is-running' : ''}`} aria-label={title}>
    <header className="term-bar">
      <span className="term-dots" aria-hidden="true"><i /><i /><i /></span>
      <span className="term-title">{title}</span>
      <span className={`term-conn is-${running ? connection : 'saved'}`}><i aria-hidden="true" />{connectionText(connection, running)}</span>
    </header>
    {!compact && <div className="term-filters" role="group" aria-label="Filter log lines">
      {groups.map(g => <button key={g.id} type="button" aria-pressed={filter === g.id} onClick={() => setFilter(g.id)}>
        {g.label}<span>{g.id === 'all' ? lines.length : counts[g.id] ?? 0}</span>
      </button>)}
      <button type="button" className="term-verbose" aria-pressed={verbose} onClick={() => setVerbose(v => !v)}>verbose</button>
    </div>}
    <div className="term-body" ref={body} tabIndex={0} role="log" aria-live="off" aria-label={`${title} log`}
      onScroll={e => { const el = e.currentTarget; setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 24); }}>
      {visible.length > shown.length && <div className="term-line term-muted">… {visible.length - shown.length} earlier lines</div>}
      {shown.map(l => { const e = raw.get(l.cursor); return <div key={l.cursor} className={`term-line group-${l.group} ${l.warn ? 'is-warn' : ''} ${compact ? '' : 'is-clickable'}`}
        onClick={compact ? undefined : () => setOpen(open === l.cursor ? null : l.cursor)}>
        <time>{clock(l.at - start)}</time><span className="term-tag">{l.tag}</span><span className="term-text" title={l.full}>{l.text}</span>
        {verbose && e && <span className="term-fields">{fields(e).map(([k, v]) => <span key={k}><i>{k}=</i>{v}</span>)}</span>}
        {open === l.cursor && e && <pre className="term-json">{JSON.stringify(e, null, 2)}</pre>}
      </div>; })}
      {!lines.length && <div className="term-line term-muted">{running ? 'waiting for the first event…' : 'no activity was recorded for this assessment'}</div>}
      {running && <div className="term-line term-prompt"><span>❯</span><i className="term-cursor" aria-hidden="true" /></div>}
    </div>
    <footer className="term-foot">
      <span><b>{counts.http ?? 0}</b> requests</span>
      <span><b>{counts.browser ?? 0}</b> browser</span>
      <span><b>{counts.ai ?? 0}</b> AI</span>
      <span className={denied ? 'term-foot-warn' : ''}><b>{denied}</b> denied / failed</span>
      {!follow && <button type="button" onClick={() => setFollow(true)}>Jump to latest ↓</button>}
    </footer>
  </section>;
}

/** Self-contained live log for a scan (used on the overview). */
export function LiveTerminal({ scanId, running, compact = false, title = 'scopelens · live log' }: {
  scanId: string; running: boolean; compact?: boolean; title?: string;
}) {
  const { events, connection } = useScanEvents(scanId);
  return <TerminalView events={events} connection={connection} running={running} compact={compact} title={title} />;
}
