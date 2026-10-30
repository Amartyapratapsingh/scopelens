import { useEffect, useMemo, useRef, useState } from 'react';
import type { ProgressEvent, ScannerResult } from './api';
import './system-map.css';

export type NodeId = 'api' | 'dispatcher' | 'supervisor' | 'broker' | 'proxy' | 'crawler' | 'browser' | 'zap' | 'nuclei' | 'testssl'
  | 'planner' | 'gateway' | 'probes' | 'vault' | 'scorer' | 'report';

// Fixed layout in a 1100×412 viewBox; columns follow the request path left to right.
export const nodes: { id: NodeId; x: number; y: number; title: string; sub: string }[] = [
  { id: 'api', x: 10, y: 50, title: 'API', sub: 'scan control · SSE' },
  { id: 'dispatcher', x: 10, y: 170, title: 'Dispatcher', sub: 'durable outbox' },
  { id: 'supervisor', x: 10, y: 290, title: 'Supervisor', sub: 'leases · fencing' },
  { id: 'broker', x: 230, y: 110, title: 'Scope broker', sub: 'admits every request' },
  { id: 'proxy', x: 230, y: 230, title: 'Forward proxy', sub: 'bounded egress' },
  { id: 'crawler', x: 450, y: 10, title: 'HTTP worker', sub: 'crawl & probe traffic' },
  { id: 'browser', x: 450, y: 88, title: 'Playwright', sub: 'states · network' },
  { id: 'zap', x: 450, y: 166, title: 'OWASP ZAP', sub: 'passive rules' },
  { id: 'nuclei', x: 450, y: 244, title: 'Nuclei', sub: 'reviewed templates' },
  { id: 'testssl', x: 450, y: 322, title: 'testssl.sh', sub: 'TLS measurement' },
  { id: 'planner', x: 670, y: 50, title: 'AI planner', sub: 'LangGraph follow-ups' },
  { id: 'gateway', x: 670, y: 170, title: 'Model gateway', sub: 'budgets · no secrets' },
  { id: 'probes', x: 670, y: 290, title: 'Proof rules', sub: 'paired probes' },
  { id: 'vault', x: 890, y: 50, title: 'Evidence vault', sub: 'SHA-256 · encrypted' },
  { id: 'scorer', x: 890, y: 170, title: 'Scorer', sub: 'coverage gates' },
  { id: 'report', x: 890, y: 290, title: 'Report', sub: 'HTML · JSON' },
];
const W = 200, H = 58;
const edges: [NodeId, NodeId][] = [
  ['api', 'dispatcher'], ['dispatcher', 'supervisor'], ['supervisor', 'broker'], ['broker', 'proxy'],
  ['proxy', 'crawler'], ['proxy', 'browser'], ['proxy', 'zap'], ['proxy', 'nuclei'], ['proxy', 'testssl'],
  ['crawler', 'planner'], ['browser', 'planner'], ['planner', 'gateway'], ['gateway', 'probes'],
  ['crawler', 'vault'], ['browser', 'vault'], ['zap', 'scorer'], ['nuclei', 'scorer'], ['testssl', 'scorer'], ['probes', 'vault'],
  ['vault', 'scorer'], ['scorer', 'report'],
];

/** Which component produced an event. Requests count against the broker; the worker is inferred from the action. */
export function nodesFor(e: ProgressEvent): NodeId[] {
  const a = e.action;
  if (a.startsWith('scan.') || a.startsWith('retest.')) return ['api'];
  if (a === 'outbox.dispatch') return ['dispatcher'];
  if (a.startsWith('task.')) return ['supervisor'];
  if (a === 'broker.admit') return e.allowed === false ? ['broker'] : ['broker', 'proxy', 'crawler'];
  if (a === 'browser.admit') return ['broker', 'browser'];
  if (a.startsWith('browser.')) return ['browser'];
  if (a === 'model.complete') return ['planner', 'gateway'];
  if (a.startsWith('adaptive.')) return ['planner', 'probes'];
  if (a === 'evidence.record') return ['vault'];
  if (a === 'score.ready') return ['scorer', 'report'];
  return [];
}
const scannerNode: Record<string, NodeId> = { zap: 'zap', nuclei: 'nuclei', testssl: 'testssl', 'conditional-config': 'probes' };
const anchor = (id: NodeId, side: 'l' | 'r' | 't' | 'b') => {
  const n = nodes.find(x => x.id === id)!;
  return side === 'l' ? [n.x, n.y + H / 2] : side === 'r' ? [n.x + W, n.y + H / 2] : side === 't' ? [n.x + W / 2, n.y] : [n.x + W / 2, n.y + H];
};
function path(from: NodeId, to: NodeId) {
  const a = nodes.find(n => n.id === from)!, b = nodes.find(n => n.id === to)!;
  if (a.x === b.x) {
    const [x1, y1] = anchor(from, a.y < b.y ? 'b' : 't'), [x2, y2] = anchor(to, a.y < b.y ? 't' : 'b');
    return `M${x1},${y1} L${x2},${y2}`;
  }
  const [x1, y1] = anchor(from, 'r'), [x2, y2] = anchor(to, 'l');
  const mid = (x1! + x2!) / 2;
  return `M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`;
}

export function SystemMap({ events, scanners = [], evidenceCount = 0, running, header = true, selected, onSelect }: {
  events: ProgressEvent[]; scanners?: ScannerResult[]; evidenceCount?: number; running: boolean; header?: boolean;
  selected?: NodeId | null; onSelect?: (id: NodeId) => void;
}) {
  const [now, setNow] = useState(Date.now());
  const lastHit = useRef(new Map<NodeId, number>());
  const lastCursor = useRef(-1);
  useEffect(() => {
    const t = Date.now();
    // The first batch is the replayed history; only events that arrive after it count as live activity.
    if (lastCursor.current >= 0) for (const e of events) {
      if (e.cursor <= lastCursor.current) continue;
      for (const id of nodesFor(e)) lastHit.current.set(id, t);
    }
    lastCursor.current = events.at(-1)?.cursor ?? lastCursor.current;
    setNow(t);
  }, [events]);
  useEffect(() => {
    if (!running) return;
    const timer = setInterval(() => setNow(Date.now()), 700);
    return () => clearInterval(timer);
  }, [running]);

  const stats = useMemo(() => {
    const count = new Map<NodeId, number>(), warn = new Set<NodeId>();
    for (const e of events) for (const id of nodesFor(e)) {
      count.set(id, (count.get(id) ?? 0) + 1);
      if (e.allowed === false || ['denied', 'failed', 'error', 'blocked'].includes(e.outcome)) warn.add(id);
    }
    for (const s of scanners) {
      const id = scannerNode[s.tool];
      if (!id) continue;
      count.set(id, (count.get(id) ?? 0) + s.observations.length + (s.state === 'completed' || s.state === 'partial' ? 1 : 0));
      if (s.errors.length) warn.add(id);
    }
    // Evidence is not always announced as events; the stored artifact count is authoritative.
    count.set('vault', Math.max(count.get('vault') ?? 0, evidenceCount));
    return { count, warn };
  }, [events, scanners, evidenceCount]);

  const state = (id: NodeId) => {
    const hit = lastHit.current.get(id);
    if (running && hit && now - hit < 3500) return 'active';
    if (stats.warn.has(id) && (stats.count.get(id) ?? 0) === 0) return 'warn';
    return (stats.count.get(id) ?? 0) > 0 ? 'done' : 'idle';
  };
  const label = (id: NodeId) => {
    const scanner = scanners.find(s => scannerNode[s.tool] === id);
    if (scanner) return `${scanner.observations.length} obs${scanner.errors.length ? ` · ${scanner.errors.length} err` : ''}`;
    if (id === 'vault' && evidenceCount) return `${evidenceCount} sealed`;
    const n = id === 'proxy' || id === 'crawler' ? events.filter(e => e.action === 'broker.admit' && e.allowed !== false).length : stats.count.get(id) ?? 0;
    return n ? `${n} event${n === 1 ? '' : 's'}` : running ? 'waiting' : '—';
  };
  const activeCount = nodes.filter(n => state(n.id) === 'active').length;

  return <section className={`smap ${running ? 'is-running' : ''}`} aria-label="System map">
    {header && <header className="smap-head">
      <div><strong>System map</strong><span>{running ? `${activeCount} component${activeCount === 1 ? '' : 's'} active now` : `${nodes.filter(n => state(n.id) === 'done').length} of ${nodes.length} components produced results`}</span></div>
      <ul className="smap-legend" aria-label="Legend">
        <li className="active">active</li><li className="done">produced results</li><li className="warn">blocked / errors</li><li className="idle">idle</li>
      </ul>
    </header>}
    <div className="smap-canvas">
      <svg viewBox="0 0 1100 412" role="img" aria-label={`ScopeLens components. ${activeCount} active.`}>
        <defs>
          <linearGradient id="smap-flow" x1="0" x2="1"><stop offset="0" stopColor="#3a6bd8" /><stop offset="1" stopColor="#9fd0ff" /></linearGradient>
        </defs>
        {[['Control plane', 10], ['Policy & egress', 230], ['Workers', 450], ['Intelligence', 670], ['Results', 890]].map(([t, x]) =>
          <text key={t as string} className="smap-col" x={(x as number) + 2} y={406}>{t}</text>)}
        {edges.map(([a, b]) => {
          const on = state(b) === 'active' || state(a) === 'active';
          const done = state(a) !== 'idle' && state(b) !== 'idle';
          return <path key={`${a}-${b}`} d={path(a, b)} className={`smap-edge ${on ? 'is-on' : done ? 'is-done' : ''}`} />;
        })}
        {nodes.map(n => {
          const s = state(n.id);
          const open = () => onSelect?.(n.id);
          return <g key={n.id} className={`smap-node is-${s} ${stats.warn.has(n.id) ? 'has-warn' : ''} ${selected === n.id ? 'is-selected' : ''} ${onSelect ? 'is-clickable' : ''}`}
            transform={`translate(${n.x},${n.y})`} {...(onSelect ? { role: 'button', tabIndex: 0, 'aria-label': `${n.title}: open component logs`, 'aria-pressed': selected === n.id,
              onClick: open, onKeyDown: (e: React.KeyboardEvent) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } } } : {})}>
            <rect width={W} height={H} rx={10} />
            <circle className="smap-dot" cx={16} cy={20} r={4} />
            <text className="smap-title" x={28} y={24}>{n.title}</text>
            <text className="smap-sub" x={16} y={44}>{n.sub}</text>
            <text className="smap-count" x={W - 12} y={24} textAnchor="end">{label(n.id)}</text>
          </g>;
        })}
      </svg>
    </div>
  </section>;
}
