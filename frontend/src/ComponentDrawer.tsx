import { useEffect, useMemo, useRef, useState } from 'react';
import { DownloadSimple, X } from '@phosphor-icons/react';
import type { BrowserView, CategoryTile, Evidence, ProgressEvent, ScannerResult } from './api';
import { TerminalView, type Connection } from './LiveTerminal';
import { nodes, nodesFor, type NodeId } from './SystemMap';
import { BarList, fmt, palette, severityColor } from './charts';
import './component-drawer.css';

/** Subset of export.json → assessment_plan that records what the AI did. */
export interface Hypothesis {
  id: string; round: number; route: string; url: string; state: string; signal: string; control: string; operation: string;
  alternative: string; cost: number; max_requests: number; challenge?: { alternative_explanation?: string; missing_proof?: string } | null;
}
export interface ModelCall {
  id: string; role: string; state: string; cost: number; prompt_version: string;
  attempts: { model: string; state: string; provider: string; elapsed_seconds: number; cost: number }[];
}
export interface AiRecord { hypotheses: Hypothesis[]; model_calls: ModelCall[]; adaptive_stop?: { reason: string; completed_followups: number } | null }

const about: Record<NodeId, string> = {
  api: 'Creates the assessment, authenticates the operator and streams progress over SSE.',
  dispatcher: 'Durable outbox. Hands queued work to the supervisor exactly once, surviving restarts.',
  supervisor: 'Runs worker tasks under leases and fencing tokens so a lost worker can never write stale results.',
  broker: 'Policy check on every outbound request: scope, method, path and budget. Denials are logged.',
  proxy: 'The only egress path for scan traffic. Bounded connections, no direct internet from workers.',
  crawler: 'HTTP worker: crawl, robots/sitemap discovery and paired probe traffic, all through the broker.',
  browser: 'Leased Playwright Chromium. Captures DOM, screenshots and network for every state it reaches.',
  zap: 'OWASP ZAP passive analysis of captured traffic.',
  nuclei: 'Reviewed Nuclei templates against discovered routes.',
  testssl: 'testssl.sh measurement of the TLS endpoint.',
  planner: 'LangGraph coordinator. The model picks one reviewed follow-up at a time; it cannot invent actions.',
  gateway: 'Holds model credentials, enforces per-scan call and cost budgets, never forwards secrets.',
  probes: 'Registered proof rules. Only these decide whether evidence confirms a finding.',
  vault: 'Redacted captures, SHA-256 hashed and stored encrypted with their producer recorded.',
  scorer: 'Deterministic scoring with coverage gates. Untested areas are never averaged in.',
  report: 'HTML and JSON reports assembled from findings, evidence and coverage.',
};
const scannerTool: Partial<Record<NodeId, string>> = { zap: 'zap', nuclei: 'nuclei', testssl: 'testssl', probes: 'conditional-config' };

export function ComponentDrawer({ node, events, connection, running, scanId, browser, scanners, evidence, categories, ai, onClose }: {
  node: NodeId; events: ProgressEvent[]; connection: Connection; running: boolean; scanId: string;
  browser?: BrowserView; scanners: ScannerResult[]; evidence: Evidence[]; categories: CategoryTile[]; ai: AiRecord | null; onClose: () => void;
}) {
  const meta = nodes.find(n => n.id === node)!;
  const own = useMemo(() => events.filter(e => nodesFor(e).includes(node)), [events, node]);
  const close = useRef<HTMLButtonElement>(null);
  useEffect(() => { close.current?.focus(); }, [node]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  const tool = scanners.find(s => s.tool === scannerTool[node]);
  const aiNode = node === 'planner' || node === 'gateway' || node === 'probes';

  return <aside className="cdrawer" role="dialog" aria-modal="false" aria-labelledby="cdrawer-title">
    <header className="cdrawer-head">
      <div>
        <p className="cdrawer-kicker">component · {node}</p>
        <h2 id="cdrawer-title">{meta.title}</h2>
        <p className="cdrawer-about">{about[node]}</p>
      </div>
      <button ref={close} type="button" className="ops-btn" aria-label="Close component panel" onClick={onClose}><X size={15} /></button>
    </header>
    <div className="cdrawer-body">
      <div className="cdrawer-stats">
        <span><b>{own.length}</b> events</span>
        <span><b>{own.filter(e => e.allowed === false || ['denied', 'failed', 'error', 'blocked'].includes(e.outcome)).length}</b> denied / failed</span>
        <span><b>{own.at(-1)?.at ? new Date(own.at(-1)!.at!).toLocaleTimeString() : '—'}</b> last event</span>
      </div>

      {node === 'browser' && <BrowserSection scanId={scanId} browser={browser} evidence={evidence} running={running} />}
      {(node === 'broker' || node === 'proxy' || node === 'crawler') && <RequestSection events={events} />}
      {tool && <ScannerSection tool={tool} />}
      {aiNode && <AiSection ai={ai} running={running} focus={node} />}
      {node === 'vault' && <VaultSection evidence={evidence} scanId={scanId} />}
      {(node === 'scorer' || node === 'report') && <ScoreSection categories={categories} scanId={scanId} running={running} />}

      <h3 className="cdrawer-h3">Component log</h3>
      <TerminalView events={own} connection={connection} running={running} compact={false} verboseDefault title={`scopelens logs --component ${node} --follow`} />
    </div>
  </aside>;
}

/** Playwright: real screenshots from browser_state captures, fetched lazily. */
function BrowserSection({ scanId, browser, evidence, running }: { scanId: string; browser?: BrowserView; evidence: Evidence[]; running: boolean }) {
  const states = evidence.filter(e => e.producer.includes('browser') && /browser_state/.test(e.summary));
  const [shots, setShots] = useState<Record<string, { url: string; img: string; text: string }>>({});
  const [open, setOpen] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      for (const e of states.slice(0, 16)) {
        if (cancelled || shots[e.id]) continue;
        try {
          const r = await fetch(`/api/scans/${scanId}/evidence/${encodeURIComponent(e.id)}/download`, { credentials: 'same-origin' });
          const body = await r.json() as { data?: { url?: string; screenshot_jpeg?: string; text?: string } };
          if (cancelled || !body.data?.screenshot_jpeg) continue;
          const shot = { url: body.data.url ?? '', img: `data:image/jpeg;base64,${body.data.screenshot_jpeg}`, text: body.data.text ?? '' };
          setShots(old => ({ ...old, [e.id]: shot }));
        } catch { /* A capture that cannot be read is simply not shown. */ }
      }
    })();
    return () => { cancelled = true; };
    // ponytail: refetch only when the set of captures changes; shots are cached by id.
  }, [scanId, states.map(s => s.id).join()]);
  const list = states.map(s => ({ id: s.id, at: s.captured_at, shot: shots[s.id] })).filter(s => s.shot);
  const big = list.find(s => s.id === open);
  return <section className="cdrawer-sec">
    <h3 className="cdrawer-h3">Browser session · {browser?.states ?? 0} states · {browser?.actions ?? 0} actions</h3>
    {(browser?.limitations ?? []).length > 0 && <ul className="cdrawer-chips">{browser!.limitations.map(l => <li key={l}>{l}</li>)}</ul>}
    {big && <figure className="shot-big"><img src={big.shot!.img} alt={`Screenshot of ${big.shot!.url}`} /><figcaption><code>{big.shot!.url}</code> · {new Date(big.at).toLocaleTimeString()}</figcaption></figure>}
    {list.length ? <div className="shots">{list.map(s => <button type="button" key={s.id} className={open === s.id ? 'is-open' : ''} onClick={() => setOpen(open === s.id ? null : s.id)} aria-label={`Show screenshot of ${s.shot!.url}`}>
      <img src={s.shot!.img} alt="" loading="lazy" /><span>{new URL(s.shot!.url, location.href).pathname}</span>
    </button>)}</div> : <p className="cdrawer-empty">{states.length ? 'Loading screenshots…' : running ? 'Screenshots appear as Playwright captures page states.' : 'No browser state captures were recorded.'}</p>}
  </section>;
}

function RequestSection({ events }: { events: ProgressEvent[] }) {
  const reqs = events.filter(e => e.action === 'broker.admit');
  const byRoute = new Map<string, number>();
  for (const r of reqs) { const route = (r.route || '/').split('?')[0]!; byRoute.set(route, (byRoute.get(route) ?? 0) + 1); }
  const methods = new Map<string, number>();
  for (const r of reqs) methods.set(r.method ?? 'GET', (methods.get(r.method ?? 'GET') ?? 0) + 1);
  const probes = reqs.filter(r => (r.route ?? '').includes('?')).length;
  return <section className="cdrawer-sec">
    <h3 className="cdrawer-h3">Traffic · {reqs.length} requests · {reqs.filter(r => r.allowed === false).length} denied · {probes} with probe parameters</h3>
    <p className="cdrawer-methods">{[...methods].map(([m, n]) => <span key={m}><code>{m}</code> {n}</span>)}</p>
    <BarList items={[...byRoute].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([route, n]) => ({ label: <code>{route}</code>, value: n, color: palette.blue }))} />
  </section>;
}

function ScannerSection({ tool }: { tool: ScannerResult }) {
  return <section className="cdrawer-sec">
    <h3 className="cdrawer-h3">{tool.tool} <code>{tool.version}</code> · {tool.state} · {tool.observations.length} observations</h3>
    <ul className="cdrawer-list">
      {tool.observations.map((o, i) => { const level = o.severity ?? o.reported_severity ?? 'info'; return <li key={i}>
        <span className="cdrawer-sev" style={{ color: severityColor[level.toLowerCase()] ?? palette.gray }}>{level}</span>
        <span>{o.title}<small><code>{o.rule_id}</code>{o.locations ? ` · ${o.locations.length} locations` : ''}{o.mapped_control ? ` · → ${o.mapped_control}` : ''}</small></span>
      </li>; })}
      {tool.errors.map((e, i) => <li key={`e${i}`} className="is-err"><span className="cdrawer-sev">error</span><span>{e}</span></li>)}
      {!tool.observations.length && !tool.errors.length && <li className="cdrawer-empty">No observations recorded.</li>}
    </ul>
  </section>;
}

function AiSection({ ai, running, focus }: { ai: AiRecord | null; running: boolean; focus: NodeId }) {
  if (!ai) return <p className="cdrawer-empty">Loading AI records…</p>;
  const calls = ai.model_calls;
  const spend = calls.reduce((n, c) => n + (c.cost || 0), 0);
  return <section className="cdrawer-sec">
    {focus !== 'gateway' && <>
      <h3 className="cdrawer-h3">Reasoning · {ai.hypotheses.length} follow-ups{ai.adaptive_stop ? ` · stopped: ${ai.adaptive_stop.reason.replaceAll('_', ' ')}` : ''}</h3>
      <AiReasoning hypotheses={ai.hypotheses} running={running} />
    </>}
    <h3 className="cdrawer-h3">Model calls · {calls.length} · ${fmt(spend, 4)} spent</h3>
    <table className="cdrawer-table">
      <thead><tr><th>Role</th><th>Model</th><th>Result</th><th className="num">Latency</th><th className="num">Cost</th></tr></thead>
      <tbody>{calls.map(c => { const a = c.attempts.at(-1); return <tr key={c.id}>
        <td><code>{c.role}</code></td><td><code>{a?.model ?? '—'}</code></td>
        <td className={c.state === 'completed' ? 'ok' : 'dim'}>{c.state}</td>
        <td className="num">{a ? `${fmt(a.elapsed_seconds, 1)}s` : '—'}</td><td className="num">${fmt(c.cost ?? 0, 4)}</td>
      </tr>; })}</tbody>
    </table>
    {!calls.length && <p className="cdrawer-empty">{running ? 'Model calls appear as the planner runs.' : 'No model calls were recorded.'}</p>}
  </section>;
}

/** Signal → hypothesis → operation → challenge → outcome, as recorded by the coordinator. */
export function AiReasoning({ hypotheses, running }: { hypotheses: Hypothesis[]; running: boolean }) {
  if (!hypotheses.length) return <p className="cdrawer-empty">{running ? 'The planner runs after the baseline finishes. Its follow-ups appear here.' : 'No AI follow-ups were needed for this assessment.'}</p>;
  return <ol className="reason">{hypotheses.map(h => <li key={h.id} className={`reason-item state-${h.state}`}>
    <div className="reason-head"><span className="reason-round">R{h.round}</span><code>{h.control}</code><span className={`reason-state`}>{h.state}</span><span className="reason-cost">${fmt(h.cost, 4)} · ≤{h.max_requests} requests</span></div>
    <dl>
      <div><dt>Signal</dt><dd>{h.signal}</dd></div>
      <div><dt>Follow-up</dt><dd><code>{h.operation}</code> on <code>{h.route}</code></dd></div>
      <div><dt>Alternative tested</dt><dd>{h.alternative}</dd></div>
      {h.challenge?.alternative_explanation && <div><dt>Verifier challenge</dt><dd>{h.challenge.alternative_explanation}</dd></div>}
      {h.challenge?.missing_proof && <div><dt>Missing proof</dt><dd>{h.challenge.missing_proof}</dd></div>}
    </dl>
  </li>)}</ol>;
}

function VaultSection({ evidence, scanId }: { evidence: Evidence[]; scanId: string }) {
  const by = new Map<string, number>();
  for (const e of evidence) by.set(e.producer, (by.get(e.producer) ?? 0) + 1);
  return <section className="cdrawer-sec">
    <h3 className="cdrawer-h3">Sealed artifacts · {evidence.length}</h3>
    <BarList items={[...by].sort((a, b) => b[1] - a[1]).map(([p, n]) => ({ label: <code>{p}</code>, value: n, color: palette.yellow }))} />
    <ul className="cdrawer-list">{evidence.slice(-8).reverse().map(e => <li key={e.id}><code className="cdrawer-hash">{e.content_hash.slice(0, 12)}</code>
      <span>{e.summary}<small>{e.producer} · {fmt((e.content_bytes ?? 0) / 1024, 1)} KB</small></span>
      <a className="ops-btn" href={`/api/scans/${scanId}/evidence/${encodeURIComponent(e.id)}/download`} aria-label="Download artifact"><DownloadSimple size={13} /></a></li>)}</ul>
  </section>;
}

function ScoreSection({ categories, scanId, running }: { categories: CategoryTile[]; scanId: string; running: boolean }) {
  return <section className="cdrawer-sec">
    <h3 className="cdrawer-h3">Coverage by category</h3>
    <BarList unit="%" max={100} items={categories.filter(c => c.in_profile).map(c => ({ label: `${c.category} ${c.title}`, value: Math.round(c.coverage_percent), color: c.score !== null ? palette.green : palette.yellow, note: c.score !== null ? `score ${c.score}` : 'not scored' }))} />
    {!running && <p className="cdrawer-methods"><a className="ops-btn" href={`/api/scans/${scanId}/export.html`} download>HTML report</a> <a className="ops-btn" href={`/api/scans/${scanId}/export.json`} download>JSON</a></p>}
  </section>;
}
