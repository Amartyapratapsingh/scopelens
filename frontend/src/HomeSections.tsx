import { useEffect, useMemo, useRef, useState } from 'react';
import { Calculator, Check, Eye, Key, LockKey, SealCheck, Target } from '@phosphor-icons/react';
import type { ProgressEvent, ScannerResult } from './api';
import { SystemMap } from './SystemMap';
import { Panel, Stat, StackedBars, palette } from './charts';
import './ops.css';
import copy from '../../backend/scopelens/writer/plain_language.json';
import './terminal.css';
import './home-sections.css';

const controls = Object.keys(import.meta.glob('../../checks_registry/controls/*.yaml')).length;
const explanations = Object.keys(copy).length;
function storyLine(time: string, tag: string, message: string, group: string, action: string, details: Partial<ProgressEvent> = {}, units = 1) {
  return { time, tag, message, group, units, event: { action, type: action, outcome: 'completed', ...details } };
}
const lines = [
  storyLine('00:00', 'create', 'Assessment created · shop.example', 'lifecycle', 'scan.create'),
  storyLine('00:01', 'dispatch', 'Durable outbox dispatched assessment', 'lifecycle', 'outbox.dispatch'),
  storyLine('00:02', 'task', 'Supervisor admitted worker lease', 'lifecycle', 'task.admit'),
  storyLine('00:03', 'crawl', 'GET / → 200', 'http', 'broker.admit', { allowed: true, method: 'GET', route: '/' }, 2),
  storyLine('00:04', 'crawl', 'GET /robots.txt → 200', 'http', 'broker.admit', { allowed: true, method: 'GET', route: '/robots.txt' }),
  storyLine('00:05', 'crawl', 'GET /sitemap.xml → 200', 'http', 'broker.admit', { allowed: true, method: 'GET', route: '/sitemap.xml' }, 3),
  storyLine('00:06', 'scope', 'DENIED outside.example · out of scope', 'lifecycle', 'broker.admit', { allowed: false, outcome: 'denied', route: 'https://outside.example/' }),
  storyLine('00:07', 'crawl', '16 pages · 3 hosts · API inventory saved', 'http', 'broker.admit', { allowed: true, method: 'GET', route: '/catalog' }, 16),
  storyLine('00:08', 'browser', 'Playwright session leased · SPA exploration', 'browser', 'browser.admit'),
  storyLine('00:09', 'browser', 'State 4/9 captured · action 7/15', 'browser', 'browser.complete'),
  storyLine('00:10', 'browser', '9 states · 15 actions · network evidence saved', 'browser', 'browser.complete', {}, 15),
  storyLine('00:11', 'zap', 'ZAP 2.17 passive → 8 observations', 'http', 'task.settle', {}, 4),
  storyLine('00:12', 'nuclei', 'Nuclei 3.11 → reviewed templates completed', 'http', 'task.settle', {}, 3),
  storyLine('00:13', 'testssl', 'testssl.sh 3.2 → TLS and certificate measured', 'http', 'task.settle', {}, 5),
  storyLine('00:14', 'ai', 'LangGraph planner reviewed baseline evidence', 'ai', 'model.complete', {}, 2),
  storyLine('00:15', 'ai', 'Proposed follow-up → reflected XSS /search?q', 'ai', 'adaptive.plan'),
  storyLine('00:16', 'probe', 'Paired baseline + payload requests admitted', 'http', 'broker.admit', { allowed: true, method: 'GET', route: '/search?q=[redacted]' }, 2),
  storyLine('00:17', 'browser', 'Execution observed · redacted capture saved', 'browser', 'browser.complete'),
  storyLine('00:18', 'proof', 'SL-C03-XSS-01 → CONFIRMED', 'evidence', 'adaptive.complete'),
  storyLine('00:19', 'evidence', '67 artifacts sealed · sha256:b994ea…', 'evidence', 'evidence.record', {}, 12),
  storyLine('00:20', 'coverage', '12 category gates met · 1 unproven candidate', 'lifecycle', 'task.settle'),
  storyLine('00:21', 'score', 'Deterministic score computed · 72/100', 'lifecycle', 'score.ready'),
  storyLine('00:22', 'report', '17 findings · 16 proven · report ready', 'lifecycle', 'score.ready'),
];
const bucketCount = 16;
// Expand each visible terminal line into its batch of operational events.
const eventTemplates = lines.flatMap((line, lineIndex) => Array.from({ length: line.units }, () => ({
  ...line.event, lineIndex, group: line.group,
  bucket: Math.min(bucketCount - 1, Math.floor(lineIndex * bucketCount / lines.length)),
  at: new Date(Date.UTC(2026, 9, 6, 0, 0, lineIndex)).toISOString(),
}))).map((event, index) => ({ ...event, cursor: index + 1 }));
const scannerExamples: ScannerResult[] = [
  { tool: 'zap', state: 'completed', version: '2.17', errors: [], observations: [{ rule_id: '10038', title: 'Content-Security-Policy missing', evidence: 'Example response headers' }] },
  { tool: 'nuclei', state: 'completed', version: '3.11', errors: [], observations: [{ rule_id: 'exposed-config', title: 'Exposed configuration', evidence: 'Example redacted response' }] },
  { tool: 'testssl', state: 'completed', version: '3.2', errors: [], observations: [{ rule_id: 'tls-measurement', title: 'TLS measurement completed', evidence: 'Example certificate and protocol capture' }] },
];

export function useAssessmentStory() {
  const terminalRef = useRef<HTMLDivElement>(null);
  const mapRef = useRef<HTMLElement>(null);
  const [position, setPosition] = useState({ count: 0, cycle: 0 });
  const [visible, setVisible] = useState(false);
  const [pageVisible, setPageVisible] = useState(!document.hidden);
  const [reduced, setReduced] = useState(() => matchMedia('(prefers-reduced-motion: reduce)').matches);
  const active = visible && pageVisible && !reduced;
  useEffect(() => {
    const media = matchMedia('(prefers-reduced-motion: reduce)');
    const motion = () => setReduced(media.matches);
    const visibility = () => setPageVisible(!document.hidden);
    const inView = new Set<Element>();
    const observer = new IntersectionObserver(entries => {
      for (const entry of entries) {
        if (entry.isIntersecting) inView.add(entry.target);
        else inView.delete(entry.target);
      }
      setVisible(inView.size > 0);
    }, { threshold: .15 });
    for (const element of [terminalRef.current, mapRef.current]) if (element) observer.observe(element);
    media.addEventListener('change', motion);
    document.addEventListener('visibilitychange', visibility);
    return () => {
      observer.disconnect();
      media.removeEventListener('change', motion);
      document.removeEventListener('visibilitychange', visibility);
    };
  }, []);
  useEffect(() => {
    if (!active) return;
    const timer = window.setTimeout(() => setPosition(value => value.count === lines.length
      ? { count: 0, cycle: value.cycle + 1 }
      : { ...value, count: value.count + 1 }), position.count === lines.length ? 3000 : 220 + position.count % 5 * 40);
    return () => window.clearTimeout(timer);
  }, [active, position]);
  const count = reduced ? lines.length : position.count;
  const events = useMemo<ProgressEvent[]>(() => eventTemplates.filter(event => event.lineIndex < count).map(event => ({
    ...event, cursor: position.cycle * eventTemplates.length + event.cursor,
  })), [count, position.cycle]);
  const points = useMemo(() => {
    const buckets = Array.from({ length: bucketCount }, (_, index) => ({
      label: lines[Math.floor(index * lines.length / bucketCount)]!.time,
      values: {} as Record<string, number>,
    }));
    for (const event of eventTemplates) {
      if (event.lineIndex >= count || event.group === 'lifecycle') continue;
      const values = buckets[event.bucket]!.values;
      values[event.group] = (values[event.group] ?? 0) + 1;
    }
    return buckets;
  }, [count]);
  const scanners = useMemo(() => scannerExamples.filter(scanner => lines.slice(0, count).some(line => line.tag === scanner.tool)), [count]);
  return { count, cycle: position.cycle, active, reduced, events, points, scanners, terminalRef, mapRef };
}
type AssessmentStory = ReturnType<typeof useAssessmentStory>;

export function AssessmentTerminal({ story }: { story: AssessmentStory }) {
  const body = useRef<HTMLDivElement>(null);
  const { count, active, reduced, terminalRef } = story;
  useEffect(() => {
    if (body.current && !reduced) body.current.scrollTop = body.current.scrollHeight;
  }, [count, reduced]);
  const shown = lines.slice(0, count);
  return <div className={'term landing-terminal' + (active ? ' is-running' : '')} ref={terminalRef} aria-label="Example ScopeLens assessment output">
    <div className="term-bar"><div className="term-dots" aria-hidden="true"><i /><i /><i /></div><span className="term-title">example run · scopelens assess https://shop.example</span><span className={'term-conn' + (active ? ' is-live' : '')}><i />{count === lines.length ? 'done' : 'running'}</span></div>
    <div className="term-body" ref={body} tabIndex={0} aria-label="Example assessment log">
      {shown.map(line => <div className={'term-line group-' + line.group + (line.event.allowed === false ? ' is-warn' : '')} key={line.time}><time>{line.time}</time><span className="term-tag">{line.tag}</span><span className="term-text">{line.message}</span></div>)}
      {!reduced && count < lines.length && <div className="term-prompt" aria-hidden="true">$ <span className="term-cursor" /></div>}
    </div>
    <div className="term-foot"><span><b>{story.events.length}</b>events</span><span><b>{shown.some(line => line.event.action === 'evidence.record') ? 67 : 0}</b>sealed artifacts</span><span className="term-foot-warn"><b>{shown.filter(line => line.event.allowed === false).length}</b>request denied</span></div>
  </div>;
}

const throughputSeries = [
  { key: 'http', label: 'HTTP', color: palette.blue },
  { key: 'browser', label: 'Browser', color: palette.purple },
  { key: 'ai', label: 'AI', color: palette.cyan },
  { key: 'evidence', label: 'Evidence', color: palette.yellow },
];
export function HeroConsole({ story }: { story: AssessmentStory }) {
  const admitted = story.events.filter(event => event.action === 'broker.admit' && event.allowed).length;
  const decisions = story.events.filter(event => event.action === 'model.complete' || event.action.startsWith('adaptive.')).length;
  const proven = story.count === lines.length ? 16 : story.events.some(event => event.action === 'adaptive.complete') ? 1 : 0;
  const points = story.points;
  const httpSpark = points.map(point => point.values.http ?? 0);
  const aiSpark = points.map(point => point.values.ai ?? 0);
  const provenSpark = points.map((_, bucket) => {
    const completed = lines.filter((_, index) => index < story.count && Math.floor(index * bucketCount / lines.length) <= bucket);
    return completed.some(line => line.tag === 'report') ? 16 : completed.some(line => line.tag === 'proof') ? 1 : 0;
  });
  return <div className="hero-console ops-grid-12" aria-label="Example assessment console">
    <Panel title="Assessment terminal" meta="example run · SSE" className="ops-span-7 console-terminal" flush><AssessmentTerminal story={story} /></Panel>
    <div className="hero-stat-stack ops-span-5">
      <Panel title="Requests admitted" meta="scope broker"><Stat label="Approved requests" value={admitted} sub="Every destination checked" spark={httpSpark} /></Panel>
      <Panel title="AI decisions" meta="LangGraph"><Stat label="Planner activity" value={decisions} sub="Bounded follow-ups from baseline evidence" color={palette.cyan} spark={aiSpark} /></Panel>
      <Panel title="Findings proven" meta="proof rules"><Stat label="Confirmed with evidence" value={proven} sub="Models propose. Registered rules confirm." color={palette.green} spark={provenSpark} /></Panel>
    </div>
    <Panel title="Throughput" meta="events / story bucket" className="ops-span-12"><StackedBars points={points} series={throughputSeries} height={110} /></Panel>
  </div>;
}

const mapCaptions = [
  ['Control plane', 'Creates the scan, dispatches work and supervises leases.'],
  ['Policy & egress', 'Admits scoped requests and bounds outbound traffic.'],
  ['Workers', 'Crawls, explores the browser and runs integrated scanners.'],
  ['Intelligence & results', 'Plans follow-ups, proves findings and seals the report.'],
];
export function SystemMapSection({ story }: { story: AssessmentStory }) {
  return <section className="system-section shell" ref={story.mapRef} aria-labelledby="system-title">
    <div className="section-intro"><span className="section-eyebrow">01 / SYSTEM</span><h2 id="system-title">One URL. Sixteen moving parts.</h2><p>Every request passes the scope broker. Every finding passes a proof rule.</p></div>
    <div className="landing-map" data-example-cycle={story.cycle} data-example-events={story.events.length}>
      <Panel title="System map · example run" meta="16 components · live example" flush><SystemMap key={story.cycle} events={story.events} scanners={story.scanners} running={story.active} header={false} /></Panel>
    </div>
    <div className="system-captions">{mapCaptions.map(([title, description]) => <div key={title}><h3>{title}</h3><p>{description}</p></div>)}</div>
  </section>;
}

const stats = [
  [controls, 'registered controls'], [explanations, 'explained finding types'], ['12', 'security categories'],
  ['4', 'integrated scanners'], ['5', 'active paired probes'], ['100%', 'findings with evidence'],
] as const;
const categories = [
  { id: 'C01', title: 'Transport & encryption', checks: ['Plaintext HTTP serving', 'Missing HSTS', 'TLS versions and ciphers', 'Certificate validity'] },
  { id: 'C02', title: 'Server & session cookies', checks: ['Secure and HttpOnly flags', 'SameSite cookie policy', 'Over-broad cookie domains', 'Extra HTTP methods', 'Verbose server errors'] },
  { id: 'C03', title: 'Injection resistance', checks: ['Reflected XSS', 'HTML injection', 'SQL injection behavior', 'Paired baseline probes'] },
  { id: 'C04', title: 'Browser & cross-origin', checks: ['Content-Security-Policy', 'Frame and referrer policies', 'X-Content-Type-Options', 'CORS misconfiguration', 'Open redirects'] },
  { id: 'C05', title: 'Data exposure & privacy', checks: ['Exposed .env and .git', 'Config and backup.sql files', 'Directory listings', 'Leaked secrets'] },
  { id: 'C06', title: 'Components & dependencies', checks: ['Passive fingerprints', 'Exposed component versions', 'OSV advisory matches', 'Reviewed Nuclei templates'] },
  { id: 'C07', title: 'API exposure', checks: ['Endpoint discovery', 'Route and method inventory', 'Browser network evidence', 'Host and subdomain mapping'] },
];
const profiles = ['C08 Authentication & sessions', 'C09 Authorization & tenants', 'C10 Files & SSRF', 'C11 Business rules & abuse', 'C12 Domain & assets'];
const stages = [
  ['Discover', 'Crawl pages. Map hosts and APIs.', '16 pages · 3 hosts'],
  ['Browser exploration', 'Capture SPA states and traffic.', '9 states · 15 actions'],
  ['Scan', 'Run scoped scanners and probes.', 'zap · nuclei · testssl'],
  ['AI follow-ups', 'Plan bounded LangGraph checks.', '16 planner decisions'],
  ['Prove with evidence', 'Confirm proof. Seal captures.', 'proof rule → confirmed'],
  ['Score & report', 'Gate scores. Export and retest.', 'HTML + JSON report'],
] as const;
const trust = [
  [Target, 'Scope-enforced requests', 'The request broker admits or denies every destination before a request leaves.'],
  [SealCheck, 'Registered proof rules', 'Models propose checks; registered rules decide whether evidence confirms a finding.'],
  [Calculator, 'Deterministic scores', 'Code computes scores only after every category meets its coverage gate.'],
  [LockKey, 'Encrypted evidence', 'Redacted captures carry SHA-256 hashes, provenance, retention and backup support.'],
  [Key, 'Protected credentials', 'Credentials are encrypted and never sent to the AI planner.'],
  [Eye, 'Honest coverage', 'Blocked or incomplete tests stay visible as gaps and never count as passes.'],
] as const;

export function CapabilitySection() {
  return <>
    <section className="numbers-section shell" aria-label="Assessment capabilities by the numbers">
      <span className="section-eyebrow">02 / CAPACITY</span>
      <div className="ops-grid-12 registry-stats">{stats.map(([value, label]) => <Panel key={label} title={label} meta="registry" className="ops-span-2"><Stat label={label} value={value} color={palette.blue} /></Panel>)}</div>
    </section>
    <section className="checks-section shell" id="capabilities" aria-labelledby="checks-title">
      <div className="section-intro"><span className="section-eyebrow">03 / CONTROLS</span><h2 id="checks-title">What your assessment checks.</h2><p>Concrete checks, with profiles for deeper coverage.</p></div>
      <div className="checks-grid">{categories.map(category => <Panel title={category.title} meta={category.id} className="check-item" key={category.id}><ul>{category.checks.map(check => <li key={check}><Check size={14} aria-hidden="true" />{check}</li>)}</ul></Panel>)}<Panel title={<><LockKey size={14} /> Unlocked with test accounts</>} meta="C08–C12" className="authenticated-card"><div className="profile-chips">{profiles.map(profile => <span className="profile-chip" key={profile}>{profile}</span>)}</div><p>Login, access control, file handling, business-rule and domain checks run with authenticated or stateful profiles.</p></Panel></div>
    </section>
  </>;
}
export function ProcessSection() {
  return <>
    <section className="pipeline-section shell" id="how-it-works" aria-labelledby="pipeline-title">
      <div className="section-intro"><span className="section-eyebrow">04 / PIPELINE</span><h2 id="pipeline-title">Watch the work. Read the proof.</h2><p>Every stage leaves evidence and streams live progress.</p></div>
      <div className="pipeline-grid">{stages.map(([title, description, output], index) => <Panel title={title} meta={'stage 0' + (index + 1)} className="pipeline-item" key={title}><p>{description}</p><code>{output}</code></Panel>)}</div>
    </section>
    <section className="trust-section shell" aria-labelledby="trust-title">
      <div className="section-intro"><span className="section-eyebrow">05 / ASSURANCE</span><h2 id="trust-title">Built to earn your trust.</h2><p>Clear scope, reproducible proof and coverage you can inspect.</p></div>
      <div className="trust-grid">{trust.map(([Icon, title, description], index) => <Panel title={<><Icon size={14} aria-hidden="true" />{title}</>} meta={'0' + (index + 1)} key={title}><p>{description}</p></Panel>)}</div>
    </section>
  </>;
}
