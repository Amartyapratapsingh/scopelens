import type { ReactNode } from 'react';
import './ops.css';

/** Dependency-free SVG charts in a Grafana-like style. Series colours come from ops.css variables. */
export const palette = {
  green: 'var(--ops-green)', yellow: 'var(--ops-yellow)', orange: 'var(--ops-orange)', red: 'var(--ops-red)',
  blue: 'var(--ops-blue)', purple: 'var(--ops-purple)', cyan: 'var(--ops-cyan)', gray: 'var(--ops-gray)',
} as const;
export const severityColor: Record<string, string> = {
  critical: palette.red, high: palette.orange, medium: palette.yellow, low: palette.blue, info: palette.gray, informational: palette.gray,
};

export function Panel({ title, meta, actions, children, className = '', flush = false }: {
  title: ReactNode; meta?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; flush?: boolean;
}) {
  return <section className={`ops-panel ${flush ? 'is-flush' : ''} ${className}`}>
    <header className="ops-panel-head"><h3>{title}</h3>{meta && <span className="ops-panel-meta">{meta}</span>}{actions && <div className="ops-panel-actions">{actions}</div>}</header>
    <div className="ops-panel-body">{children}</div>
  </section>;
}

export function Stat({ label, value, unit, sub, spark, color = palette.blue }: {
  label: string; value: ReactNode; unit?: string; sub?: ReactNode; spark?: number[]; color?: string;
}) {
  return <div className="ops-stat">
    <span className="ops-stat-label">{label}</span>
    <strong className="ops-stat-value" style={{ color }}>{value}{unit && <small>{unit}</small>}</strong>
    {sub && <span className="ops-stat-sub">{sub}</span>}
    {spark && spark.length > 1 && <Sparkline values={spark} color={color} />}
  </div>;
}

export function Sparkline({ values, color = palette.blue, height = 28 }: { values: number[]; color?: string; height?: number }) {
  const max = Math.max(1, ...values), w = 100;
  const pts = values.map((v, i) => `${(i / Math.max(1, values.length - 1)) * w},${height - (v / max) * (height - 2) - 1}`);
  return <svg className="ops-spark" viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" aria-hidden="true">
    <polygon points={`0,${height} ${pts.join(' ')} ${w},${height}`} fill={color} opacity=".12" />
    <polyline points={pts.join(' ')} fill="none" stroke={color} strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
  </svg>;
}

export interface StackedPoint { label: string; values: Record<string, number> }
/** Stacked columns over time buckets with a y-axis and sparse x labels. */
export function StackedBars({ points, series, height = 160, unit = '' }: {
  points: StackedPoint[]; series: { key: string; label: string; color: string }[]; height?: number; unit?: string;
}) {
  const totals = points.map(p => series.reduce((n, s) => n + (p.values[s.key] ?? 0), 0));
  const max = Math.max(1, ...totals);
  const mid = max / 2;
  const ticks = [max, Number.isInteger(mid) ? mid : max > 2 ? Math.round(mid) : '', 0];
  const every = Math.max(1, Math.ceil(points.length / 8));
  return <div className="ops-chart">
    <div className="ops-chart-plot" style={{ height }}>
      <div className="ops-yaxis">{ticks.map((t, i) => <span key={i}>{t}{unit}</span>)}</div>
      <div className="ops-grid" aria-hidden="true"><i /><i /><i /></div>
      <div className="ops-cols" role="img" aria-label={`${points.length} buckets, peak ${max}${unit}`}>
        {points.map((p, i) => <div key={i} className="ops-col" title={`${p.label}\n${series.map(s => `${s.label}: ${p.values[s.key] ?? 0}`).join('\n')}`}>
          {series.map(s => (p.values[s.key] ?? 0) > 0 && <span key={s.key} style={{ height: `${((p.values[s.key] ?? 0) / max) * 100}%`, background: s.color }} />)}
        </div>)}
      </div>
    </div>
    <div className="ops-xaxis">{points.map((p, i) => <span key={i}>{i % every === 0 ? p.label : ''}</span>)}</div>
    <Legend items={series.map(s => ({ label: s.label, color: s.color, value: points.reduce((n, p) => n + (p.values[s.key] ?? 0), 0) }))} />
  </div>;
}

/** Null-safe number formatting: backend fields such as cost or latency can be null mid-scan. */
export const fmt = (v: number | null | undefined, digits = 0) =>
  typeof v === 'number' && Number.isFinite(v) ? (Number.isInteger(v) && digits <= 1 ? String(v) : v.toFixed(digits)) : '—';

/** Horizontal bars, e.g. top targets or category coverage. */
export function BarList({ items, max, unit = '' }: { items: { label: ReactNode; value: number; color?: string; note?: ReactNode }[]; max?: number; unit?: string }) {
  const top = max ?? Math.max(1, ...items.map(i => i.value));
  return <ul className="ops-barlist">{items.map((it, i) => <li key={i}>
    <span className="ops-barlist-label">{it.label}</span>
    <span className="ops-barlist-track"><span style={{ width: `${Math.max(1.5, (it.value / top) * 100)}%`, background: it.color ?? palette.blue }} /></span>
    <span className="ops-barlist-value">{fmt(it.value, 1)}{unit}{it.note && <small>{it.note}</small>}</span>
  </li>)}</ul>;
}

export function Legend({ items }: { items: { label: string; color: string; value?: number }[] }) {
  return <ul className="ops-legend">{items.map(i => <li key={i.label}><i style={{ background: i.color }} />{i.label}{i.value !== undefined && <b>{i.value}</b>}</li>)}</ul>;
}

/** Gauge for a 0–100 value (coverage, score). */
export function Gauge({ value, label, color = palette.green }: { value: number; label: string; color?: string }) {
  const v = Math.max(0, Math.min(100, value)), r = 42, c = Math.PI * r;
  return <div className="ops-gauge">
    <svg viewBox="0 0 100 58" aria-hidden="true">
      <path d={`M8,52 A${r},${r} 0 0 1 92,52`} fill="none" stroke="var(--ops-border)" strokeWidth="9" strokeLinecap="round" />
      <path d={`M8,52 A${r},${r} 0 0 1 92,52`} fill="none" stroke={color} strokeWidth="9" strokeLinecap="round" strokeDasharray={`${(v / 100) * c} ${c}`} />
    </svg>
    <strong style={{ color }}>{Math.round(v)}<small>%</small></strong>
    <span>{label}</span>
  </div>;
}

/** Bucket timestamps (ms) into n equal windows between start and end. */
export function bucketize<T>(items: T[], time: (t: T) => number, start: number, end: number, n: number, key: (t: T) => string) {
  const width = Math.max(1, (end - start) / n);
  const out: Record<string, number>[] = Array.from({ length: n }, () => ({}));
  for (const it of items) {
    const t = time(it);
    if (!Number.isFinite(t)) continue;
    const i = Math.min(n - 1, Math.max(0, Math.floor((t - start) / width)));
    const k = key(it);
    out[i]![k] = (out[i]![k] ?? 0) + 1;
  }
  return { buckets: out, width };
}
