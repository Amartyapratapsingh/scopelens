import { ArrowsClockwise, CaretDown, DownloadSimple, LinkSimple, MapPin, SealCheck, Warning } from '@phosphor-icons/react';
import type { Finding } from './api';
import copy from '../../backend/scopelens/writer/plain_language.json';

type Copy = { title: string; what: string; why: string; fix: string; limit: string };
export const plainLanguage = copy as Record<string, Copy>;
export const severityKey = (value: string) => value.toLowerCase() === 'informational' ? 'info' : value.toLowerCase();
export const isConfirmed = (f: Finding) => f.evidence_status.toLowerCase() === 'confirmed';
const safeLink = (value: string) => { try { return ['http:', 'https:'].includes(new URL(value).protocol); } catch { return false; } };

export function FindingRow({ finding: f, scanId, busy, onRetest, defaultOpen = false }: {
  finding: Finding; scanId: string; busy: boolean; onRetest: () => void; defaultOpen?: boolean;
}) {
  const severity = severityKey(f.severity);
  const confirmed = isConfirmed(f);
  const text = plainLanguage[f.check_id];
  const title = text ? (confirmed ? text.title : `Possible issue: ${text.title}`) : f.title;
  const observation = text && confirmed ? text.what : f.what || f.detail;
  const refs = f.references.filter(safeLink);
  return <details className={`frow sev-${severity}`} open={defaultOpen}>
    <summary>
      <span className={`sev-pill sev-${severity}`}>{severity === 'info' ? 'Info' : severity}</span>
      <span className="frow-title">
        <strong>{title}</strong>
        <small>{f.category_title ?? f.category} · {f.locations.length} location{f.locations.length === 1 ? '' : 's'} · <code>{f.check_id}</code></small>
      </span>
      <span className={`proof ${confirmed ? 'is-proven' : 'is-lead'}`}>
        {confirmed ? <SealCheck size={15} weight="fill" /> : <Warning size={15} />}
        {confirmed ? 'Proven' : 'Needs verification'}
      </span>
      <span className="frow-conf">{f.confidence} confidence</span>
      <CaretDown className="frow-caret" size={16} aria-hidden="true" />
    </summary>
    <div className="frow-body">
      <div className="frow-copy">
        <section><h4>What we found</h4><p>{observation || 'No description was recorded for this finding.'}</p>
          {!confirmed && <p className="frow-note">This is a lead from a scanner observation. A proof rule has not confirmed it yet.</p>}</section>
        <section><h4>What someone could do</h4><p>{text?.why || f.why || 'Impact has not been documented for this observation.'}</p></section>
        <section className="frow-fix"><h4>How to fix it</h4><p>{text?.fix || f.fix || 'Remediation guidance has not been recorded.'}</p></section>
        {text?.limit && <p className="frow-limit">{text.limit}</p>}
      </div>
      <aside className="frow-side">
        <section><h4><MapPin size={14} /> Where</h4>
          <ul className="frow-locs">{f.locations.map((l, i) => <li key={i}><code>{l.route}</code>
            {(l.header || l.parameter) && <span>{l.header ? `header ${l.header}` : ''}{l.header && l.parameter ? ' · ' : ''}{l.parameter ? `param ${l.parameter}` : ''}</span>}
            {l.detail && <small>{l.detail}</small>}</li>)}</ul>
        </section>
        {f.confidence_reasons.length > 0 && <section><h4>Why we're {f.confidence.toLowerCase()} confidence</h4>
          <ul className="frow-reasons">{f.confidence_reasons.map((r, i) => <li key={i}>{r}</li>)}</ul></section>}
        <section><h4>Evidence · {f.evidence_refs.length} artifact{f.evidence_refs.length === 1 ? '' : 's'}</h4>
          <div className="frow-links">
            {f.evidence_refs.map(id => <a key={id} href={`/api/scans/${scanId}/evidence/${encodeURIComponent(id)}/download`}><DownloadSimple size={13} /> {id.slice(0, 8)}</a>)}
            {refs.map((r, i) => <a key={r} href={r} target="_blank" rel="noreferrer"><LinkSimple size={13} /> Reference {i + 1}</a>)}
            {!f.evidence_refs.length && !refs.length && <span className="muted">No artifacts linked</span>}
          </div>
        </section>
        <div className="frow-actions">
          <button type="button" className="ab-button" disabled={busy || f.retest_state === 'requested'} onClick={onRetest}>
            <ArrowsClockwise size={15} /> {f.retest_state === 'requested' ? 'Retest pending' : 'Retest this issue'}
          </button>
          <span>{f.status}{f.retest_state ? ` · retest ${f.retest_state.replaceAll('_', ' ')}` : ''}</span>
        </div>
      </aside>
    </div>
  </details>;
}
