import { useState } from 'react';
import { Globe, MagnifyingGlass } from '@phosphor-icons/react';
import type { HostDiscoveryCoverage, HostInventoryEntry, HostPriorityPlan, HostSource, Summary } from './api';
import './host-inventory.css';

const SOURCE_LABEL: Record<HostSource, string> = { crawl: 'Crawl', link: 'Linked', 'certificate-transparency': 'Certificate log', dns: 'DNS' };

function dnsText(host: HostInventoryEntry) {
  if (host.dns_status === 'resolvable') return host.dns_addresses?.length ? `Resolves to ${host.dns_addresses.slice(0, 3).join(', ')}${host.dns_addresses.length > 3 ? ` +${host.dns_addresses.length - 3}` : ''}` : 'Resolves in DNS';
  if (host.dns_status === 'unresolved') return 'No DNS record found';
  if (host.dns_status === 'unavailable') return 'DNS check unavailable';
  return null;
}

function Provenance({ host }: { host: HostInventoryEntry }) {
  const dns = dnsText(host);
  const wildcard = host.observations?.some(item => item.wildcard);
  if (!host.sources?.length && !dns) return null;
  return <div className="dash-host-sources">
    {host.sources?.map(source => <span key={source}>{SOURCE_LABEL[source]}</span>)}
    {wildcard && <span>Wildcard certificate</span>}
    {dns && <small className={`dns-${host.dns_status}`}>{dns}</small>}
  </div>;
}

const COVERAGE_NOTE: Record<string, string> = {
  certificate_transparency_first_page_only: 'Only the first page of certificate-log results was read.',
  certificate_transparency_recent_window: 'Only recent certificates were searched.',
  certificate_transparency_host_cap: 'The certificate-log host limit was reached.',
  certificate_transparency_source_unavailable: 'Certificate logs could not be reached.',
  crt_sh_source_unavailable: 'crt.sh was unavailable; a fallback log was used.',
  dns_count_or_time_cap: 'DNS checks stopped at their count or time limit.',
  dns_source_unavailable: 'DNS lookups were unavailable.',
  response_size_cap: 'A certificate-log response hit its size limit.',
  source_time_cap: 'A certificate-log query hit its time limit.',
};
const coverageNote = (code: string) => COVERAGE_NOTE[code] ?? code.replace(/_/g, ' ') + '.';

function passiveText(coverage: HostDiscoveryCoverage, found: number) {
  const domain = coverage.registrable_domain ?? 'this domain';
  if (coverage.state === 'complete') return `Certificate-log discovery found ${found} host${found === 1 ? '' : 's'} for ${domain}.`;
  if (coverage.state === 'partial') return `Certificate-log discovery for ${domain} was partial; more hosts may exist.`;
  if (coverage.state === 'source_unavailable') return `Certificate logs were unavailable for ${domain}; subdomains may be missing from this list.`;
  if (coverage.state === 'not_applicable') return 'Certificate-log discovery does not apply to this target.';
  return 'Certificate-log discovery did not run for this scan; only crawled and linked hosts are listed.';
}

export function HostInventory({ hosts, failed, discovery, running, priorities }: {
  priorities?: HostPriorityPlan | null;
  hosts: HostInventoryEntry[] | null;
  failed: boolean;
  discovery: Summary['discovery'];
  running: boolean;
}) {
  const [query, setQuery] = useState('');
  const [showAll, setShowAll] = useState(false);
  const ranked = new Map((priorities?.hosts ?? []).map((row, index) => [row.host, { row, index }]));
  const ordered = [...(hosts ?? [])].sort((a, b) => (ranked.get(a.host)?.index ?? 9999) - (ranked.get(b.host)?.index ?? 9999));
  const matches = ordered.filter(host => host.host.toLowerCase().includes(query.trim().toLowerCase()));
  const visible = query || showAll ? matches : matches.slice(0, 8);
  const unassessed = (hosts ?? []).filter(host => host.role !== 'primary').length;
  return <section className="dash-panel dash-hosts" aria-labelledby="host-inventory-heading">
    <div className="dash-panel-heading">
      <div><h2 id="host-inventory-heading">Discovered websites <span className="dash-count">{hosts?.length ?? '—'}</span></h2><p>{hosts ? `${unassessed} discovered hosts have not been assessed in this scan.` : 'Collecting the websites referenced during exploration.'}</p></div>
      <label className="dash-search"><MagnifyingGlass size={16} /><input aria-label="Search discovered websites" placeholder="Search a host or subdomain" value={query} onChange={event => setQuery(event.target.value)} /></label>
    </div>
    <div className="dash-discovery-note">
      <Globe size={18} aria-hidden="true" />
      <div>{priorities && <p><strong>Assessment priorities</strong> · Evidence-backed applications come first. Every owned host stays on the list. Priority is not a vulnerability score.</p>}<p>Discovery identifies a host. Assessment requires its own approved scan. Being listed here does not mean a website was tested or found vulnerable.</p>
        {priorities?.discovery && <p className="dash-discovery-passive">{passiveText(priorities.discovery, (hosts ?? []).filter(host => host.sources?.includes('certificate-transparency')).length)}{(priorities.discovery.state === 'complete' || priorities.discovery.state === 'partial') && priorities.discovery.target_http_requests === 0 && ' No requests were sent to discovered hosts.'}{priorities.discovery.coverage_notes.map(note => <span key={note}> {coverageNote(note)}</span>)}</p>}
        {discovery?.stopped_by ? <p className="dash-discovery-stop">Exploration stopped: {discovery.stopped_by}{typeof discovery.pages_fetched === 'number' ? ` · ${discovery.pages_fetched} pages fetched` : ''}. More websites may remain undiscovered.</p> : <p>{running ? 'Exploration is in progress; this list may grow.' : discovery ? `Exploration recorded ${discovery.pages_fetched} pages. This list only covers observed hosts.` : 'Discovery completion was not reported for this scan. This list may be incomplete.'}</p>}
      </div>
    </div>
    {failed && <p className="dash-hosts-message" role="status">Could not refresh discovered websites.{hosts ? ' Showing the last loaded inventory.' : ' Other assessment results remain available.'}</p>}
    {!hosts ? <p className="dash-hosts-message">{failed ? 'Host inventory is currently unavailable.' : 'Loading discovered websites…'}</p> : !matches.length ? <p className="dash-hosts-message">{query ? 'No discovered websites match your search.' : 'No host observations have been recorded yet.'}</p> : <ul className="dash-host-list">
      {visible.map(host => <li key={`${host.host}-${host.role}`}>
        <Globe size={18} aria-hidden="true" />
        <div className="dash-host-name"><strong>{host.host}</strong><p>{host.evidence || 'Discovery source was not recorded.'}</p><Provenance host={host} />{ranked.get(host.host)?.row && <details className="dash-host-plan"><summary>{ranked.get(host.host)!.row.priority === 'focus' ? 'Focus next' : ranked.get(host.host)!.row.owned_domain_match ? 'Assessment plan' : 'Inventory only'} · {ranked.get(host.host)!.row.evidence_level === 'observed' ? 'Based on observed evidence' : 'Needs discovery'}</summary><ul>{ranked.get(host.host)!.row.signals.map(signal => <li key={signal.code}>{signal.explanation}</li>)}</ul>{ranked.get(host.host)!.row.next_steps.map(step => <p key={step.code}><strong>{step.readiness === 'needs_test_accounts' ? 'Test accounts needed' : step.readiness === 'needs_review' ? 'Review required' : 'Next step'}</strong> · {step.description}</p>)}{ranked.get(host.host)!.row.latest_scan_id && <a href={`/dashboard?scan=${ranked.get(host.host)!.row.latest_scan_id}`}>View latest assessment →</a>}</details>}</div>
        <div className="dash-host-state"><span className={`dash-status ${host.role === 'primary' ? 'host-primary' : ''}`}>{host.role === 'primary' ? 'Assessment target' : ranked.get(host.host)?.row.latest_scan_id ? 'Separate assessment available' : 'Not assessed in this scan'}</span>{host.role === 'primary' ? <small>Completed checks are shown in coverage</small> : ranked.get(host.host)?.row.latest_scan_id ? <a className="dash-button" href={`/dashboard?scan=${ranked.get(host.host)!.row.latest_scan_id}`}>Review assessment</a> : ranked.get(host.host)?.row.owned_domain_match ? <><small>Needs a separate scope and scan</small><a className="dash-button" href={`/dashboard?website=${encodeURIComponent(`https://${host.host}`)}`}>Set up assessment</a></> : <small>Ownership and assessment scope not established</small>}</div>
      </li>)}
    </ul>}
    {!query && matches.length > 8 && <div className="dash-hosts-footer"><span>{visible.length} of {matches.length} hosts shown</span><button className="dash-button" aria-expanded={showAll} onClick={() => setShowAll(value => !value)}>{showAll ? 'Show fewer' : `Show all ${matches.length} hosts`}</button></div>}
  </section>;
}
