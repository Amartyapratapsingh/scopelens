import { DownloadSimple, SealCheck } from '@phosphor-icons/react';
import { BarList, Gauge, Panel, Stat, palette, severityColor } from './charts';
import './ops.css';

type Finding = { id: string; title: string; severity: 'High' | 'Medium' | 'Low'; category: string; location: string; explanation: string; evidence: string; fix: string; proof: string };
const examples: Finding[] = [
  { id: 'xss', title: 'Search reflects executable script', severity: 'High', category: 'C03 · Injection resistance', location: '/search?q', explanation: 'A paired probe changed only the search input. The response reflected the payload in a context that executed in the browser.', evidence: 'GET /search?q=[redacted] → 200\nBrowser execution observed · capture sha256:b994ea…', fix: 'Encode search terms for their output context and enforce an appropriate Content-Security-Policy.', proof: 'SL-C03-XSS-01 · confirmed by paired probe and browser capture' },
  { id: 'csp', title: 'Content Security Policy is missing', severity: 'Medium', category: 'C04 · Browser security', location: '/', explanation: 'The response does not define which sources the browser may load. A policy can limit the impact of injected content.', evidence: 'GET / → 200\nContent-Security-Policy: not present', fix: 'Define a Content-Security-Policy for required resources. Test it in report-only mode before enforcing it.', proof: 'SL-C04-CSP-01 · confirmed by response headers' },
  { id: 'cookie', title: 'Session cookie missing HttpOnly', severity: 'Low', category: 'C02 · Session configuration', location: '/account', explanation: 'The example session cookie is readable by page scripts. HttpOnly prevents JavaScript from directly accessing its value.', evidence: 'Set-Cookie: session=[redacted]; Secure; SameSite=Lax', fix: 'Add HttpOnly to the server-generated session cookie. Keep Secure enabled and use an appropriate SameSite policy.', proof: 'SL-C02-COOKIE-01 · confirmed by response headers' },
];
const metrics = [
  { label: 'Pages', value: 16, color: palette.blue },
  { label: 'Browser states', value: 9, color: palette.purple },
  { label: 'Tests', value: 246, unit: '/290', color: palette.green },
  { label: 'AI decisions', value: 19, color: palette.cyan },
  { label: 'Evidence', value: 71, color: palette.yellow },
];
export function ProductPreview({ standalone = false }: { standalone?: boolean }) {
  function download() {
    const blob = new Blob([JSON.stringify({ example: true, website: 'https://example.com', coverage_percent: 73, findings: examples }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'scopelens-example-report.json';
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return <div className={'ops-product-preview' + (standalone ? ' standalone' : '')} aria-label="Example assessment dashboard">
    <div className="preview-stat-grid">{metrics.map(metric => <Panel title={metric.label} meta="example" key={metric.label}><Stat label={metric.label} value={metric.value} unit={metric.unit} color={metric.color} /></Panel>)}</div>
    <div className="ops-grid-12 preview-chart-grid">
      <Panel title="Finding severity" meta="13 findings · 12 proven" className="ops-span-8"><BarList items={[['High', 1], ['Medium', 4], ['Low', 7], ['Info', 1]].map(([label, value]) => ({ label: String(label), value: Number(value), color: severityColor[String(label).toLowerCase()] }))} /></Panel>
      <Panel title="Assessment coverage" meta="applicable checks" className="ops-span-4"><Gauge value={73} label="Score withheld until coverage gates pass" color={palette.yellow} /></Panel>
      <Panel title="Findings · example.com" meta="7 categories assessed · SHA-256 evidence" className="ops-span-12" flush actions={<button className="ops-btn" onClick={download}><DownloadSimple size={14} />JSON</button>}>
        <div className="ops-preview-findings">{examples.map(finding => <details className="ops-preview-finding" key={finding.id}><summary><span className={'ops-severity severity-' + finding.severity.toLowerCase()}>{finding.severity}</span><span className="ops-preview-finding-title"><strong>{finding.title}</strong><small>{finding.category} · {finding.location}</small></span><span className="ops-proven"><SealCheck size={14} weight="fill" />Proven</span></summary><div className="ops-preview-detail"><p>{finding.explanation}</p><h4>Proof rule</h4><p>{finding.proof}</p><h4>Redacted evidence</h4><pre>{finding.evidence}</pre><h4>Recommended fix</h4><p>{finding.fix}</p></div></details>)}</div>
        <div className="ops-preview-foot">Playwright · OWASP ZAP 2.17 · Nuclei 3.11 · testssl.sh 3.2<span>HTML / JSON export · Retest any finding</span></div>
      </Panel>
    </div>
  </div>;
}
