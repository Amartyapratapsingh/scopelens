import { useEffect, useRef, useState } from 'react';
import { ArrowRight, ArrowUpRight, Check, Code, Database, Globe, List, LockKey, ShieldCheck, Sparkle, Terminal, X } from '@phosphor-icons/react';
import { FaqSection } from './FaqSection';
import { Dashboard } from './Dashboard';
import { ProductPreview } from './ProductPreview';
import { HeroConsole, CapabilitySection, ProcessSection, SystemMapSection, useAssessmentStory } from './HomeSections';

export function Brand() {
  return <a href="/" className="brand-link" aria-label="ScopeLens home"><span className="brand-mark" aria-hidden="true"><ShieldCheck size={24} weight="duotone" /></span><span>ScopeLens</span></a>;
}

function Navigation() {
  const dialog = useRef<HTMLDialogElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const links = [{ text: 'Home', href: '/' }, { text: 'Capabilities', href: '/#capabilities' }, { text: 'How it works', href: '/#how-it-works' }, { text: 'Dashboard', href: '/dashboard' }];
  function close() { dialog.current?.close(); }
  useEffect(() => {
    const element = dialog.current;
    if (!element) return;
    const restore = () => { document.body.style.overflow = ''; trigger.current?.focus(); };
    element.addEventListener('close', restore);
    return () => { element.removeEventListener('close', restore); document.body.style.overflow = ''; };
  }, []);
  return <header className="site-header shell">
    <Brand />
    <nav className="desktop-nav flex items-center gap-9" aria-label="Main navigation">{links.map(l => <a key={l.text} href={l.href}>{l.text}</a>)}</nav>
    <a className="ops-btn is-primary header-cta" href="/dashboard">Open dashboard <ArrowRight size={18} /></a>
    <button ref={trigger} className="menu-toggle" aria-label="Open navigation" aria-haspopup="dialog" onClick={() => { dialog.current?.showModal(); document.body.style.overflow = 'hidden'; }}><List size={28} /></button>
    <dialog ref={dialog} className="mobile-menu" aria-labelledby="menu-heading" onKeyDown={e => {
      if (e.key !== 'Tab') return;
      const items = [...e.currentTarget.querySelectorAll<HTMLElement>('a[href], button:not([disabled])')];
      const first = items[0], last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last?.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first?.focus(); }
    }} onClick={e => { if (e.target === e.currentTarget) close(); }}>
      <div className="menu-top"><span id="menu-heading">ScopeLens</span><button autoFocus aria-label="Close navigation" onClick={close}><X size={24} /></button></div>
      <nav aria-label="Mobile navigation">{links.map(l => <a href={l.href} key={l.text} onClick={close}>{l.text}<ArrowUpRight size={20} /></a>)}</nav>
      <p>Find what needs fixing.</p>
    </dialog>
  </header>;
}

function UrlForm() {
  const [value, setValue] = useState('');
  const [error, setError] = useState('');
  function submit(e: React.FormEvent) {
    e.preventDefault();
    try {
      const url = new URL(value.includes('://') ? value.trim() : `https://${value.trim()}`);
      if (!['http:', 'https:'].includes(url.protocol) || !url.hostname.includes('.') || url.username || url.password || url.search || url.hash) throw new Error('Enter a website address without credentials, query parameters or a fragment.');
      window.location.assign(`/dashboard?website=${encodeURIComponent(url.origin + url.pathname)}`);
    } catch (e) { setError(e instanceof Error && e.message.startsWith('Enter') ? e.message : 'Enter a valid website address, such as example.com.'); }
  }
  return <div className="hero-form-wrap"><form className="url-form" onSubmit={submit}>
    <Globe size={20} className="url-icon" aria-hidden="true" />
    <label className="sr-only" htmlFor="website-url">Website URL</label>
    <input id="website-url" name="website" required autoComplete="url" inputMode="url" placeholder="Enter your website URL" value={value} aria-invalid={!!error} aria-describedby={error ? 'url-error' : undefined} onChange={e => { setValue(e.target.value); setError(''); }} />
    <button className="ops-btn is-primary" type="submit">Get started <ArrowRight size={18} /></button>
  </form>{error && <p className="form-error" role="alert" id="url-error">{error}</p>}</div>;
}

function Home() {
  const story = useAssessmentStory();
  return <div className="landing-page"><a href="#main" className="skip-link">Skip to content</a><div className="hero-backdrop" aria-hidden="true" /><Navigation />
    <main id="main">
      <section className="hero shell" aria-labelledby="hero-title">
        <div className="hero-copy"><span className="section-eyebrow">00 / ASSESSMENT ENGINE</span>
          <h1 className="hero-title" id="hero-title">Find the exposure.<br /><span>Prove the risk.</span></h1>
          <p className="hero-description">ScopeLens runs browser crawl, ZAP, Nuclei, testssl.sh and AI follow-ups. Proof rules confirm findings with sealed evidence.</p>
          <UrlForm />
          <div className="hero-proof-points">{['Scope-enforced requests', 'Proof before every finding', 'Evidence sealed with SHA-256'].map(point => <span key={point}><Check size={14} aria-hidden="true" />{point}</span>)}</div>
        </div>
        <HeroConsole story={story} />
      <div className="engine-strip" aria-label="Assessment engine">
        <p>The engine behind every assessment</p>
        <div><span><Globe size={16} />Playwright</span><span><ShieldCheck size={16} />OWASP ZAP</span><span><Code size={16} />Nuclei</span><span><Terminal size={16} />testssl.sh</span><span><Sparkle size={16} />AI planner</span><span><LockKey size={16} />Proof rules</span><span><Database size={16} />Encrypted evidence vault</span></div>
      </div>
      </section>
      <SystemMapSection story={story} />
      <CapabilitySection />
      <ProcessSection />
      <section id="product" className="product-stage shell" aria-labelledby="product-title">
        <div className="section-intro"><span className="section-eyebrow">06 / REPORT</span><h2 id="product-title">A report you can work from.</h2><p>Review the finding, inspect its proof and retest after the fix.</p></div>
        <ProductPreview />
      </section>
      <FaqSection />
    </main>
    <footer className="site-footer shell"><Brand /><span>Evidence. Coverage. Clear next steps.</span><a href="/dashboard">Open dashboard <ArrowUpRight size={16} /></a></footer>
  </div>;
}

export default function App() {
  return location.pathname.replace(/\/$/, '') === '/dashboard' ? <Dashboard /> : <Home />;
}
