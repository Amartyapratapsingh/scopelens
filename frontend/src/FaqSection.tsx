import { useState } from 'react';
import { Plus, Minus } from '@phosphor-icons/react';
import './faq.css';

const questions = [
  ['What does ScopeLens do?', 'ScopeLens assesses your website for security weaknesses and brings the findings, supporting evidence, and suggested fixes into one report. Every assessment also shows its coverage, so you can see what was checked and what remains unassessed.'],
  ['What kinds of vulnerabilities can it find?', 'Depending on the assessment profile and available tools, checks cover areas such as HTTPS and TLS, security headers, cookies, exposed files, components, and selected web application vulnerabilities. Your report lists the checks that actually ran, including any that were blocked or could not finish.'],
  ['Where does AI fit into the assessment?', 'AI can help interpret observations, propose follow-up checks, and explain findings. Registered proof rules determine whether evidence confirms a finding. Scores and coverage are calculated from assessment results, rather than invented by a model.'],
  ['Does a high score mean my website is secure?', 'A score describes the checks completed within that assessment’s scope. It is not a guarantee that your website has no vulnerabilities. When coverage or verification is incomplete, ScopeLens explains why a score is unavailable.'],
  ['Which websites can I assess?', 'Use ScopeLens on websites you own or have permission to assess. Each scan uses a registered scope that defines the destination and permitted checks. Limits and exclusions remain attached to that assessment.'],
  ['Can I share the results with my team?', 'Yes. Completed reports can be exported as HTML or JSON, with findings, evidence references, coverage, and remediation guidance. You can also review individual findings and request a retest after making a fix.'],
];

export function FaqSection() {
  const [open, setOpen] = useState<number | null>(0);
  return <section id="faq" className="faq-section shell" aria-labelledby="faq-title">
    <div className="faq-heading"><span className="section-eyebrow">07 / QUESTIONS</span><h2 id="faq-title">Frequently asked questions.</h2><p>Understand your assessment, its evidence and its limits.</p></div>
    <div className="faq-list">{questions.map(([question, answer], i) => <div className={`faq-item ${open === i ? 'is-open' : ''}`} key={question}>
      <h3><button id={`faq-question-${i}`} aria-expanded={open === i} aria-controls={`faq-answer-${i}`} onClick={() => setOpen(open === i ? null : i)}><span>{i + 1}. {question}</span><span className="faq-symbol" aria-hidden="true">{open === i ? <Minus size={24} weight="light" /> : <Plus size={24} weight="light" />}</span></button></h3>
      <div id={`faq-answer-${i}`} role="region" aria-labelledby={`faq-question-${i}`} hidden={open !== i}><p>{answer}</p></div>
    </div>)}</div>
  </section>;
}
