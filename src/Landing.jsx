import React, {useEffect, useRef, useState} from 'react';
import {Icon} from './icons.jsx';
import InteractiveEnvelope from './InteractiveEnvelope.jsx';
import ProjectLinks from './ProjectLinks.jsx';

const traces = {
  secure: {label: 'Secure negotiation', status: 'TLS established', tone: 'safe', lines: [['01', 'S → C', '220 mail.example.test ESMTP'], ['02', 'C → S', 'EHLO client.example.test'], ['03', 'S → C', '250-STARTTLS'], ['04', 'C → S', 'STARTTLS'], ['05', 'S → C', '220 Ready to start TLS'], ['06', 'C ↔ S', 'TLS 1.3 · AES_256_GCM_SHA384']], note: 'A negotiated encrypted channel. Certificate contents remain unobservable in TLS 1.3.'},
  exposed: {label: 'Exposed authentication', status: 'Critical finding', tone: 'risk', lines: [['01', 'S → C', '220 mail.example.test ESMTP'], ['02', 'C → S', 'EHLO client.example.test'], ['03', 'S → C', '250 AUTH LOGIN'], ['04', 'C → S', 'AUTH LOGIN'], ['05', 'C → S', '[credential redacted]'], ['06', 'S → C', '235 Authentication successful']], note: 'Authentication before encryption. Trace the finding to its packet; keep the credential out of the report.'},
};
export default function Landing({onEnter, themeButton}) {
  const [trace, setTrace] = useState('exposed');
  const [motionPaused, setMotionPaused] = useState(false);
  const root = useRef(null);
  const selected = traces[trace];
  useEffect(() => {
    let frame;
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)');
    const clamp = n => Math.max(0, Math.min(1, n));
    const update = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const node = root.current;
        if (!node) return;
        const height = window.innerHeight;
        const progress = clamp(window.scrollY / Math.max(1, document.documentElement.scrollHeight - height));
        node.style.setProperty('--reading-progress', progress);
        node.dataset.scrolled = window.scrollY > 40;
        let active = '';
        for (const id of ['solution', 'evidence', 'capabilities']) {
          const section = node.querySelector(`#${id}`);
          if (section.getBoundingClientRect().top < height * .5) active = id;
        }
        node.dataset.chapter = active;
        const process = node.querySelector('.process-line');
        const solution = node.querySelector('#solution');
        const pin = node.querySelector('.solution-pin');
        const headerHeight = node.querySelector('.landing-header').offsetHeight;
        solution.style.setProperty('--pin-top', `${headerHeight}px`);
        const canPin = !reduce.matches && pin.offsetHeight <= height - headerHeight + 2;
        solution.dataset.pinned = canPin;
        const runway = Math.max(1, solution.offsetHeight - pin.offsetHeight);
        const processProgress = canPin ? clamp((headerHeight - solution.getBoundingClientRect().top) / runway) : 1;
        process.style.setProperty('--process-progress', reduce.matches ? 1 : processProgress);
        [...process.children].forEach((step, i) => {
          step.dataset.reached = processProgress > 0 && processProgress >= i / 4;
          step.style.setProperty('--step-progress', clamp(processProgress * 4 - i));
        });
        if (!reduce.matches) {
          const heroProgress = clamp(window.scrollY / height);
          node.style.setProperty('--travel', `${heroProgress * 60}px`);
          node.style.setProperty('--scan-travel', `${heroProgress * 25}px`);
          node.style.setProperty('--paper-angle', `${-3 + heroProgress * 3}deg`);
          node.style.setProperty('--hero-tilt', `${heroProgress * -7}deg`);
          node.style.setProperty('--paper-depth', `${heroProgress * -18}px`);
          const sheet = node.querySelector('.trace-sheet');
          const reveal = clamp((height * .95 - sheet.getBoundingClientRect().top) / (height * .6));
          sheet.style.setProperty('--transcript-reveal', reveal);
        }
      });
    };
    update();
    window.addEventListener('scroll', update, {passive: true});
    window.addEventListener('resize', update);
    reduce.addEventListener('change', update);
    return () => {window.removeEventListener('scroll', update); window.removeEventListener('resize', update); reduce.removeEventListener('change', update); cancelAnimationFrame(frame);};
  }, []);
  useEffect(() => {
    const node = root.current;
    let visible = true;
    const sync = () => {node.dataset.heroRunning = visible && !document.hidden;};
    const observer = new IntersectionObserver(([entry]) => {visible = entry.isIntersecting; sync();});
    observer.observe(node.querySelector('.hero-evidence'));
    document.addEventListener('visibilitychange', sync);
    sync();
    return () => {observer.disconnect(); document.removeEventListener('visibilitychange', sync);};
  }, []);
  return <div className="landing" ref={root} data-motion-paused={motionPaused}>
    <div className="reading-progress" aria-hidden="true" />
    <a className="skip-link" href="#solution">Skip to solution</a>
    <header className="landing-header"><a href="#" className="brand"><Icon name="mail" size={29}/><span>SecureMailScope<span className="brand-period">.</span></span></a><nav aria-label="Website navigation"><a href="#solution">The approach</a><a href="#capabilities">Capabilities</a><a href="#evidence">The evidence</a><a href="#guide">How it works</a></nav><div className="landing-header-actions"><a className="header-social" href="https://github.com/SIH-2026-7/SecureMailScope" target="_blank" rel="noopener noreferrer" aria-label="GitHub (opens in a new tab)" title="GitHub"><svg viewBox="0 0 24 24" width="19" height="19" fill="currentColor" aria-hidden="true"><path d="M12 .3a12 12 0 0 0-3.8 23.4c.6.1.8-.3.8-.6v-2.3c-3.3.7-4-1.4-4-1.4-.5-1.4-1.3-1.8-1.3-1.8-1.1-.8.1-.8.1-.8 1.2.1 1.8 1.2 1.8 1.2 1.1 1.8 2.8 1.3 3.5 1 .1-.8.4-1.3.8-1.6-2.7-.3-5.5-1.4-5.5-6A4.7 4.7 0 0 1 5.6 8c-.1-.3-.5-1.6.1-3.3 0 0 1-.3 3.3 1.2a11.5 11.5 0 0 1 6 0c2.3-1.5 3.3-1.2 3.3-1.2.6 1.7.2 3 .1 3.3a4.7 4.7 0 0 1 1.2 3.3c0 4.6-2.8 5.7-5.5 6 .5.4.9 1.1.9 2.2v3.6c0 .3.2.7.8.6A12 12 0 0 0 12 .3Z"/></svg></a><a className="header-social" href="https://www.youtube.com/@Vedant_Patel_007" target="_blank" rel="noopener noreferrer" aria-label="YouTube (opens in a new tab)" title="YouTube"><svg viewBox="0 0 24 24" width="21" height="21" fill="currentColor" aria-hidden="true"><path fillRule="evenodd" d="M23 7s-.2-1.7-.9-2.4c-.9-.9-1.9-.9-2.4-1C16.3 3.3 12 3.3 12 3.3s-4.3 0-7.7.3c-.5.1-1.5.1-2.4 1C1.2 5.3 1 7 1 7s-.3 2-.3 4v2c0 2 .3 4 .3 4s.2 1.7.9 2.4c.9.9 2.1.9 2.6 1 1.9.2 7.5.3 7.5.3s4.3 0 7.7-.3c.5-.1 1.5-.1 2.4-1 .7-.7.9-2.4.9-2.4s.3-2 .3-4v-2c0-2-.3-4-.3-4ZM9.7 15.5v-7l6.5 3.5-6.5 3.5Z"/></svg></a>{themeButton}<button onClick={() => onEnter()}>Open workspace <Icon name="arrow" size={16}/></button></div></header>
    <main>
      <section className="landing-hero">
        <div className="hero-copy"><div className="eyebrow"><span className="status-dot"/> EMAIL SECURITY, UNDER EXAMINATION</div><h1>Encrypted.<br/>But <em>secure?</em></h1><p className="hero-intro">The lock is only the beginning. See what your email traffic actually reveals about its security.</p><div className="hero-actions"><button className="landing-cta" onClick={() => onEnter()}>Examine a capture <Icon name="arrow" size={19}/></button><button className="quiet-cta" onClick={() => onEnter('Overview')}>Explore the demo <span>↗</span></button></div><div className="hero-resource-actions"><a className="hero-guide-link" href="#guide">How it works <Icon name="arrow" size={16}/></a><a className="hero-guide-link" href="https://github.com/SIH-2026-7/SecureMailScope" target="_blank" rel="noopener noreferrer" aria-label="GitHub (opens in a new tab)">GitHub <Icon name="arrow" size={16}/></a><a className="hero-guide-link" href="https://www.youtube.com/@Vedant_Patel_007" target="_blank" rel="noopener noreferrer" aria-label="YouTube (opens in a new tab)">YouTube <Icon name="arrow" size={16}/></a></div><div className="hero-fineprint"><Icon name="lock" size={13}/> Local analysis. No cloud uploads. Your evidence.</div></div>
        <div className="hero-evidence"><div className="evidence-overline"><span>INSIDE THE CONNECTION</span><span>SMTP / 587</span><button className="hero-motion-toggle" aria-pressed={motionPaused} onClick={() => setMotionPaused(paused => !paused)}>{motionPaused ? 'Resume motion' : 'Pause motion'}</button></div><InteractiveEnvelope motionPaused={motionPaused} onEnter={onEnter} /><div className="evidence-slip"><div><span className="slip-index">01 / OBSERVATION</span><span className="risk-text">ENCRYPTION ≠ ASSURANCE</span></div><h3>A secure port.<br/>An insecure conversation.</h3><p>Legacy TLS. Exposed credentials. A missing upgrade.<br/>The details are in the handshake.</p><div className="slip-bottom"><span>PACKET → SESSION → FINDING</span><Icon name="arrow" size={20}/></div></div></div>
        <div className="hero-baseline"><span>BUILT FOR THE ANALYST. GROUNDED IN THE PACKET.</span><a href="#solution">Follow the evidence <span>↓</span></a></div>
      </section>
      <section className="solution-story" id="solution"><div className="solution-pin"><div className="section-index">01 / THE APPROACH</div><div className="solution-heading"><h2>Email security has<br/>a <em>visibility problem.</em></h2><p>A connection can be encrypted and still rely on weak ciphers, an expired certificate, or a failed STARTTLS upgrade. SecureMailScope turns captured traffic into an assessment you can actually inspect.</p></div><div className="process-line"><div><span>01</span><h3>Capture</h3><p>Bring a PCAP or PCAPNG.<br/>Keep analysis on your machine.</p><small>UP TO 50 MB</small></div><div><span>02</span><h3>Reconstruct</h3><p>Follow TCP streams and email<br/>protocol conversations.</p><small>SMTP · IMAP · POP3 · TLS</small></div><div><span>03</span><h3>Examine</h3><p>Inspect cryptography, rule findings,<br/>and separate ML signals.</p><small>EXPLAINABLE BY DESIGN</small></div><div><span>04</span><h3>Act</h3><p>Trace the evidence. Review the fix.<br/>Export the assessment.</p><small>JSON · HTML · PDF</small></div></div></div></section>
      <section className="evidence-story" id="evidence"><div className="evidence-story-copy"><div className="section-index">02 / NOTHING TAKEN ON TRUST</div><h2>Every finding.<br/>A <em>paper trail.</em></h2><p>Not just a red flag. The exact frame, the reconstructed conversation, and a reason you can verify.</p><div className="trace-tabs" role="group" aria-label="Illustrative connection examples">{Object.entries(traces).map(([key, item]) => <button key={key} aria-pressed={trace === key} onClick={() => setTrace(key)}>{item.label}<Icon name="arrow" size={16}/></button>)}</div><small className="example-disclaimer">Illustrative protocol transcript · not a live capture</small></div><div className={`trace-sheet ${selected.tone}`}><div className="trace-title"><span>CONNECTION TRANSCRIPT</span><Icon name="file" size={18}/></div><div className="trace-endpoints"><span>client.example.test</span><span>→</span><span>mail.example.test</span></div><div className="trace-lines">{selected.lines.map(([number, direction, command]) => <div key={number}><span>{number}</span><span>{direction}</span><code>{command}</code></div>)}</div><div className="trace-verdict" aria-live="polite"><span><Icon name={trace === 'secure' ? 'check' : 'alert'} size={18}/> {selected.status}</span><p>{selected.note}</p></div></div></section>
      <section className="capabilities-story" id="capabilities"><div className="section-index">03 / THE COMPLETE PICTURE</div><div className="capabilities-layout"><div className="capabilities-heading"><h2>Deep inspection.<br/><em>Clear conclusions.</em></h2><p>One workspace, from the first packet to the final report.</p><button className="quiet-cta" onClick={() => onEnter()}>See it in the workspace <Icon name="arrow" size={18}/></button></div><div className="capability-list">{[
        ['01', 'The conversation, reconstructed.', 'TCP stream reassembly and SMTP, IMAP, POP3 state tracking. Follow STARTTLS transitions, authentication order, and packet-linked timelines.'],
        ['02', 'Cryptography under scrutiny.', 'Negotiated TLS versions, cipher suites, forward secrecy, and downgrade indicators. Inspect observable X.509 validity, hostname, key strength, and chain trust.'],
        ['03', 'Risk with a reason.', 'Deterministic rules and inspectable score deductions. Random Forest risk classification and Isolation Forest anomaly signals stay separately labeled.'],
        ['04', 'A safe place to ask “what if?”', 'Run bundled laboratory captures or use the browser simulation to compare scenarios and explore the effect of remediation.'],
        ['05', 'Evidence that travels well.', 'Export JSON, HTML, or PDF reports with findings and remediation. SHA-256 identifies the original capture; credentials and message bodies stay out of reports.'],
      ].map(([number, title, copy]) => <article key={number}><span>{number}</span><div><h3>{title}</h3><p>{copy}</p></div></article>)}</div></div></section>
      <section className="honesty-note"><Icon name="shield" size={27}/><h3>What we can’t see,<br/>we don’t pretend to know.</h3><p>Passive analysis doesn’t decrypt email. Missing evidence stays unknown, and incomplete sessions remain unassessed. ML is trained on synthetic scenarios: a demonstration signal, not a production accuracy claim.</p></section>
      <section className="landing-close"><div className="section-index">LESS ASSUMPTION. MORE EVIDENCE.</div><h2>Read between<br/>the <em>packets.</em></h2><div><p>Your next finding is already in the capture.</p><button className="landing-cta" onClick={() => onEnter()}>Open your workspace <Icon name="arrow" size={20}/></button><ProjectLinks /></div></section>
    </main><footer className="landing-footer"><a className="brand" href="#"><Icon name="mail" size={23}/>SecureMailScope.</a><span>Crypterpillars · SIH 2026 · PS 26159</span><span>Local by design. Evidence by default.</span></footer>
  </div>;
}
