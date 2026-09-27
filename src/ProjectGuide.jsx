import React, {useEffect, useRef, useState} from 'react';
import {Icon} from './icons.jsx';

const steps = [
  ['A mail leaves its sender', 'An email travels between a device and a mail server. We look at the connection’s safety, not the words inside the email.', 'SMTP sends mail; IMAP and POP3 retrieve it. SecureMailScope examines a recording of this network traffic after it happened. The envelope here represents a connection, not a message being sent by this app.', 'mail'],
  ['Bring in the recording', 'Upload a PCAP or PCAPNG: a file that records small pieces of network traffic called packets.', 'The local API validates the capture format and the 50 MB size limit, calculates a SHA-256 fingerprint, and starts an analysis job. TShark extracts packets when available; Scapy provides the fallback. Raw captures are deleted after processing.', 'file'],
  ['Put the conversation in order', 'The app joins those pieces together so it can follow who spoke, what protocol they used, and when.', 'TCP streams are grouped and ordered by sequence number. Retransmissions and missing pieces are tracked. SMTP, IMAP and POP3 parsers reconstruct protocol conversations and identify authentication and STARTTLS or STLS upgrades. Incomplete evidence stays marked as incomplete.', 'layers'],
  ['Check the locks', 'Was encryption used? Was it modern? Did the connection switch to encryption before a password was sent?', 'TLS handshake evidence reveals observable versions, cipher suites and forward secrecy. When a certificate is visible, checks include capture-time expiry, hostname, key strength, signature and chain trust. TLS 1.3 hides certificate contents; passive analysis cannot decrypt email or verify encrypted authentication.', 'lock'],
  ['Turn evidence into findings', 'Clear rules flag problems and explain why they matter. A separate machine-learning signal adds another perspective.', 'Rules identify issues such as plaintext authentication, legacy TLS and failed upgrades. Findings link back to frames and include remediation. Normalized cryptographic features feed a Random Forest classifier and an Isolation Forest anomaly model. These models use synthetic training data; their signals are labeled separately from rule evidence.', 'alert'],
  ['Score, understand, and act', 'The dashboard shows the observed security posture. Open a finding to understand the evidence and the suggested fix.', 'Assessed sessions start at 100. Rule penalties are 30, 15, 7, 2 or 0 by severity, with separate ML penalties of 20, 10, 5 or 0. Scores are clamped to 0–100 and averaged across assessed sessions. Missing evidence is not a clean bill of health: incomplete sessions remain unassessed. The browser simulation is a separate rules-only demonstration.', 'activity'],
  ['Take the evidence with you', 'Export a report to share what you found and what should be improved.', 'JSON, HTML and PDF exports contain findings, evidence references and remediation. Reports persist locally in SQLite. Credentials and message bodies are excluded from exports. Suggested fixes guide a person’s next steps; the app does not change mail-server settings.', 'shield'],
];

export default function ProjectGuide({onEnter, themeButton}) {
  const [active, setActive] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [expanded, setExpanded] = useState(null);
  useEffect(() => {
    if (playing) setExpanded(active);
  }, [playing, active]);
  const [reduced, setReduced] = useState(false);
  const [progress, setProgress] = useState(0);
  const playback = useRef({playing: false, progress: 0});
  playback.current = {playing, progress};
  const track = useRef(null);
  const cards = useRef([]);
  useEffect(() => {
    const preference = window.matchMedia('(prefers-reduced-motion: reduce)');
    const sync = () => {setReduced(preference.matches); if (preference.matches) setPlaying(false);};
    sync(); preference.addEventListener('change', sync);
    return () => preference.removeEventListener('change', sync);
  }, []);
  function go(index) {
    const node = track.current;
    const target = cards.current[Math.max(0, Math.min(steps.length - 1, index))];
    node.scrollTo({left: target.offsetLeft - cards.current[0].offsetLeft, behavior: reduced ? 'instant' : 'smooth'});
  }
  useEffect(() => {
    if (!playing) return;
    const startProgress = playback.current.progress;
    const startTime = performance.now();
    let frame;
    let reached = Math.floor(startProgress * (steps.length - 1));
    const advance = now => {
      // Travel each route segment over the full five-second reading interval.
      const position = Math.min(steps.length - 1, startProgress * (steps.length - 1) + (now - startTime) / 5000);
      const next = Math.floor(position);
      if (!reduced) setProgress(position / (steps.length - 1));
      if (next > reached) {
        reached = next;
        go(next);
        if (reduced) setProgress(next / (steps.length - 1));
      }
      const finalOffset = cards.current[steps.length - 1].offsetLeft - cards.current[0].offsetLeft;
      if (position === steps.length - 1 && Math.abs(track.current.scrollLeft - finalOffset) < 1) {setExpanded(steps.length - 1); setPlaying(false); return;}
      frame = requestAnimationFrame(advance);
    };
    frame = requestAnimationFrame(advance);
    return () => cancelAnimationFrame(frame);
  }, [playing, reduced]);
  useEffect(() => {
    const node = track.current;
    const sync = () => {
      const width = cards.current[1].offsetLeft - cards.current[0].offsetLeft;
      const position = width ? node.scrollLeft / width : 0;
      setActive(Math.max(0, Math.min(steps.length - 1, Math.round(position))));
      if (!playback.current.playing) setProgress(Math.max(0, Math.min(1, position / (steps.length - 1))));
    };
    const resize = new ResizeObserver(sync);
    resize.observe(node); node.addEventListener('scroll', sync, {passive: true}); sync();
    const pauseHidden = () => {if (document.hidden) setPlaying(false);};
    document.addEventListener('visibilitychange', pauseHidden);
    return () => {resize.disconnect(); node.removeEventListener('scroll', sync); document.removeEventListener('visibilitychange', pauseHidden);};
  }, []);
  return <div className="project-guide" data-playing={playing}>
    <header className="guide-header"><a className="brand" href="#"><Icon name="mail"/>SecureMailScope.</a><div>{themeButton}<button onClick={() => onEnter('Overview')}>Go to dashboard ↗</button></div></header>
    <main className="guide-main">
      <div className="guide-intro"><div><span className="section-index">THE PROJECT, IN PLAIN ENGLISH</span><h1>Follow the mail.<br/><em>Understand the security.</em></h1></div><p>A safety inspection for email connections. Travel from recorded traffic to an explained result, one stop at a time.</p></div>
      <section className="journey-horizontal" aria-label="Interactive mail journey">
        <div className="journey-toolbar"><span className="guide-note">SCROLL SIDEWAYS · FOLLOW THE ENVELOPE</span><button aria-pressed={playing} onClick={() => {if (!playing && active === steps.length - 1) {track.current.scrollTo({left: 0, behavior: 'instant'}); setActive(0); setProgress(0);} setPlaying(value => !value);}}>{playing ? 'Pause journey' : 'Play journey'} <Icon name={playing ? 'mail' : 'play'} size={14}/></button></div>
        <nav className="journey-route" aria-label="Mail journey steps" style={{'--journey-progress': progress}}><div className="route-line" aria-hidden="true"><span/><div className="route-envelope"><Icon name="mail" size={25}/></div></div>{steps.map(([title], i) => <button key={title} className={active === i ? 'current' : i < active ? 'passed' : ''} aria-label={`Step ${i + 1}: ${title}`} aria-current={active === i ? 'step' : undefined} onClick={() => {setPlaying(false); go(i);}}><span>{String(i + 1).padStart(2, '0')}</span></button>)}</nav>
        <ol className="journey-flow" ref={track} tabIndex={0} aria-label="Journey cards; use left and right arrow keys" onPointerDown={() => setPlaying(false)} onWheel={() => setPlaying(false)} onKeyDown={event => {if (event.target === event.currentTarget && ['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {event.preventDefault(); setPlaying(false); go(event.key === 'Home' ? 0 : event.key === 'End' ? 6 : active + (event.key === 'ArrowRight' ? 1 : -1));}}}>
          {steps.map(([title, brief, detail, icon], i) => <li key={title} ref={node => {cards.current[i] = node;}} className={active === i ? 'current' : ''}><article><div className="journey-card-top"><span className="journey-step">STEP {String(i + 1).padStart(2, '0')} / 07</span><div className="journey-stamp"><Icon name={icon} size={32}/></div></div><h2>{title}</h2><p>{brief}</p><details open={expanded === i}><summary onClick={event => {event.preventDefault(); setPlaying(false); setExpanded(value => value === i ? null : i);}}><span className="read-more">Read more</span><span className="read-less">Read less</span><span aria-hidden="true">↗</span></summary><p>{detail}</p></details><div className="journey-card-footer"><span>{i === 6 ? 'EVIDENCE DELIVERED' : 'FOLLOW THE EVIDENCE'}</span><Icon name={i === 6 ? 'check' : 'arrow'} size={18}/></div></article></li>)}
        </ol>
        <div className="journey-controls"><span role="status" aria-live="polite">{String(active + 1).padStart(2, '0')} / 07 · {steps[active][0]}</span><div><button disabled={active === 0} onClick={() => {setPlaying(false); go(active - 1);}} aria-label="Previous step">←</button><button disabled={active === 6} onClick={() => {setPlaying(false); go(active + 1);}} aria-label="Next step">→</button></div></div>
      </section>
      <div className="guide-finish"><div><h2>From packets to a clearer picture.</h2><p>Try a bundled capture, or explore the simulated dashboard.</p></div><div><button className="primary" onClick={() => onEnter()}>Analyze a capture ↗</button><button onClick={() => onEnter('Overview')}>Explore dashboard ↗</button></div></div>
    </main>
  </div>;
}
