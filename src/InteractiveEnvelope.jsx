import React, {useEffect, useRef, useState} from 'react';
import {createPortal} from 'react-dom';
import ProjectLinks from './ProjectLinks.jsx';

const lines = ['TRUST THE EVIDENCE.', 'NOT THE ENVELOPE.'];
const letters = lines.flatMap((line, row) => [...line].map((letter, col) => ({letter, row, col})));

export default function InteractiveEnvelope({motionPaused = false, onEnter}) {
  const anchor = useRef(null), flight = useRef(null);
  const trigger = useRef(null), dialog = useRef(null);
  const [origin, setOrigin] = useState(null), [decoded, setDecoded] = useState(false);
  useEffect(() => {
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
    let frame = 0, current = null, previousTime = 0;
    const update = time => {
      frame = 0;
      const node = flight.current;
      if (reduced.matches || motionPaused || document.hidden) {
        node.removeAttribute('style');
        node.dataset.travelling = false;
        current = null;
        return;
      }
      const rect = anchor.current.getBoundingClientRect();
      const progress = Math.min(1, Math.max(0, window.scrollY / (window.innerHeight * .85)));
      const eased = progress * progress * (3 - 2 * progress);
      const scale = 1 + (Math.min(112 / rect.width, .38) - 1) * eased;
      const target = {
        x: rect.left + (window.innerWidth - rect.width * scale - 20 - rect.left) * eased,
        y: rect.top + (window.innerHeight - rect.height * scale - 20 - rect.top) * eased,
        scale,
        angle: Math.sin(progress * Math.PI) * -12,
      };
      // Time-based easing keeps the flight consistent across display refresh rates.
      const blend = 1 - Math.exp(-Math.min(time - previousTime || 16, 64) / 85);
      previousTime = time;
      if (!current) current = {...target};
      let unsettled = false;
      for (const key of Object.keys(target)) {
        current[key] += (target[key] - current[key]) * blend;
        if (Math.abs(target[key] - current[key]) > .001) unsettled = true;
      }
      Object.assign(node.style, {position: 'fixed', left: '0', top: '0', width: `${rect.width}px`, transform: `translate3d(${current.x}px, ${current.y}px, 0) scale(${current.scale}) rotate(${current.angle}deg)`});
      node.dataset.travelling = progress > .6;
      if (unsettled) frame = requestAnimationFrame(update);
    };
    const schedule = () => {if (!frame) frame = requestAnimationFrame(update);};
    schedule();
    window.addEventListener('scroll', schedule, {passive: true});
    window.addEventListener('resize', schedule);
    document.addEventListener('visibilitychange', schedule);
    reduced.addEventListener('change', schedule);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener('scroll', schedule);
      window.removeEventListener('resize', schedule);
      document.removeEventListener('visibilitychange', schedule);
      reduced.removeEventListener('change', schedule);
    };
  }, [motionPaused]);
  function open() {
    if (origin) return;
    const rect = trigger.current.getBoundingClientRect();
    setDecoded(false);
    setOrigin({x: rect.left + rect.width / 2 - window.innerWidth / 2, y: rect.top + rect.height / 2 - window.innerHeight / 2});
  }
  function close() {setOrigin(null);}
  useEffect(() => {
    if (!origin) return;
    const sheet = dialog.current;
    sheet.showModal();
    const previous = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {sheet.close(); document.body.style.overflow = previous; trigger.current?.focus({preventScroll: true});};
  }, [origin]);
  return <>
    <div className="envelope-anchor" ref={anchor}><div className="envelope-flight" ref={flight}>
    <button ref={trigger} className="envelope envelope-trigger" aria-label="Open encrypted letter" aria-haspopup="dialog" onClick={open}>
      <svg viewBox="0 0 480 285" aria-hidden="true"><path className="envelope-body" d="M35 42H445V245H35Z"/><path d="M35 42 240 180 445 42M35 245 173 136M445 245 308 136"/><g className="scan-sweep"><path className="scan-line" d="M14 157H465"/><circle cx="319" cy="157" r="5" className="scan-node"/></g></svg>
      <span className="envelope-note">CLICK TO OPEN · FOLLOW THE EVIDENCE ↗</span>
    </button>
    </div></div>
    {origin && createPortal(<dialog ref={dialog} className="letter-dialog" aria-label="An encrypted letter" onCancel={event => {event.preventDefault(); close();}} onClick={event => {if (event.target === event.currentTarget) close();}} style={{'--origin-x': `${origin.x}px`, '--origin-y': `${origin.y}px`}}>
      <div className="letter-stage"><div className="letter-flap" aria-hidden="true"/>
        <div className="letter-paper"><div className="letter-meta"><span>PRIVATE CORRESPONDENCE / 001</span><button onClick={close} aria-label="Close encrypted letter">×</button></div>
          <p className="letter-label">{decoded ? 'THE MESSAGE, REVEALED' : 'A MESSAGE HIDES IN THE NOISE'}</p>
          <button className={`cipher-message ${decoded ? 'decoded' : ''}`} onClick={() => setDecoded(value => !value)} aria-label={decoded ? 'Scramble the message again' : 'Decipher the encrypted message'}>
            <span className="cipher-letters" aria-hidden="true">{letters.map(({letter, row, col}, i) => {
              const scrambled = letters[letters.length - 1 - i];
              return <span key={i} style={{'--col': decoded ? col : scrambled.col, '--row': decoded ? row : scrambled.row, '--delay': `${i * 16}ms`}}>{decoded ? letter : /[A-Z]/.test(letter) ? String.fromCharCode((letter.charCodeAt(0) - 65 + 13) % 26 + 65) : letter}</span>;
            })}</span>
            <span className="letter-instruction">{decoded ? 'Click to encrypt again ↻' : 'Click the message to decipher →'}</span>
          </button>
          <p className="letter-quote" role="status">{decoded ? '“Trust the evidence. Not the envelope.”' : 'Encrypted message ready to decipher.'}</p>
          <div className="letter-actions"><button onClick={() => {close(); onEnter('Overview');}}>Go to dashboard ↗</button><a href="#guide" onClick={close}>How it works →</a></div>
          <ProjectLinks />
          <div className="letter-signoff"><span>SecureMailScope</span><small>Read between the packets.</small></div>
          <p className="letter-disclaimer">An interactive illustration. Capture analysis does not decrypt email.</p>
        </div><div className="letter-pocket" aria-hidden="true"/>
      </div>
    </dialog>, document.body)}
  </>;
}
