import React, {useEffect, useRef, useState} from 'react';
import {createPortal} from 'react-dom';

const lines = ['TRUST THE EVIDENCE.', 'NOT THE ENVELOPE.'];
const letters = lines.flatMap((line, row) => [...line].map((letter, col) => ({letter, row, col})));

export default function InteractiveEnvelope() {
  const trigger = useRef(null), dialog = useRef(null);
  const [origin, setOrigin] = useState(null), [decoded, setDecoded] = useState(false);
  const suppressHover = useRef(false);
  function open() {
    if (origin || suppressHover.current) return;
    const rect = trigger.current.getBoundingClientRect();
    setDecoded(false);
    setOrigin({x: rect.left + rect.width / 2 - window.innerWidth / 2, y: rect.top + rect.height / 2 - window.innerHeight / 2});
  }
  function close() {suppressHover.current = true; setOrigin(null);}
  useEffect(() => {
    if (!origin) return;
    const sheet = dialog.current;
    sheet.showModal();
    const previous = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {sheet.close(); document.body.style.overflow = previous; trigger.current?.focus({preventScroll: true});};
  }, [origin]);
  return <>
    <button ref={trigger} className="envelope envelope-trigger" aria-label="Open encrypted letter" aria-haspopup="dialog" onPointerEnter={event => {if (event.pointerType === 'mouse') open();}} onPointerLeave={() => {suppressHover.current = false;}} onClick={() => {suppressHover.current = false; open();}}>
      <svg viewBox="0 0 480 285" aria-hidden="true"><path className="envelope-body" d="M35 42H445V245H35Z"/><path d="M35 42 240 180 445 42M35 245 173 136M445 245 308 136"/><g className="scan-sweep"><path className="scan-line" d="M14 157H465"/><circle cx="319" cy="157" r="5" className="scan-node"/></g></svg>
      <span className="envelope-note">HOVER TO OPEN · CLICK TO DECIPHER</span>
    </button>
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
          <div className="letter-signoff"><span>SecureMailScope</span><small>Read between the packets.</small></div>
          <p className="letter-disclaimer">An interactive illustration. Capture analysis does not decrypt email.</p>
        </div><div className="letter-pocket" aria-hidden="true"/>
      </div>
    </dialog>, document.body)}
  </>;
}
