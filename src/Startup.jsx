import React, {useEffect, useState} from 'react';
import App from './App.jsx';

export default function Startup() {
  const [phase, setPhase] = useState('opening');
  useEffect(() => {
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    // One short brand cycle on initial app mount; never used as analysis progress.
    const finish = setTimeout(() => setPhase('leaving'), reduced ? 0 : 850);
    const remove = setTimeout(() => setPhase('ready'), reduced ? 0 : 1050);
    return () => {clearTimeout(finish); clearTimeout(remove);};
  }, []);
  return <>
    <div inert={phase !== 'ready'}><App /></div>
    {phase !== 'ready' && <div className={`startup-screen ${phase}`} role="status" aria-label="Opening SecureMailScope">
      <div className="startup-mark"><svg viewBox="0 0 120 90" fill="none" aria-hidden="true"><path className="startup-outline" d="M10 15H110V75H10Z"/><path className="startup-seam" d="M10 75 43 40M110 75 77 40"/><path className="startup-fold" d="M10 15 60 52 110 15"/></svg></div>
      <span className="startup-name">SecureMailScope<span>.</span></span>
      <div className="startup-track" aria-hidden="true"><span/></div>
      <span className="startup-caption">Opening your workspace</span>
    </div>}
  </>;
}
