import React, {useRef, useState} from 'react';
import {Button, Panel} from './components.jsx';
import {Icon} from './icons.jsx';
import {uploadCapture} from './api/client';
const demos = [
  ['hardened', 'Modern TLS baseline', 'TLS 1.3 negotiation; encrypted certificate remains unobserved.'],
  ['cleartext_auth', 'Cleartext authentication', 'SMTP, IMAP and POP3 authentication with redacted evidence.'],
  ['expired_cert', 'Expired certificate', 'TLS 1.2 certificate, checked against the capture timestamp.'],
  ['starttls_downgrade', 'STARTTLS failure', 'Plaintext authentication continues after an upgrade request.'],
];

export default function DemoCaptures({onOpen}: {onOpen: (id: string) => void}) {
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  const lock = useRef(false);
  async function analyze(key: string) {
    if (lock.current) return;
    lock.current = true; setBusy(true); setError('');
    try {
      const response = await fetch('/captures/' + key + '.pcap');
      if (!response.ok) throw new Error('Demo capture could not be loaded.');
      const result = await uploadCapture(new File([await response.blob()], key + '.pcap'), () => {});
      onOpen(result.job_id);
    } catch (e: any) {setError(e.message);}
    finally {lock.current = false; setBusy(false);}
  }
  return <>
    <div className="capture-demo-grid">{demos.map(([key, title, description]) => <Panel key={key} className="reportcard"><Icon name="file" size={23} /><h3>{title}</h3><p>{description}</p><Button disabled={busy} onClick={() => analyze(key)}>Analyze demo PCAP</Button></Panel>)}</div>
    {busy && <p role="status">Preparing demo analysis…</p>}
    {error && <p className="notice capture-error" role="alert">{error}</p>}
  </>;
}
