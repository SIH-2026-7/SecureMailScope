import React, {useEffect, useRef, useState} from 'react';
import {Badge, Button, DetailGrid, Heading, Modal, Panel} from './components.jsx';
import {Icon} from './icons.jsx';
import {getAnalysis, uploadCapture, exportUrl} from './api/client';
import PostureScoreGauge from './components/PostureScoreGauge';
import './tailwind.css';

type Evidence = {frame_no: number; timestamp: number; stream_id: string};
type Finding = {rule_id: string; severity: string; title: string; description: string; remediation: string; evidence: Evidence};
type Session = {session_id: string; protocol: string; client_ip: string; server_ip: string; server_port: number; session_score: number | null; tls: Record<string, any>; certificate: Record<string, any> | null; findings: Finding[]; commands: (Evidence & {direction: string; line: string; state: string})[]; warnings: string[]; ml_status: string; ml_risk_class: string | null; ml_anomaly_score: number | null; ml_is_anomaly: boolean | null; score_breakdown: {source: string; id: string; deduction: number}[]};
type Report = {job_id: string; overall_posture_score: number | null; capture_meta: Record<string, any>; summary: Record<string, number>; sessions: Session[]; limitations: string[]; ml: Record<string, any>};
const demos = [
  ['hardened', 'Modern TLS baseline', 'TLS 1.3 negotiation; encrypted certificate remains unobserved.'],
  ['cleartext_auth', 'Cleartext authentication', 'SMTP, IMAP and POP3 authentication with redacted evidence.'],
  ['expired_cert', 'Expired certificate', 'TLS 1.2 certificate, checked against the capture timestamp.'],
  ['starttls_downgrade', 'STARTTLS failure', 'Plaintext authentication continues after an upgrade request.'],
];
const time = (ts: number) => new Date(ts * 1000).toISOString();

function FindingCard({finding: f, onEvidence}: {finding: Finding; onEvidence?: () => void}) {
  return <details className="capture-finding"><summary><Badge>{f.severity}</Badge> <strong>{f.rule_id} · {f.title}</strong><span className="muted">Frame {f.evidence.frame_no}</span></summary>
    <p>{f.description}</p><p><strong>Remediation:</strong> {f.remediation}</p><a onClick={onEvidence ? event => {event.preventDefault(); onEvidence();} : undefined} href={`#frame-${f.evidence.stream_id}-${f.evidence.frame_no}`}>Frame {f.evidence.frame_no}</a> · <span className="muted">{time(f.evidence.timestamp)}</span>
  </details>;
}

function SessionDetail({session: s}: {session: Session}) {
  const cert = s.certificate;
  return <>
    <DetailGrid items={{Client: s.client_ip, Server: `${s.server_ip}:${s.server_port}`, TLS: s.tls.version || 'Not observed', Cipher: s.tls.cipher_suite || 'Not observed', SNI: s.tls.sni || 'Not observed', Score: s.session_score ?? 'Unassessed'}} />
    <h3>Deterministic findings</h3>{s.findings.length ? s.findings.map(f => <FindingCard key={f.rule_id} finding={f} />) : <p className="muted">No configured rules triggered in the available evidence.</p>}
    <h3>ML signal · separate from rule evidence</h3>
    <DetailGrid items={{'Risk class': s.ml_risk_class || 'Unavailable', 'Anomaly score': s.ml_anomaly_score ?? 'Unavailable', Anomaly: s.ml_is_anomaly === null ? 'Unavailable' : s.ml_is_anomaly ? 'Flagged' : 'Not flagged', Model: s.ml_status}} />
    <p className="notice">AI operates on normalized cryptographic features, not raw packet content. Models are trained on synthetic scenarios; this is a demonstration signal.</p>
    <h3>Explainable score</h3><p>100 minus rule deductions and the ML penalty, clamped to 0–100. Partial sessions remain unassessed.</p>
    {s.score_breakdown.map((item, i) => <div className="barlabel" key={i}><span>{item.source === 'ml' ? 'ML risk' : 'Rule'} · {item.id}</span><strong>−{item.deduction}</strong></div>)}
    <h3 style={{marginTop: 24}}>X.509 certificate</h3>
    {cert ? <><DetailGrid items={{Subject: cert.subject, Issuer: cert.issuer, 'Valid from': cert.not_before, 'Valid until': cert.not_after, 'Days remaining at capture': cert.days_until_expiry, 'SAN names': cert.sans.join(', ') || 'None', 'Hostname match': cert.hostname_match === null ? 'Unknown: no SNI' : String(cert.hostname_match), 'Key bits': cert.key_bits || 'Unknown', Signature: cert.signature_algorithm, Trust: cert.trust_status, Revocation: cert.revocation_status, 'SHA-256 fingerprint': cert.fingerprint_sha256}} />
      <div className="timeline">{cert.chain.map((c: any, i: number) => <div className="event" key={i}><small>{i === 0 ? 'Leaf' : 'Chain certificate'} · frame {cert.evidence.frame_no}</small><code>{c.subject}</code></div>)}</div></> : <p className="notice">Certificate not observable in this capture. TLS 1.3 encrypts certificate messages. Certificate checks are unknown.</p>}
    <h3>Reconstructed timeline</h3><div className="timeline">{s.commands.map((c, i) => <div className="event" id={s.commands.findIndex(item => item.frame_no === c.frame_no) === i ? `frame-${s.session_id}-${c.frame_no}` : undefined} key={i}><small>Frame {c.frame_no} · {time(c.timestamp)} · {c.direction} · {c.state}</small><code>{c.line}</code></div>)}</div>
    {s.warnings.map((warning, i) => <p className="notice" key={i}>{warning}</p>)}
  </>;
}

export default function CaptureWorkspace() {
  const [report, setReport] = useState<Report | null>(null);
  const [job, setJob] = useState(() => sessionStorage.getItem('securemailscope-job') || '');
  const [busy, setBusy] = useState(false), [progress, setProgress] = useState(0), [error, setError] = useState('');
  const [protocol, setProtocol] = useState('All'), [risk, setRisk] = useState('All'), [query, setQuery] = useState(''), [sort, setSort] = useState('score');
  const [selected, setSelected] = useState<Session | null>(null), [tab, setTab] = useState('Overview');
  const fileInput = useRef<HTMLInputElement>(null), lock = useRef(false);
  useEffect(() => {
    if (!job) return;
    const controller = new AbortController(); let timer: ReturnType<typeof setTimeout>;
    setBusy(true);
    async function poll() {
      try {
        const result = await getAnalysis(job, controller.signal);
        if (result.status === 'done') {setReport(result.report); setBusy(false); lock.current = false;}
        else if (result.status === 'error') {setError(result.error); setBusy(false); lock.current = false;}
        else timer = setTimeout(poll, 1000);
      } catch (e: any) {if (!controller.signal.aborted) {setError(e.message); setBusy(false); lock.current = false;}}
    }
    poll();
    return () => {controller.abort(); clearTimeout(timer);};
  }, [job]);

  async function analyze(file?: File) {
    if (!file || lock.current) return;
    lock.current = true; setError(''); setProgress(0); setBusy(true); setReport(null); setSelected(null);
    try {
      if (!/\.pcap(ng)?$/i.test(file.name)) throw new Error('Choose a .pcap or .pcapng file.');
      if (file.size > 50 * 1024 * 1024) throw new Error('Capture exceeds the 50 MB limit.');
      const result = await uploadCapture(file, setProgress);
      sessionStorage.setItem('securemailscope-job', result.job_id); setJob(result.job_id); setTab('Overview');
    } catch (e: any) {setError(e.message); setBusy(false); lock.current = false;}
  }
  async function demo(key: string) {
    if (lock.current) return;
    try {const response = await fetch(`/captures/${key}.pcap`); if (!response.ok) throw new Error('Demo capture not found. Run dataset_generation/generate_traffic.py.'); await analyze(new File([await response.blob()], `${key}.pcap`));}
    catch (e: any) {setError(e.message);}
  }
  const rows = (report?.sessions || []).filter(s => (protocol === 'All' || s.protocol === protocol) && (risk === 'All' || s.findings.some(f => f.severity === risk)) && `${s.session_id} ${s.client_ip} ${s.server_ip}`.toLowerCase().includes(query.toLowerCase())).sort((a, b) => sort === 'score' ? (a.session_score ?? 101) - (b.session_score ?? 101) : a.session_id.localeCompare(b.session_id));
  return <>
    <Heading title="Capture analysis" subtitle="From captured packets to traceable findings. Processed by your local analysis service." />
    <div className="capture-demo-grid">{demos.map(([key, title, description]) => <Panel key={key} className="reportcard"><Icon name="file" size={23} /><h3>{title}</h3><p>{description}</p><Button disabled={busy} onClick={() => demo(key)}>Analyze demo PCAP</Button></Panel>)}</div>
    <section className="upload" onDragOver={e => e.preventDefault()} onDrop={e => {e.preventDefault(); if (!busy) analyze(e.dataTransfer.files[0]);}}>
      <Icon name="upload" size={30} /><h2>Drop a PCAP or PCAPNG capture</h2><p className="muted">Up to 50 MB · SHA-256 integrity · SMTP / IMAP / POP3 / TLS</p>
      <input ref={fileInput} type="file" accept=".pcap,.pcapng" aria-label="Upload capture for analysis" disabled={busy} onChange={e => {analyze(e.target.files?.[0]); e.target.value = '';}} />
      {busy && <><p role="status">{progress < 100 ? `Uploading capture… ${progress}%` : 'Reconstructing streams and evaluating evidence…'}</p><progress aria-label="Upload progress" max={100} value={progress} /></>}
    </section>
    {error && <div className="notice capture-error" role="alert">{error}</div>}
    {report && <>
      <div className="capture"><Icon name="file" size={26} /><div><strong>{report.capture_meta.filename}</strong><div className="meta">{report.capture_meta.packet_count} packets · {time(report.capture_meta.start_time)} · {report.capture_meta.extractor}</div></div><Badge>Analysis complete</Badge></div>
      <div className="toolbar">{['Overview', 'Sessions', 'Findings', 'Reports'].map(t => <Button key={t} primary={tab === t} onClick={() => setTab(t)}>{t}</Button>)}</div>
      {tab === 'Overview' && <>
        <div className="stats">{[['Sessions', report.summary.total_sessions], ['Critical findings', report.summary.critical_findings], ['High findings', report.summary.high_findings], ['Medium findings', report.summary.medium_findings]].map(([label, value]) => <div className="stat" key={label}><div className="statlabel">{label}</div><div className="statvalue">{value}</div></div>)}</div>
        <div className="twocol"><Panel title="Observed security posture"><div className="panelbody"><PostureScoreGauge score={report.overall_posture_score} /><p className="capture-score-caption">{report.summary.assessed_sessions} of {report.summary.total_sessions} sessions assessed</p><p className="muted">Mean of assessed session scores. Open a session to inspect every rule and ML deduction.</p></div></Panel>
        <Panel title="Structured-feature AI"><div className="panelbody"><Badge type="low">OFFLINE INFERENCE</Badge><h3>Cryptographic features, not email content</h3><p>Random Forest classifies risk; Isolation Forest flags unusual feature combinations. Deterministic findings remain independently inspectable.</p><p className="notice">Synthetic training data · {report.ml.status || 'Model unavailable'} · No production accuracy claim</p><Button onClick={() => setTab('Sessions')}>Inspect session signals</Button></div></Panel></div>
        {report.summary.total_sessions === 0 && <p className="notice">No supported email or TLS sessions were found. This capture has no security score.</p>}
      </>}
      {tab === 'Sessions' && <><div className="toolbar"><input type="search" placeholder="Search session or IP…" aria-label="Search captured sessions" value={query} onChange={e => setQuery(e.target.value)} /><select aria-label="Capture protocol" value={protocol} onChange={e => setProtocol(e.target.value)}>{['All', 'SMTP', 'IMAP', 'POP3', 'TLS'].map(p => <option key={p}>{p}</option>)}</select><select aria-label="Finding severity" value={risk} onChange={e => setRisk(e.target.value)}>{['All', 'Critical', 'High', 'Medium', 'Low', 'Info'].map(p => <option key={p}>{p}</option>)}</select><select aria-label="Sort sessions" value={sort} onChange={e => setSort(e.target.value)}><option value="score">Lowest score first</option><option value="id">Session ID</option></select></div>
        <Panel title="Reconstructed sessions"><div className="tablewrap"><table><thead><tr>{['Session', 'Endpoints', 'TLS', 'Score', 'Top finding', 'ML risk'].map(t => <th key={t}>{t}</th>)}</tr></thead><tbody>{rows.map(s => <tr key={s.session_id}><td><Button className="textbutton" onClick={() => setSelected(s)}>{s.session_id}</Button><small>{s.protocol}</small></td><td>{s.client_ip}<small>→ {s.server_ip}:{s.server_port}</small></td><td>{s.tls.version || 'Not observed'}</td><td>{s.session_score ?? 'Unassessed'}</td><td>{[...s.findings].sort((a, b) => ['Critical', 'High', 'Medium', 'Low', 'Info'].indexOf(a.severity) - ['Critical', 'High', 'Medium', 'Low', 'Info'].indexOf(b.severity))[0]?.title || 'None observed'}</td><td>{s.ml_risk_class || 'Unavailable'}</td></tr>)}{!rows.length && <tr><td colSpan={6} className="empty">No matching sessions.</td></tr>}</tbody></table></div></Panel></>}
      {tab === 'Findings' && <>{report.sessions.filter(s => s.findings.length).map(s => <Panel key={s.session_id} className="lab"><h3>{s.session_id}</h3>{s.findings.map(f => <FindingCard key={f.rule_id} finding={f} onEvidence={() => setSelected(s)} />)}<Button onClick={() => setSelected(s)}>Open evidence timeline</Button></Panel>)}{report.sessions.every(s => !s.findings.length) && <p className="notice">No configured rules triggered. Review coverage and limitations before drawing conclusions.</p>}</>}
      {tab === 'Reports' && <><div className="cards">{['json', 'html', 'pdf'].map(format => <Panel key={format} className="reportcard"><h2>{format.toUpperCase()} report</h2><p>Capture identity, session findings, evidence, remediation, score deductions and assessment limitations.</p><a className="capture-download focus-visible:outline-2 focus-visible:outline-offset-4" href={exportUrl(report.job_id, format)}>Download {format.toUpperCase()}</a></Panel>)}</div><Panel className="lab"><h3>Capture integrity</h3><code className="capture-hash">{report.capture_meta.sha256}</code><p>SHA-256 of the original uploaded capture. Raw uploads are deleted after analysis; redacted reports persist locally.</p></Panel></>}
      <details className="notice"><summary>Coverage and assessment limitations</summary>{report.limitations.map(limit => <p key={limit}>{limit}</p>)}</details>
    </>}
    <p className="notice">Offline-first: captures go to your local FastAPI service. Raw credential payloads and message bodies are omitted from reports. Demo PCAPs are generated laboratory traffic.</p>
    {selected && <Modal title={`${selected.session_id} · packet evidence`} onClose={() => setSelected(null)}><SessionDetail session={selected} /></Modal>}
  </>;
}

