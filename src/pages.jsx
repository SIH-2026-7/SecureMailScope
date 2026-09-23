import React from 'react';
import {useDemo} from './context.js';
import {Badge, Button, DetailGrid, Heading, Panel} from './components.jsx';
import {Icon} from './icons.jsx';
import {findings, generateScenario, metrics, rules, scenarios, scoreSession, severity, trace} from './engine.js';

const colors = ['#b8b8b8', '#cf946d', '#777777'];
const protocols = ['SMTP', 'IMAP', 'POP3'];
const textButton = 'textbutton';

function CaptureBanner() {
  const {state, navigate} = useDemo();
  return <div className="capture"><div className="fileicon"><Icon name="file" size={23} /></div>
    <div><strong>{scenarios[state.scenario].file}</strong><div className="meta">Synthetic capture · 19 Sep 2026, 10:00 UTC · {metrics(state.sessions).packets.toLocaleString()} fixture packets</div></div>
    <div className="right"><Badge>{state.fixes.length ? 'Remediated simulation' : 'Analysis complete'}</Badge><Button className={textButton} onClick={() => navigate('Capture analysis')}>Change capture <Icon name="chevron" size={14} /></Button></div>
  </div>;
}

function Stat({label, value, icon, children, color}) {
  return <div className="stat"><div className="statlabel">{label}<Icon name={icon} size={17} /></div><div className="statvalue" style={{color}}>{value}</div><div className="statfoot">{children}</div></div>;
}

export function Overview() {
  const {state, navigate, dispatch, exportReport, showScoring, openSession} = useDemo();
  const sessions = state.sessions, summary = metrics(sessions), groups = findings(sessions);
  const partial = sessions.filter(s => s.issues.includes('partial')).length;
  const weak = sessions.filter(s => ['TLS 1.0', 'TLS 1.1'].includes(s.tls)).length;
  const plain = sessions.filter(s => s.tls === 'None').length;
  const noPfs = sessions.filter(s => s.issues.includes('pfs')).length;
  const downgrade = sessions.some(s => s.issues.includes('downgrade'));
  return <>
    <Heading title="Security overview" subtitle="Understand the cryptographic posture of your email infrastructure.">
      <Button icon="download" onClick={() => exportReport('json')}>Export report</Button><Button primary icon="play" onClick={() => navigate('Simulation lab')}>Run simulation</Button>
    </Heading>
    <CaptureBanner />
    <div className="stats">
      <Stat label="Sessions analyzed" icon="layers" value={<>{sessions.length}<span style={{fontSize: 13, color: 'var(--muted)', fontWeight: 400, letterSpacing: 0}}> &nbsp; across {new Set(sessions.map(s => s.protocol)).size} protocols</span></>}><b>{sessions.length - partial} complete</b> · {partial} partial</Stat>
      <Stat label="Encrypted sessions" icon="lock" value={<>{Math.round(summary.encrypted / sessions.length * 100)}<span style={{fontSize: 20}}>%</span></>}>{summary.encrypted} of {sessions.length} sessions negotiated TLS</Stat>
      <Stat label="Security findings" icon="alert" value={summary.findings} color="var(--amber)">{groups.length} distinct weakness types</Stat>
      <Stat label="Critical sessions" icon="activity" value={String(summary.critical).padStart(2, '0')} color="var(--red)">{summary.critical ? 'Immediate attention recommended' : 'No critical risks in this scenario'}</Stat>
    </div>
    <div className="grid">
      <Panel title="Security posture" extra={<small>ⓘ</small>}><div className="panelbody">
        <div className="gauge" style={{'--score': summary.score}}><div className="value"><b>{summary.score ?? '—'}</b><small>OUT OF 100</small></div></div>
        <div className="gaugecaption">{summary.score >= 90 ? 'Strong posture' : summary.score >= 75 ? 'Acceptable · improvements available' : summary.score >= 50 ? 'Weak · action required' : 'High risk · action required'}</div>
        <div className="scorefoot"><span>Deterministic assessment</span><Button className={textButton} onClick={showScoring}>View scoring <Icon name="chevron" size={12} /></Button></div>
      </div></Panel>
      <Panel title="TLS distribution" extra={<small>Sessions</small>}><div className="panelbody">
        {['TLS 1.3', 'TLS 1.2', 'TLS 1.1', 'TLS 1.0'].map((tls, i) => {
          const count = sessions.filter(s => s.tls === tls).length;
          return <div className="barrow" key={tls}><div className="barlabel"><Button className={textButton} style={{color: 'inherit'}} onClick={() => {navigate('Sessions'); dispatch({type: 'filter', values: {filter: tls}});}}>{tls}</Button><span>{count} <span className="muted">/ {sessions.length}</span></span></div><div className="bar"><i style={{width: `${count / sessions.length * 100}%`, background: ['#b8b8b8', '#888888', '#cfad70', '#d78979'][i]}} /></div></div>;
        })}
        <div className="tlssummary">{weak} legacy sessions · {plain} plaintext · {partial} unknown</div>
      </div></Panel>
      <Panel title="Email protocols" extra={<small>Coverage</small>}><div className="panelbody">
        <svg width="100%" height="139" viewBox="0 0 260 139" role="img" aria-label="Protocol distribution">
          <path d="M45 123a85 85 0 0 1 170 0" stroke="var(--surface-raised)" strokeWidth="27" fill="none" />
          {protocols.map((protocol, i) => {
            const count = sessions.filter(s => s.protocol === protocol).length / sessions.length * 100;
            const offset = protocols.slice(0, i).reduce((n, p) => n + sessions.filter(s => s.protocol === p).length / sessions.length * 100, 0);
            return <path key={protocol} d="M45 123a85 85 0 0 1 170 0" pathLength="100" stroke={colors[i]} strokeWidth="27" fill="none" strokeDasharray={`${count} ${100 - count}`} strokeDashoffset={-offset} />;
          })}
          <text x="130" y="103" textAnchor="middle" fill="var(--ink)" fontSize="30" fontFamily="system-ui">{sessions.length}</text><text x="130" y="123" textAnchor="middle" fill="var(--muted)" fontSize="11">TOTAL SESSIONS</text>
        </svg>
        {protocols.map((protocol, i) => <div key={protocol} className="barlabel" style={{margin: '15px 0 0'}}><span><i style={{display: 'inline-block', width: 7, height: 7, background: colors[i], borderRadius: 2, marginRight: 7}} />{protocol}</span><span>{sessions.filter(s => s.protocol === protocol).length} <span className="muted">sessions</span></span></div>)}
      </div></Panel>
    </div>
    <div className="twocol">
      <Panel title={`Priority findings   ${groups.length}`} extra={<Button className={textButton} onClick={() => navigate('Findings')}>View all <Icon name="arrow" size={14} /></Button>}>
        {groups.length ? <div className="tablewrap"><table><thead><tr><th>Finding</th><th>Severity</th><th>Sessions</th></tr></thead><tbody>{groups.slice(0, 4).map(f => <tr key={f.key} className="clickable" onClick={() => openSession(f.sessions[0].id)}><td><Button className={textButton} style={{color: 'inherit'}} onClick={e => {e.stopPropagation(); openSession(f.sessions[0].id);}}>{f.title}</Button><small>{f.key.toUpperCase()} · Packet-linked evidence</small></td><td><Badge>{f.severity}</Badge></td><td>{String(f.sessions.length).padStart(2, '0')}</td></tr>)}</tbody></table></div> : <div className="empty">No weaknesses detected in this synthetic scenario.</div>}
      </Panel>
      <Panel title={<><Icon name="spark" size={18} /> &nbsp; Analyst insights</>} extra={<Badge type="low">EXPLAINABLE</Badge>}><div className="panelbody">
        <div className="insight"><Icon name="alert" size={18} /><div><strong>{weak ? 'Encryption does not equal security' : 'Modern encryption baseline'}</strong><p>{weak ? `${weak} sessions negotiated legacy TLS. ${noPfs} sessions lack forward secrecy.` : 'All observed negotiated versions meet the modern protocol baseline in this scenario.'}</p></div></div>
        <div className="insight"><Icon name="activity" size={18} /><div><strong>{downgrade ? 'Capability change detected' : 'No downgrade indicators'}</strong><p>{downgrade ? 'STARTTLS disappears from the synthetic server baseline. Review the transition and authentication sequence.' : 'No STARTTLS capability regression appears in the synthetic evidence.'}</p></div></div>
        <Button className={textButton} onClick={() => navigate('Simulation lab')}>Explore the evidence in the lab <Icon name="arrow" size={14} /></Button>
      </div></Panel>
    </div>
  </>;
}

export function Sessions() {
  const {state, dispatch, openSession, exportReport} = useDemo();
  const update = values => dispatch({type: 'filter', values});
  const rows = state.sessions.filter(s => (state.filter === 'All' || s.tls === state.filter || severity(s) === state.filter) && (state.protocol === 'All' || s.protocol === state.protocol) && `${s.id} ${s.server} ${s.client}`.toLowerCase().includes(state.query.toLowerCase()));
  return <><Heading title="Session explorer" subtitle="Reconstruct each connection, verify the handshake, and follow its evidence."><Button icon="download" onClick={() => exportReport('json')}>Export evidence</Button></Heading>
    <div className="toolbar"><input type="search" aria-label="Search sessions" placeholder="Search server, IP, or session ID…" value={state.query} onChange={event => update({query: event.target.value})} />
      <select aria-label="Filter protocol" value={state.protocol} onChange={event => update({protocol: event.target.value})}>{['All', ...protocols].map(p => <option key={p}>{p}</option>)}</select>
      <select aria-label="Filter risk or TLS version" value={state.filter} onChange={event => update({filter: event.target.value})}>{['All', 'Critical', 'High', 'Medium', 'Low', 'Unknown', 'TLS 1.3', 'TLS 1.2', 'TLS 1.1', 'TLS 1.0', 'None'].map(p => <option key={p}>{p}</option>)}</select>
      <Button onClick={() => update({query: '', filter: 'All', protocol: 'All'})}>Reset filters</Button>
    </div>
    <Panel title="Reconstructed sessions" extra={<small>{rows.length} matching sessions</small>}><div className="tablewrap"><table><thead><tr>{['Session', 'Endpoint', 'Protocol', 'Negotiated TLS', 'Forward secrecy', 'Risk', 'Score'].map(title => <th key={title}>{title}</th>)}</tr></thead><tbody>{rows.length ? rows.map(s => <tr key={s.id} className="clickable" onClick={() => openSession(s.id)}><td><Button className={textButton} onClick={event => {event.stopPropagation(); openSession(s.id);}}>{s.id}</Button><small>{s.time} UTC</small></td><td>{s.server}<small>{s.client} → :{s.port}</small></td><td>{s.protocol}</td><td>{s.tls}</td><td>{s.pfs}</td><td><Badge>{severity(s)}</Badge></td><td>{s.issues.includes('partial') ? '—' : scoreSession(s)} <Icon name="chevron" size={13} /></td></tr>) : <tr><td colSpan={7} className="empty">No sessions match these filters.</td></tr>}</tbody></table></div></Panel>
  </>;
}

export function Findings() {
  const {state, dispatch, fix, openSession, reset} = useDemo();
  const all = findings(state.sessions), visible = all.filter(f => state.filter === 'All' || f.severity === state.filter);
  return <><Heading title="Findings & remediation" subtitle="Evidence-backed recommendations, ordered by cryptographic risk."><Button primary icon="check" disabled={state.busy || !all.some(f => f.weight)} onClick={() => fix('all')}>Simulate all fixes</Button></Heading>
    <div className="notice">Remediation changes the simulated configuration only. No servers are contacted or modified. Re-capturing a partial handshake is a separate evidence task.</div>
    <div className="toolbar">{['All', 'Critical', 'High', 'Medium', 'Informational'].map(level => <Button key={level} primary={state.filter === level} onClick={() => dispatch({type: 'filter', values: {filter: level}})}>{level}</Button>)}</div>
    {visible.length ? visible.map(f => <Panel key={f.key} className="remediate"><Icon name={f.weight ? 'alert' : 'file'} size={23} /><div style={{flex: 1}}><h3>{f.title} &nbsp; <Badge>{f.severity}</Badge></h3><p>{f.reason}</p><p><strong style={{color: '#dce3eb'}}>{f.action}</strong></p><span className="muted" style={{fontSize: 12}}>{f.sessions.length} affected sessions · {f.weight ? `${f.weight} score-point penalty per session` : 'Not scored: incomplete evidence'}</span></div><div className="actions"><Button onClick={() => openSession(f.sessions[0].id)}>Evidence</Button>{f.weight > 0 && <Button primary disabled={state.busy} onClick={() => fix(f.key)}>Simulate fix</Button>}</div></Panel>) : <div className="panel empty">No findings in this category.</div>}
    {state.fixes.length > 0 && <div className="notice">{state.fixes.length} remediation rules applied to this simulation. <Button className={textButton} onClick={reset} disabled={state.busy}>Reset scenario</Button></div>}
  </>;
}

function ScenarioCards({load = false}) {
  const {state, dispatch, runSimulation} = useDemo();
  return <div className="cards">{Object.entries(scenarios).map(([key, scenario]) => <Panel key={key} className={`scenario ${!load && state.selected === key ? 'selected' : ''}`}>
    <Icon name={load ? 'file' : key === 'secure' ? 'shield' : key === 'downgrade' ? 'alert' : 'layers'} size={28} /><h2>{scenario.name}</h2><p>{scenario.description}</p>
    <div className="muted" style={{fontSize: 12}}>{scenario.count} synthetic sessions · SMTP / IMAP / POP3</div>
    <Button primary={load || state.selected === key} disabled={state.busy} onClick={() => load ? runSimulation(key) : dispatch({type: 'select', scenario: key})}>{load ? 'Load demonstration' : state.selected === key ? 'Selected scenario' : 'Select scenario'}</Button>
  </Panel>)}</div>;
}

export function SimulationLab() {
  const {state, reset, runSimulation, navigate, openSession} = useDemo();
  return <><Heading title="Simulation lab" subtitle="Walk through the journey from captured packets to an actionable security decision."><Button icon="refresh" disabled={state.busy} onClick={reset}>Reset scenario</Button></Heading><ScenarioCards />
    <Panel className="lab"><div className="heading"><div><h2>Packet-to-posture pipeline</h2><p className="muted">A guided replay of deterministic synthetic evidence.</p></div><Button primary icon="play" disabled={state.busy} onClick={() => runSimulation()}>{state.busy ? 'Analyzing…' : 'Run simulation'}</Button></div>
      <div className="pipeline">{['Capture intake', 'Reconstruct sessions', 'Inspect TLS & X.509', 'Evaluate risk', 'Generate report'].map((stage, i) => <div key={stage} className={`step ${state.step > i ? 'done' : ''}`}>{state.step > i ? '✓' : String(i + 1).padStart(2, '0')} &nbsp; {stage}</div>)}</div>
      <div className="terminal" aria-live="polite">{state.logs.length ? state.logs.join('\n') : '> Select a scenario and run the simulation.\n> Synthetic packet evidence is processed entirely in your browser.\n> No credentials, live connections, or trained model are required.'}</div>
      <div className="progress" role="progressbar" aria-label="Simulation progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={state.step * 20}><i style={{width: `${state.step * 20}%`}} /></div>
      {state.step === 5 && <div className="actions" style={{marginTop: 20}}><Button primary onClick={() => navigate('Overview')}>View assessment <Icon name="arrow" size={16} /></Button><Button onClick={() => openSession(state.sessions[0].id)}>Inspect first session</Button><Button onClick={() => navigate('Findings')}>Explore remediation</Button></div>}
    </Panel>
    <Panel className="lab"><div className="heading"><div><h2>What changes after remediation?</h2><p className="muted">Compare the loaded scenario against the simulated fixes.</p></div><div className="compare"><div><span>Before</span><br /><strong>{metrics(generateScenario(state.scenario)).score}</strong></div><Icon name="arrow" size={24} /><div><span>After</span><br /><strong style={{color: 'var(--green)'}}>{metrics(state.sessions).score}</strong></div></div></div><Button onClick={() => navigate('Findings')}>Open remediation workspace <Icon name="arrow" size={16} /></Button></Panel>
    <div className="notice">AI-assisted workflow demonstration: explanations are produced by transparent rules on fixture features. No trained classifier or measured model accuracy is claimed. TLS 1.3 certificate details come from lab ground truth, since those handshake messages are encrypted.</div>
  </>;
}

export function CaptureAnalysis() {
  const {state, uploadCapture, uploading} = useDemo();
  return <><Heading title="Capture analysis" subtitle="Load a reproducible demo or validate the structure of your own capture." /><ScenarioCards load />
    <section className="upload"><Icon name="upload" size={32} /><h2 style={{marginTop: 14}}>Inspect a PCAP or PCAPNG file</h2><p className="muted">File validation, packet count, and SHA-256 integrity hash · Up to 50 MB</p>
      <input type="file" accept=".pcap,.pcapng" aria-label="Select PCAP or PCAPNG capture" disabled={uploading} onChange={event => {uploadCapture(event.target.files[0]); event.target.value = '';}} />
      <p className="muted" style={{fontSize: 13}}>{uploading ? 'Inspecting capture…' : 'Local inspection only. This demo does not reconstruct TLS or score uploaded network traffic.'}</p>
    </section>
    {state.capture && <Panel className="lab"><h2>Capture intake result</h2><DetailGrid items={state.capture} /><div className="notice">Structural validation is complete. Security posture remains unassessed; use a synthetic scenario to demonstrate the analysis pipeline.</div></Panel>}
    <div className="notice">Uploaded captures never leave your browser. The synthetic assessment is separate from uploaded file metadata and will not be presented as a real analysis result.</div>
  </>;
}

export function Reports() {
  const {state, exportReport} = useDemo();
  const formats = [
    ['json', 'file', 'Structured evidence', 'Full session inventory, rule findings, scoring method, and simulation provenance.', 'Download JSON'],
    ['html', 'layers', 'Analyst report', 'A self-contained HTML report with prioritized remediation and a session appendix.', 'Download HTML'],
    ['print', 'file', 'Print-ready report', 'Open the formatted forensic report and choose “Save as PDF” in your browser’s print dialog.', 'Print / Save PDF'],
  ];
  return <><Heading title="Forensic reports" subtitle="Export a reproducible record of the current scenario and remediation state." /><CaptureBanner />
    <div className="cards">{formats.map(([format, icon, title, description, label]) => <Panel key={format} className="reportcard"><Icon name={icon} size={28} /><h2 style={{marginTop: 17}}>{title}</h2><p>{description}</p><Button primary icon={format === 'print' ? 'file' : 'download'} onClick={() => exportReport(format)}>{label}</Button></Panel>)}</div>
    <Panel className="lab"><h2>Report provenance</h2><DetailGrid items={{'Evidence source': 'Deterministic synthetic fixture', Engine: 'SecureMailScope Demo 1.0 · Rules-based', Assessment: state.fixes.length ? 'After simulated remediation' : 'Original scenario', 'Finding instances': metrics(state.sessions).findings}} /><p className="muted" style={{fontSize: 14}}>Exports contain synthetic session metadata, not uploaded packet bytes. The JSON report includes a SHA-256 hash of its evidence payload for integrity verification.</p></Panel>
  </>;
}

export function SessionDetails({session: s}) {
  return <><p className="muted">SYNTHETIC SESSION EVIDENCE · {s.server}</p><Badge>{severity(s)}</Badge> &nbsp; <Badge type="unknown">{s.issues.includes('partial') ? 'Partial evidence' : 'Complete fixture'}</Badge>
    <DetailGrid items={{Client: s.client, 'Service port': s.port, 'Negotiated protocol': s.tls, 'Cipher suite': s.cipher, 'Forward secrecy': s.pfs, Certificate: s.cert, 'Posture score': s.issues.includes('partial') ? 'Not assessed' : `${scoreSession(s)}/100`, 'Evidence origin': 'Synthetic lab fixture'}} />
    <h3>Connection reconstruction</h3><div className="timeline">{trace(s).map(([frame, title, body]) => <div className="event" key={frame}><small>Frame {frame} · {title}</small><code>{body}</code></div>)}</div>
    <h3>Explainable assessment</h3>{s.issues.length ? s.issues.map(key => <div className="finding" key={key}><strong>{rules[key].title}</strong><p>{rules[key].reason}</p><span>{rules[key].action}</span></div>) : <div className="notice">No configured risk rules triggered. This means the synthetic features meet this demo’s baseline, not that an actual endpoint has been verified.</div>}
    <h3 style={{marginTop: 23}}>X.509 fixture context</h3><DetailGrid items={{'Subject / SAN': s.cert === 'SAN mismatch' ? 'unrelated.example.org' : s.server, 'Validity at capture time': s.cert === 'Expired' ? 'Expired 01 Sep 2026' : ['None', 'Unknown'].includes(s.tls) ? 'Not observed' : 'Lab interval: 01 Jan – 31 Dec 2026'}} />
    <p className="muted" style={{fontSize: 13}}>Certificate attributes are synthetic ground truth. Trust-chain and revocation validation are not performed. Encrypted email content is never decrypted.</p>
  </>;
}

export function Scoring() {
  return <><p>Each complete session starts at 100. Triggered rule weights are subtracted and the result is clamped to zero. Overall posture is the rounded mean of assessed sessions.</p>
    {Object.entries(rules).map(([key, rule]) => <div className="barlabel" key={key} style={{margin: '20px 0'}}><span>{rule.title}</span><strong>{rule.weight ? `−${rule.weight}` : 'Excluded'}</strong></div>)}
    <div className="notice">Incomplete handshake sessions are excluded from the overall score. This transparent demo score is not a validated risk model or a compliance certification.</div>
  </>;
}
