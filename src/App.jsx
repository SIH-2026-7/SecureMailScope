import React, {createContext, useCallback, useContext, useEffect, useReducer, useRef, useState} from 'react';
import {flushSync} from 'react-dom';
import {initialState, reducer} from './state.js';
import {scenarios, rules, metrics, inspectCapture} from './engine.js';
import {createReport, download, hash, reportHtml} from './reports.js';
import {Icon} from './icons.jsx';
import {Badge, Modal} from './components.jsx';
import {Overview, Sessions, Findings, SimulationLab, CaptureAnalysis, Reports, SessionDetails, Scoring} from './pages.jsx';

const DemoContext = createContext(null);
export const useDemo = () => useContext(DemoContext);
const navigation = [
  ['Overview', 'grid'], ['Capture analysis', 'layers'], ['Sessions', 'activity'],
  ['Findings', 'alert'], ['Simulation lab', 'play'], ['Reports', 'file'],
];

export default function App() {
  const [state, dispatch] = useReducer(reducer, undefined, initialState);
  const [detail, setDetail] = useState(null);
  const [message, setMessage] = useState('');
  const [uploading, setUploading] = useState(false);
  const stateRef = useRef(state);
  const runLock = useRef(false);
  const timers = useRef(new Set());
  stateRef.current = state;

  useEffect(() => () => {timers.current.forEach(clearTimeout); timers.current.clear();}, []);
  useEffect(() => {
    if (!message) return;
    const timer = setTimeout(() => setMessage(''), 4500);
    return () => clearTimeout(timer);
  }, [message]);

  const closeDetails = useCallback(() => setDetail(null), []);
  const navigate = useCallback(page => {
    dispatch({type: 'navigate', page});
    window.scrollTo(0, 0);
  }, []);

  const runSimulation = useCallback((key = stateRef.current.selected) => {
    if (runLock.current || !Object.hasOwn(scenarios, key)) return;
    runLock.current = true;
    dispatch({type: 'start', scenario: key});
    const logs = [
      `[INTAKE] Loaded ${scenarios[key].file} • synthetic fixture validated`,
      `[STREAM] Reconstructed ${scenarios[key].count} SMTP / IMAP / POP3 sessions`,
      '[CRYPTO] Correlated STARTTLS transitions, negotiated ciphers, and lab certificate metadata',
      `[RULES] Applied ${Object.keys(rules).length} explainable risk rules; no trained AI inference`,
      '[REPORT] Assessment complete. Evidence and recommendations ready.',
    ];
    logs.forEach((log, index) => {
      const timer = setTimeout(() => {
        timers.current.delete(timer);
        dispatch({type: 'step', step: index + 1, log});
        if (index === logs.length - 1) {
          dispatch({type: 'load', scenario: key});
          runLock.current = false;
          setMessage('Simulation complete — explore the assessment.');
        }
      }, (index + 1) * 650);
      timers.current.add(timer);
    });
  }, []);

  useEffect(() => {
    const context = document.modelContext;
    if (!context?.registerTool) return;
    const lifecycle = new AbortController();
    Promise.resolve(context.registerTool({
      name: 'load_security_scenario',
      description: 'Load a synthetic SecureMailScope email security scenario.',
      inputSchema: {type: 'object', properties: {scenario: {type: 'string', enum: Object.keys(scenarios)}}, required: ['scenario'], additionalProperties: false},
      annotations: {readOnlyHint: false, untrustedContentHint: false},
      execute: async ({scenario}) => {
        if (!Object.hasOwn(scenarios, scenario)) throw Error('Unknown scenario');
        if (runLock.current) throw Error('Wait for the current simulation');
        flushSync(() => {
          dispatch({type: 'load', scenario});
          dispatch({type: 'navigate', page: 'Overview'});
        });
        return {scenario, ...metrics(stateRef.current.sessions)};
      },
    }, {signal: lifecycle.signal})).catch(() => {});
    return () => lifecycle.abort();
  }, []);

  async function exportReport(format) {
    let reportWindow;
    if (format === 'print') {
      reportWindow = window.open('', '_blank');
      if (!reportWindow) {setMessage('Allow pop-ups to open the printable report.'); return;}
    }
    try {
      const snapshot = stateRef.current;
      const report = await createReport(snapshot.sessions, snapshot.scenario, snapshot.fixes.length > 0);
      if (format === 'json') download(JSON.stringify(report, null, 2), 'securemailscope-report.json', 'application/json');
      else if (format === 'html') download(reportHtml(report), 'securemailscope-report.html', 'text/html');
      else {
        // The standalone export is a separate document; the application itself is rendered exclusively by React.
        reportWindow.document.write(reportHtml(report));
        reportWindow.document.close();
        reportWindow.focus();
      }
      setMessage(format === 'print' ? 'Report opened. Choose Print / Save as PDF.' : 'Report download prepared with evidence integrity hash.');
    } catch (error) {reportWindow?.close(); setMessage('Report export failed: ' + error.message);}
  }

  async function uploadCapture(file) {
    if (!file) return;
    setUploading(true);
    try {
      if (file.size > 50 * 1024 * 1024) throw Error('Capture exceeds the 50 MB demo limit.');
      const buffer = await file.arrayBuffer();
      const metadata = inspectCapture(buffer);
      const fingerprint = await hash(buffer);
      dispatch({type: 'capture', capture: {
        Filename: file.name, Format: metadata.format, 'Packet records': metadata.packets,
        Size: `${metadata.bytes.toLocaleString()} bytes`, 'SHA-256': fingerprint, 'Security posture': 'Not assessed',
      }});
      setMessage('Capture structure validated locally.');
    } catch (error) {dispatch({type: 'capture', capture: null}); setMessage(error.message);}
    finally {setUploading(false);}
  }

  function fix(key) {
    dispatch({type: 'fix', key});
    setMessage('Fixes simulated. Posture recalculated; partial captures remain unassessed.');
  }
  function reset() {dispatch({type: 'reset'}); setMessage('Original scenario restored.');}

  const value = {state, dispatch, navigate, runSimulation, exportReport, uploadCapture, uploading, fix, reset,
    openSession: id => setDetail({sessionId: id}), showScoring: () => setDetail({scoring: true})};
  const pages = {Overview, Sessions, Findings, 'Simulation lab': SimulationLab, 'Capture analysis': CaptureAnalysis, Reports};
  const Page = pages[state.page];
  const session = state.sessions.find(item => item.id === detail?.sessionId);

  return <DemoContext.Provider value={value}>
    <div className="layout">
      <aside>
        <div className="brand"><Icon name="shield" size={30} /><div>SecureMailScope<small>CRYPTOGRAPHIC INTELLIGENCE</small></div></div>
        <div className="navlabel">WORKSPACE</div>
        <nav className="nav" aria-label="Main navigation">{navigation.map(([name, icon]) =>
          <button key={name} className={state.page === name ? 'active' : ''} aria-current={state.page === name ? 'page' : undefined} onClick={() => navigate(name)}>
            <Icon name={icon} />{name}{name === 'Findings' && <span className="count">{metrics(state.sessions).findings}</span>}
          </button>)}</nav>
        <div className="sidebottom"><div className="offline"><strong><Icon name="lock" size={14} /> &nbsp; Local analysis</strong><br /><span className="muted">Your captures stay on this device.</span></div>
          <div className="profile"><div className="avatar">CP</div><div>Crypterpillars<small>SIH 2026 · PS 26159</small></div></div></div>
      </aside>
      <main className="main"><div className="topbar"><span>Workspace &nbsp; / &nbsp; <strong>{state.page}</strong></span><Badge><Icon name="play" size={12} /> INTERACTIVE DEMO</Badge></div>
        <div className="content"><Page /><div className="footnote"><span><Icon name="shield" size={13} /> SecureMailScope · Passive email security assessment</span><span>Synthetic evidence · Rules-based demonstration</span></div></div>
      </main>
    </div>
    {detail && <Modal title={detail.scoring ? 'How posture is scored' : `${session?.id} · ${session?.protocol}`} onClose={closeDetails}>
      {detail.scoring ? <Scoring /> : session && <SessionDetails session={session} />}
    </Modal>}
    <div id="toast" role="status" style={{display: message ? 'block' : 'none'}}>{message}</div>
  </DemoContext.Provider>;
}
