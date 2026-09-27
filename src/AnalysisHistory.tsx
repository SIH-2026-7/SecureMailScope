import React, {useEffect, useState} from 'react';
import {Badge, Button, Heading, Panel} from './components.jsx';
import {getAnalysisHistory, captureUrl, type AnalysisHistoryEntry} from './api/client';

export default function AnalysisHistory({onOpen}: {onOpen: (id: string) => void}) {
  const [history, setHistory] = useState<AnalysisHistoryEntry[]>([]);
  const [historyError, setHistoryError] = useState('');
  const [historyLoading, setHistoryLoading] = useState(true);
  const [historyVersion, setHistoryVersion] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setHistoryLoading(true);
    getAnalysisHistory(controller.signal).then(result => {
      setHistory(result.analyses); setHistoryError('');
    }).catch(e => {if (!controller.signal.aborted) setHistoryError(e.message);})
      .finally(() => {if (!controller.signal.aborted) setHistoryLoading(false);});
    return () => controller.abort();
  }, [historyVersion]);
  return <>
    <Heading title="Past file analyses" subtitle="Revisit saved captures, reopen their reports, or download the original files." />
    <Panel title="Past file analyses" extra={<Button disabled={historyLoading} onClick={() => setHistoryVersion(v => v + 1)}>Refresh</Button>}>
      <div className="panelbody"><p className="muted">Uploaded captures and their analyses are saved locally and remain available after you return.</p>
        {historyError && <p role="alert" className="notice capture-error">Could not load history: {historyError}</p>}
        {historyLoading && <p role="status">Loading analysis history…</p>}
        {!historyLoading && !historyError && !history.length && <p className="empty">No past analyses yet. Upload a PCAP or PCAPNG file to get started.</p>}
      </div>
      {!!history.length && <div className="tablewrap"><table><thead><tr><th>Capture</th><th>Uploaded</th><th>Status</th><th>Actions</th></tr></thead><tbody>
        {history.map(item => <tr key={item.job_id}>
          <td><strong>{item.filename}</strong></td>
          <td>{new Date(item.created_at).toLocaleString()}</td>
          <td><Badge>{item.status === 'done' ? 'Complete' : item.status === 'error' ? 'Failed' : 'Processing'}</Badge></td>
          <td><Button onClick={() => onOpen(item.job_id)}>{item.status === 'error' ? 'View error' : 'Open analysis'}</Button>{' '}
            {item.capture_available ? <a className="capture-download" href={captureUrl(item.job_id)}>Download capture</a> : <small>Original capture unavailable</small>}</td>
        </tr>)}
      </tbody></table></div>}
    </Panel>
  </>;
}
