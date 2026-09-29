import React from 'react';
import {Icon} from './icons.jsx';
import {usePageMeta} from './seo.js';

export default function ThankYou({type = 'capture', onAction, onHome}) {
  usePageMeta('thankyou');
  const messages = {
    capture: {
      heading: 'Capture analyzed successfully',
      body: 'Your file has been validated and the analysis is ready for review. No data left your browser.',
      action: 'View results',
      actionIcon: 'activity',
    },
    simulation: {
      heading: 'Simulation complete',
      body: 'The synthetic scenario has been processed. Explore the security assessment and remediation workspace.',
      action: 'View assessment',
      actionIcon: 'shield',
    },
    report: {
      heading: 'Report exported',
      body: 'Your forensic report has been generated with evidence integrity hashes. Check your downloads folder.',
      action: 'Export another format',
      actionIcon: 'file',
    },
  };
  const msg = messages[type] || messages.capture;
  return <div className="thank-you-overlay">
    <div className="thank-you-card">
      <div className="thank-you-icon"><Icon name="check" size={32}/></div>
      <h2>{msg.heading}</h2>
      <p>{msg.body}</p>
      <div className="thank-you-actions">
        <button className="primary" onClick={onAction}>
          <Icon name={msg.actionIcon} size={16}/> {msg.action}
        </button>
        <button onClick={onHome}>
          Back to workspace
        </button>
      </div>
      <small className="thank-you-privacy">
        <Icon name="lock" size={12}/> Your data stays on your device. Nothing was uploaded.
      </small>
    </div>
  </div>;
}
