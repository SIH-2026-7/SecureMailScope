import React from 'react';
import {Icon} from './icons.jsx';
import {usePageMeta} from './seo.js';

export function PrivacyPolicy({onBack}) {
  usePageMeta('privacy');
  return <div className="legal-page">
    <header className="legal-header">
      <a href="#" className="brand"><Icon name="mail" size={24}/>SecureMailScope<span className="brand-period">.</span></a>
      <button onClick={onBack}><Icon name="arrow" size={14} style={{transform: 'rotate(180deg)'}}/> Back</button>
    </header>
    <main className="legal-content">
      <h1>Privacy Policy</h1>
      <p className="legal-updated">Last updated: September 2026</p>

      <h2>What SecureMailScope is</h2>
      <p>SecureMailScope is an email security forensics tool that analyzes PCAP and PCAPNG network capture files. It is built by the Crypterpillars team for the Smart India Hackathon 2026 (Problem Statement 26159).</p>

      <h2>Data we process</h2>
      <ul>
        <li><strong>Capture files you upload</strong> — analyzed locally in your browser or on the server you host. Raw captures are deleted after processing. We never transmit capture data to third-party services.</li>
        <li><strong>Analysis results</strong> — findings, session metadata, and reports are stored locally in your browser's storage or in your account's private database if authentication is enabled.</li>
        <li><strong>Account data</strong> — if Google Sign-In is enabled, we store your email address and a session cookie solely for authentication. No profile data is shared.</li>
      </ul>

      <h2>Data we do not collect</h2>
      <ul>
        <li>We do not read email message contents — passive analysis inspects only network-layer metadata.</li>
        <li>We do not use tracking cookies, advertising pixels, or third-party analytics by default.</li>
        <li>We do not sell, share, or license any user data.</li>
      </ul>

      <h2>Where data is stored</h2>
      <p>In the default local mode, all data stays on your device. When authentication is enabled and a backend database is configured, analysis data is stored in a server-side database with row-level security — each user can access only their own data.</p>

      <h2>Your rights</h2>
      <p>You can delete your analysis history at any time from the workspace. If authentication is enabled, signing out clears your session. To request full data deletion from the server database, contact us at <a href="mailto:securemailscope@proton.me">securemailscope@proton.me</a>.</p>

      <h2>Security</h2>
      <p>All communication uses HTTPS. Authentication tokens are stored as secure, HTTP-only cookies. The application follows OWASP best practices for input validation and output encoding.</p>

      <h2>Contact</h2>
      <p>For any privacy questions: <a href="mailto:securemailscope@proton.me">securemailscope@proton.me</a></p>
    </main>
  </div>;
}

export function TermsOfUse({onBack}) {
  usePageMeta('terms');
  return <div className="legal-page">
    <header className="legal-header">
      <a href="#" className="brand"><Icon name="mail" size={24}/>SecureMailScope<span className="brand-period">.</span></a>
      <button onClick={onBack}><Icon name="arrow" size={14} style={{transform: 'rotate(180deg)'}}/> Back</button>
    </header>
    <main className="legal-content">
      <h1>Terms of Use</h1>
      <p className="legal-updated">Last updated: September 2026</p>

      <h2>Purpose</h2>
      <p>SecureMailScope is a demonstration and educational tool for passive email security analysis. It is developed as part of Smart India Hackathon 2026, Problem Statement 26159.</p>

      <h2>No warranty</h2>
      <p>This software is provided "as is" without warranty of any kind. The security posture scores, findings, and recommendations are based on synthetic demonstration data or user-provided captures analyzed through deterministic rules and synthetic-trained models. They do not constitute a compliance certification, security audit, or professional assessment.</p>

      <h2>Acceptable use</h2>
      <ul>
        <li>You may analyze network captures that you have lawful authority to inspect.</li>
        <li>Do not upload captures containing personally identifiable information you are not authorized to process.</li>
        <li>Do not use SecureMailScope to attack, probe, or exploit mail servers.</li>
      </ul>

      <h2>Intellectual property</h2>
      <p>SecureMailScope is open source. See the <a href="https://github.com/SIH-2026-7/SecureMailScope" target="_blank" rel="noopener noreferrer">GitHub repository</a> for license details.</p>

      <h2>Limitation of liability</h2>
      <p>The Crypterpillars team shall not be liable for any damages arising from the use or inability to use this tool, including but not limited to data loss, security incidents, or misinterpretation of analysis results.</p>

      <h2>Changes</h2>
      <p>We may update these terms at any time. Continued use after changes constitutes acceptance.</p>

      <h2>Contact</h2>
      <p>Questions about these terms: <a href="mailto:securemailscope@proton.me">securemailscope@proton.me</a></p>
    </main>
  </div>;
}
