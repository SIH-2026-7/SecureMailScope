import {useEffect} from 'react';

const BASE = 'SecureMailScope';

const pageMeta = {
  landing: {
    title: 'SecureMailScope — Email Security Forensics',
    description: 'Analyze email traffic security. Upload PCAP captures, inspect TLS handshakes, detect weak ciphers, and export forensic reports — all locally.',
  },
  guide: {
    title: 'How It Works — SecureMailScope',
    description: 'Follow the mail from captured packets to an explained security result. A step-by-step guide to email forensics with SecureMailScope.',
  },
  'Capture analysis': {
    title: 'Capture Analysis — SecureMailScope',
    description: 'Upload a PCAP or PCAPNG file for local email security inspection. Validate structure, count packets, and generate SHA-256 hashes.',
  },
  'Past file analyses': {
    title: 'Analysis History — SecureMailScope',
    description: 'Browse and revisit past capture analysis results. Re-open saved reports and compare findings across sessions.',
  },
  Overview: {
    title: 'Security Overview — SecureMailScope',
    description: 'Dashboard view of email security posture, TLS distribution, protocol coverage, and priority findings from your capture analysis.',
  },
  Sessions: {
    title: 'Session Explorer — SecureMailScope',
    description: 'Reconstruct each email connection, verify TLS handshakes, and follow evidence back to individual packets.',
  },
  Findings: {
    title: 'Findings & Remediation — SecureMailScope',
    description: 'Evidence-backed security findings ordered by cryptographic risk, with actionable remediation for every issue found.',
  },
  'Simulation lab': {
    title: 'Simulation Lab — SecureMailScope',
    description: 'Walk through the analysis pipeline from captured packets to security decisions. Compare scenarios and test remediation.',
  },
  Reports: {
    title: 'Forensic Reports — SecureMailScope',
    description: 'Export reproducible forensic reports in JSON, HTML, or PDF. Includes evidence hashes and remediation guidance.',
  },
  privacy: {
    title: 'Privacy Policy — SecureMailScope',
    description: 'How SecureMailScope handles your data. Captures stay local, no tracking, no cloud uploads unless you choose authentication.',
  },
  terms: {
    title: 'Terms of Use — SecureMailScope',
    description: 'Terms of use for SecureMailScope. Synthetic demonstration data, local analysis, and responsible disclosure.',
  },
  notfound: {
    title: 'Page Not Found — SecureMailScope',
    description: 'The page you are looking for does not exist. Return to SecureMailScope home or explore the workspace.',
  },
  thankyou: {
    title: 'Analysis Complete — SecureMailScope',
    description: 'Your capture has been analyzed. Explore the results, export a forensic report, or start a new analysis.',
  },
};

/**
 * Sets <title> and <meta name="description"> dynamically per page.
 * @param {string} page - key into pageMeta
 */
export function usePageMeta(page) {
  useEffect(() => {
    const meta = pageMeta[page] || pageMeta.landing;
    document.title = meta.title;
    const descTag = document.querySelector('meta[name="description"]');
    if (descTag) descTag.setAttribute('content', meta.description);
    // Update OG tags too
    const ogTitle = document.querySelector('meta[property="og:title"]');
    const ogDesc = document.querySelector('meta[property="og:description"]');
    const twTitle = document.querySelector('meta[name="twitter:title"]');
    const twDesc = document.querySelector('meta[name="twitter:description"]');
    if (ogTitle) ogTitle.setAttribute('content', meta.title);
    if (ogDesc) ogDesc.setAttribute('content', meta.description);
    if (twTitle) twTitle.setAttribute('content', meta.title);
    if (twDesc) twDesc.setAttribute('content', meta.description);
  }, [page]);
}

export default pageMeta;
