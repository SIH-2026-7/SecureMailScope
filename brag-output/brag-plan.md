# SecureMailScope — Brag Plan

## What is it?
A local-first email traffic security analyzer: upload a PCAP, get deterministic findings, explainable ML signals, X.509 inspection, and exportable PDF reports — all offline, all traceable to the packet.

## Who is it for?
Security analysts and forensic investigators who need to know whether email encryption is actually securing anything.

## What sets it apart?
It doesn't trust the lock icon. It reconstructs SMTP/IMAP/POP3 sessions from raw packets, inspects TLS handshakes, validates certificates at capture time, and gives you an explainable posture score — every finding traced to a frame number. No cloud. No trust assumptions.

## Most impressive claim
"Encrypted. But secure?" — it catches cleartext credentials, expired certs, STARTTLS downgrades, and weak ciphers hiding behind "secure" ports.

## Visual hook
The dark-mode forensic UI with the animated envelope being scanned, the orange accent on charcoal, the protocol transcript revealing exposed credentials.

## Tone
`polished` — serious, elegant, restrained. 3-4 scenes, long holds, soft fades.

## Visual identity
- Background: #111111 (charcoal)
- Accent: #e99069 (signal orange)
- Ink: #f1f1f1
- Red: #f19a89

## Storyboard (~20s, 30fps, 1920x1080)

### Scene 1 — Hook (0s-3s)
"Encrypted. But *secure?*" Large typography on charcoal. Orange italic for "secure?".

### Scene 2 — The Reveal (3s-8s)
SMTP transcript materializes line by line. Line 05 glows orange. Verdict: "Critical finding · AUTH-001".

### Scene 3 — The Workspace (8s-15s)
Full UI: posture gauge, session table, findings, PDF export. Pipeline: Capture → Reconstruct → Examine → Act.

### Scene 4 — Punchline (15s-20s)
"Read between the packets." + "SecureMailScope." + team credit.
