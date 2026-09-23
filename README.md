# SecureMailScope

Local email-traffic security analysis plus the original browser simulation. Upload PCAP/PCAPNG, reconstruct TCP and SMTP/IMAP/POP3 sessions, inspect TLS/X.509 evidence, evaluate deterministic rules and a separately labeled ML signal, and export JSON, HTML or PDF reports.

## Run locally

Node.js 22.12+ and Python 3.11 are required. Setup downloads dependencies; analysis makes no external API calls. The backend virtual environment has already been created in this workspace.

```powershell
npm install
# First-time backend setup (uv, or py -3.11 -m venv backend/.venv):
uv venv --python 3.11 backend/.venv
uv pip install --python backend/.venv/Scripts/python.exe -r backend/requirements.txt
npm start
```

Open [SecureMailScope](http://127.0.0.1:5173). `npm start` launches the API on port 8000 and Vite on port 5173. To run separately: `npm run api` and `npm run dev`. On Linux/macOS, create `backend/.venv` with Python 3.11 and install using `backend/.venv/bin/pip install -r backend/requirements.txt`; the launcher chooses the correct interpreter.

TShark is optional locally. When installed at OS level it is the primary extractor; otherwise Scapy is used. Set `PACKET_EXTRACTOR=scapy` to force the fallback. Docker includes TShark. PyShark is pinned as an available wrapper; the implemented primary path calls TShark directly.

## Demo flow

The app opens on the product landing page. **Open workspace** leads to **Capture analysis**, with its own Overview, Sessions, Findings and Reports tabs. Open `/#workspace` to go directly to analysis. Dark mode is the default; the theme switch persists your preference locally. The sidebar's **Browser simulation** preserves the original synthetic demonstration and simulated remediation. These results remain separate from uploaded captures.

1. **Modern TLS baseline**: analyze the demo PCAP, show a 90+ observed score, and explain the unknown TLS 1.3 certificate state.
2. **Cleartext authentication**: inspect critical AUTH-001 findings across SMTP, IMAP and POP3. Open a session for the originating frame and redacted command.
3. **Expired certificate**: inspect capture-time expiration, SAN, key strength, chain and fingerprint.
4. **STARTTLS failure**: show plaintext authentication continuing after an upgrade request.
5. Show separate ML signals and score deductions. AI uses normalized cryptographic features, not raw packet content.
6. **Reports → Download PDF** produces an actual backend-generated PDF. JSON is the source of truth; HTML is self-contained.

The 20 bundled PCAPs are constructed packet fixtures, not live-server recordings. They use the same API/parser as user uploads. See [dataset generation](dataset_generation/README.md) for labels, training, optional live Postfix/Dovecot containers and limitations.

## API and persistence

- `POST /api/upload`: multipart `file`, 50 MB limit, HTTP 202 with job_id/status.
- `GET /api/analysis/{job_id}`: processing, done with report, or error with a safe message.
- `GET /api/report/{job_id}/export?format=json|html|pdf`: download completed report.
- `GET /api/health`: local service health.

Reports persist in SQLite under `backend/data`. Override `DATA_DIR` or set `DATABASE_URL` (`postgresql+psycopg://...` for PostgreSQL). Raw captures are deleted after processing. SHA-256 identifies uploaded bytes. Interrupted jobs are marked failed on restart and can be reuploaded. Use one API worker for this local demo.

## Architecture

- `backend/app/core/pipeline.py`: run_analysis(pcap_path) → Report.
- `integrity.py`, `pcap_extractor.py`, `stream_reassembly.py`: container validation, TShark/Scapy extraction, sequence ordering and retransmission/gap flags.
- `protocol_parser.py`, `tls_parser.py`: enums/transitions, redacted commands, segmented TLS records/handshakes, supported_versions, cipher and SNI extraction.
- `cert_validator.py`: capture-time validity, SAN/key/signature/extension checks and chain verification against bundled certifi roots.
- `rule_engine.py`: pure-function registry; findings include frame, timestamp and remediation.
- `ml/`: 11 normalized features, Random Forest, XGBoost challenger, Isolation Forest and scenario-separated evaluation.
- `posture_score.py`: rule deductions 30/15/7/2/0 plus ML penalties 20/10/5/0, clamped to 0–100. Overall score averages assessed sessions.
- `report_builder.py`: escaped HTML and multipage ReportLab PDF.
- `src/CaptureWorkspace.tsx`, `src/api/client.ts`: typed capture workflow and API client; Tailwind supplements the existing design and Plotly renders the gauge.

The existing React 19/Vite app is preserved instead of downgrading to the brief's React 18 scaffold. Existing simulation pages remain JSX; new capture features are TypeScript. No external fonts/CDN assets are requested at runtime. Plotly is bundled and lazy-loaded (roughly 4.4 MB uncompressed).

## Validation

```powershell
npm test
npm run check
backend/.venv/Scripts/python.exe -m pytest backend/tests -q
backend/.venv/Scripts/python.exe -m pytest tests/test_synthetic_fixtures.py -q
```

## Synthetic PCAPNG Fixture Suite

SecureMailScope includes a reproducible, deterministic synthetic PCAPNG generation framework built with Scapy and the `cryptography` library. It generates valid, parseable wire-format PCAPNG captures with realistic Ethernet/IP/TCP layers, accurate sequence numbers, non-decreasing timestamps, and synthetic application payloads for SMTP, IMAP, POP3, and TLS.

All timestamps are deterministic, anchored at `2026-09-19 10:00:00 UTC` (`1789812000.0`), and all network endpoints utilize private documentation IP ranges (`10.24.1.10`–`10.24.1.250`) and example domains (`mail.example.test`). Credentials and mailbox contents are dummy values (`demo-user`, `demo-password`).

### Setup and Quickstart

```bash
python -m venv .venv
.venv/Scripts/activate
pip install -r requirements.txt
python generate_pcaps.py
python validate_pcaps.py
tshark -r captures/cleartext_auth_smtp.pcapng -V
```

### Generated Scenarios (`captures/`)

| Scenario | Protocol & Port | Key Mechanisms & Attributes | Expected Findings | Severity |
| :--- | :--- | :--- | :--- | :--- |
| `hardened_smtp` | SMTP (587) | STARTTLS, TLS 1.3, `TLS_AES_256_GCM_SHA384`, forward secrecy | None (Clean) | None (Score 100) |
| `hardened_imap` | IMAP (143) | STARTTLS upgrade, TLS 1.3, encrypted authentication | None (Clean) | None (Score 100) |
| `hardened_pop3` | POP3 (110) | STLS upgrade, TLS 1.3, USER/PASS only after encryption | None (Clean) | None (Score 100) |
| `cleartext_auth_smtp` | SMTP (587) | Server advertises AUTH before STARTTLS; cleartext `AUTH LOGIN` | `AUTH-001` | Critical |
| `cleartext_auth_imap` | IMAP (143) | Cleartext `LOGIN demo-user demo-password` before STARTTLS | `AUTH-001` | Critical |
| `cleartext_auth_pop3` | POP3 (110) | Cleartext `USER demo-user` and `PASS demo-password` before STLS | `AUTH-001` | Critical |
| `starttls_downgrade` | SMTP (587) | STARTTLS requested, server fails (454), client downgrades to plaintext `AUTH` | `STARTTLS-001`, `AUTH-001` | Critical |
| `expired_certificate` | SMTP (587) | TLS 1.2 handshake carrying X.509 cert expired before capture date | `CERT-001`, `CERT-003` | High |
| `san_mismatch` | SMTP (587) | TLS 1.2 SNI `mail.example.test` vs cert SAN `other.example.test` | `CERT-002`, `CERT-003` | High |
| `weak_crypto` | SMTP (587) | TLS 1.0, RC4 cipher (`TLS_RSA_WITH_RC4_128_SHA`), 1024-bit RSA key, no PFS | `TLS-002`, `CIPHER-001`, `CIPHER-002`, `CERT-004` | Critical |
| `partial_capture` | SMTP (587) | TLS handshake initiated but truncated before completion | Unassessed (`complete=False`) | None (Score None) |
| `multi_protocol_mix` | SMTP, IMAP, POP3 | 4 concurrent interleaved sessions across ports 587, 143, 110 | Multi-session independent findings | Mixed |

Every generated capture file is indexed with SHA-256 hashes, byte sizes, and exact frame evidence markers in `captures/manifest.json`.


Tests cover PCAP/PCAPNG, all three protocols, fragmented records, expiry/SAN validation, redaction, retransmission, partial evidence, score math, invalid uploads, job polling and all exports. Browser checks cover upload-through-demo, session evidence and dashboard. Docker, PostgreSQL and the TShark branch need a host with those services for verification.

## Docker

```sh
docker compose up --build
```

Serves the frontend at localhost:5173, proxies API requests and persists reports in a named volume. Building requires internet; runtime is offline. `npm run preview` alone has no API proxy; use Docker for the complete production-build demo.

## Evidence boundaries

- Demonstrative passive analysis, not a production forensic/compliance tool. No email decryption or TLS Finished verification.
- TLS 1.3 certificates/authentication are encrypted. Missing certificate/SNI/revocation evidence stays unknown; OCSP acknowledgment alone does not establish good revocation status.
- Missing connection openings or stream gaps exclude a session from the overall score. No supported sessions means no score, not 100.
- IP fragment reassembly, SSLv2 records, QUIC and unknown applications are unsupported. TLS-001 evaluates SSLv3; its rule also supports SSLv2 metadata from future extractors. Nonstandard ports are retained when a recognizable ClientHello is present.
- Chain validation can fail for private CAs, expiry, hostname or constraints. CERT-003 means validation failed, not proof of a malicious certificate.
- Synthetic ML metrics are not real-world accuracy. Limited normal-feature diversity constrains anomaly detection; evaluation metadata documents splits and class coverage.
- Responses are reduced to status codes and safe capability labels. Authentication arguments, SASL continuations and message bodies are never exported/logged.
- No multi-user authentication, durable queue or tenant isolation. The service binds to loopback for a single local demonstration.
