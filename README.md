# SecureMailScope

A complete browser-based demonstration of SIH 2026 problem statement 26159, based on the supplied Crypterpillars proposal. No installation or API keys are needed beyond Node.js 20+.

## Run

```sh
npm start
```

Open http://127.0.0.1:5173. Set `PORT` to use another port. The server binds to the local machine only. Alternatively, serve `dist/` with any static HTTP server. Do not open the HTML through `file://`; browser module loading requires HTTP.

## Demonstration flow

1. Start on **Overview**: 84 synthetic sessions, protocol distribution, explainable posture score, and priority findings.
2. Open **Simulation lab**, select **STARTTLS downgrade**, then **Run simulation**. Watch the five pipeline stages complete.
3. Open the assessment and inspect a critical session. Follow the synthetic TCP/SMTP/STARTTLS timeline and redacted authentication evidence.
4. In **Findings**, apply individual simulated fixes or **Simulate all fixes**. Revisit the overview or lab to compare the recalculated score.
5. Switch to **Hardened baseline** to demonstrate a clean environment.
6. In **Reports**, export JSON, standalone HTML, or open the printable report and use the browser's Save as PDF option.
7. **Capture analysis** also accepts real PCAP/PCAPNG files for local structural validation, packet-record counting, and SHA-256 hashing. Uploaded captures are explicitly unassessed, separate from the simulation.

## Scope and honest limitations

- All forensic sessions and certificate attributes are deterministic synthetic fixtures. They are not obtained by analyzing real traffic.
- Risk explanations use transparent weighted rules, not a trained ML model. There are no claimed accuracy metrics.
- The score averages assessed sessions, each scored from 100 minus triggered penalties, clamped to zero. Partial handshakes are excluded and shown as unknown.
- Real capture upload validates container structure only; it does not decode TCP/TLS, validate trust chains, decrypt messages, or infer a security posture.
- TLS 1.3 certificates are encrypted on the wire. Their displayed details are explicitly lab ground truth.
- Remediation affects in-memory simulation state only. Refreshing resets the demo; no mail servers are contacted.
- JSON exports contain a SHA-256 hash of `JSON.stringify(sessions)` encoded as UTF-8. The hash verifies the exported synthetic evidence, not a PCAP.
- Capture processing and reports stay in the browser. Google Fonts is optional; local fallback fonts keep the app usable offline.

## Source

- `dist/index.html`: application entrypoint and metadata.
- `dist/style.css`: responsive console styling.
- `dist/engine.js`: deterministic scenarios, evidence, scoring, and binary capture validation.
- `dist/app.js`: views, simulation state, accessible detail panels, filtering, report generation.
- `server.js`: dependency-free static server.
- `tests/engine.test.js`: scenario consistency and capture validation tests.

## Validation

```sh
npm test
npm run check
```

Future production work: add FastAPI/TShark TCP reconstruction and TLS extraction, X.509 trust evaluation, persistent case storage, and a separately evaluated ML pipeline. This demo intentionally makes no production forensic claims.
