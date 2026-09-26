# SecureMailScope: ML placement and five-page presentation plan

Source reviewed: Crypterpillars_Software_SIH26159.pdf, all six pages including image-based architecture, feasibility and impact content.
Scope: proposed slide structure and copy; the supplied PDF has not been edited. Assumption: five pages TOTAL, including the title. No prescribed five-page template was supplied. If five content pages plus title are allowed, retain the current six-page structure and update its content instead.

## Where Random Forest and Isolation Forest sit

On the source PDF's page 3, both belong in stage 6, **Rule Engine + AI/ML**, between stage 5 (TLS & Certificate Analysis) and stage 7 (Risk Scoring & Assessment).

Current implementation:

PCAP/PCAPNG -> packet extraction -> TCP reconstruction -> SMTP/IMAP/POP3 parsing -> TLS and certificate checks -> deterministic rule findings -> 23-feature extraction -> Random Forest AND Isolation Forest -> posture scoring -> dashboard/reports.

The two forests are peers, not a chain: Random Forest does not feed Isolation Forest and Isolation Forest does not assign the four severity classes.

- Deterministic rules: exact evidence-backed findings, severity and remediation.
- Random Forest: supervised Critical / High / Medium / Low prediction per session.
- Isolation Forest: normal-training-baseline anomaly score and flag per session. An unusual record is not proof of an attack.
- Stage 7: combine rule deductions and Random Forest penalty. The current anomaly flag is displayed separately and adds no score deduction.
- Training happens offline in a separate workflow. The live analysis path loads fitted models; it does not retrain on the uploaded capture.

Recommended revised stage 6 diagram:

```text
Stage 5: parsed session + TLS/certificate evidence
                       |
          +------------+-------------+
          |                          |
   Deterministic rules     Evidence feature extraction
          |                          |
          |                  +-------+-------+
          |                  |               |
      Findings         Random Forest   Isolation Forest
          |            risk class      anomaly score/flag
          +------------------+---------------+
                             |
                  Stage 7: scoring + explanation
                             |
                  Stage 8: dashboard + reports
```

This parallel rule/model design is the recommended next version. The current application still runs rules before extracting its 23 model features because two features contain rule results. The new candidate dataset/model uses 28 evidence inputs, excluding those two rule-result fields. Adopting that candidate requires a runtime feature adapter and integration checks; it has not replaced the app's deployed model.

XGBoost is an offline comparison model in the existing project. Label it "challenger (offline evaluation)" rather than implying it also supplies the active risk prediction.

## Five-page restructuring

### Page 1 — Title and problem identity

Reuse source page 1. Preserve SIH and team branding.

- SecureMailScope
- AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications
- Problem Statement ID: 26159
- Theme: Blockchain & Cybersecurity
- Category: Software
- Team: Crypterpillars (confirm spelling; source title text says Cryterpillars while its logo says Crypterpillars)
- Fill the real Team ID before submission; do not invent it.

Keep this page minimal. Do not put the architecture or model results here.

### Page 2 — Problem, solution and innovation

Condense source page 2 into two columns and one short concluding statement.

Left, problem:
- TLS-enabled email can still expose credentials or use weak cryptography.
- Key issues: legacy TLS, weak ciphers, certificate errors, failed upgrades and missing forward secrecy.
- Analysts must correlate packets into meaningful session evidence.

Right, solution:
- Upload PCAP/PCAPNG and reconstruct SMTP, IMAP and POP3 sessions.
- Inspect TLS, STARTTLS/STLS and observable X.509 evidence.
- Produce explainable findings, severity signals and prioritized fixes.

Bottom innovation statement:
"Every finding connects a session, observed evidence, risk and a remediation recommendation."

Move the original eight-step workflow to page 3 to avoid repeating it.

### Page 3 — Technical approach and ML architecture

Reuse the direction of the original architecture, but simplify stage text. Make stage 6 visibly contain rules, feature extraction and the two peer models.

Top/main area:
Input -> Extraction -> TCP reconstruction -> Protocol analysis -> TLS/certificate evidence -> Rules + ML -> Scoring -> Reports.

Stage 6 labels:
- Rules: known weaknesses + evidence
- Random Forest: four-class severity
- Isolation Forest: anomaly score + flag

Bottom, brief score explanation:
"100 minus rule penalties (30/15/7/2/0) and RF penalty (20/10/5/0). Average assessed sessions. Incomplete sessions remain unassessed."

Compact stack strip:
Python/FastAPI | TShark with Scapy fallback | cryptography | scikit-learn | React/TypeScript | SQLite | Docker.

Accuracy corrections:
- TShark is invoked directly; PyShark is not the active extraction path.
- TCP segment reassembly is implemented; IP fragment reassembly is unsupported.
- Distinguish the CURRENT 23-input path from the PROPOSED 28-input candidate; do not imply candidate deployment is finished.
- RF contributes to the score; Isolation Forest currently does not.

### Page 4 — Dataset, validation and feasibility

Replace the oversized feasibility collage with a compact training workflow plus measured dataset facts.

Main pipeline:
Controlled synthetic session scenarios -> application-compatible evidence fields -> scenario labels + rule consistency checks -> separate train/validation/test groups -> offline RF and IF training -> evaluation.

Dataset evidence:
- 30,000 unique synthetic session feature records
- 7,500 each: Low, Medium, High, Critical
- 16 scenario families; SMTP, IMAP and POP3
- Train: 21,239 | Validation: 4,121 | Test: 4,640
- 28 candidate inputs; direct rule-result fields excluded
- No duplicate feature vectors or shared configuration groups across splits

Small limitations/mitigation strip:
- Synthetic data: expand with authorized laboratory captures before operational claims.
- TLS 1.3 hidden certificates: retain unknown evidence; no decryption claim.
- Partial captures: unassessed score.
- Offline revocation: unknown status.

Evaluation note, if metrics are shown:
"RF macro-F1 1.00 on controlled synthetic holdout only. Isolation Forest normal false-positive rate 15.1% at the baseline threshold; advisory use and further calibration required."

Do not headline 100% accuracy, claim 30,000 real PCAPs, or show this feature-level corpus as recordings from Postfix/Dovecot. The original source's test-server capture pipeline is a future/lab data source, not how this new corpus was produced.

### Page 5 — Impact, roadmap and references

Combine selected source page 5 benefits with compact source page 6 references.

Upper area, intended beneficiaries:
- SOC analysts: prioritize sessions and inspect frame-linked findings.
- Investigators: reconstruct timelines and export evidence-linked reports.
- Email administrators: identify TLS and certificate configuration problems.

Middle area, delivery status and next steps:
- Available: local capture analysis, deterministic findings, labeled ML signals, JSON/HTML/PDF export.
- Completed preparation: 30,000-record synthetic corpus and isolated candidate training.
- Next: authorized lab captures, expert label review, anomaly calibration, 28-feature runtime integration and regression testing.
- Future: configuration drift monitoring and SIEM/SOAR integration.

Bottom area, compact references retained from the source deck:
- NIST SP 800-52 Rev. 2: https://csrc.nist.gov/pubs/sp/800/52/r2/final
- RFC 3207: https://www.rfc-editor.org/rfc/rfc3207.html
- RFC 8314: https://www.rfc-editor.org/rfc/rfc8314.html
- Wireshark/TShark: https://www.wireshark.org/docs/
- scikit-learn: https://scikit-learn.org/

These are source-deck references, not a claim of completed compliance assessment. Keep extended library references in speaker notes when producing an editable deck.

Remove unsupported source claims: "Ready for Real-World Use", proven phishing protection, measured cost/environmental savings, and deployed drift detection. Phrase benefits as intended outcomes unless independently measured.

## What moves where

| Original page | Five-page destination | Main change |
|---|---|---|
| 1 Title | 1 | Correct team spelling and fill real Team ID |
| 2 Problem/solution | 2 | Reduce repetition and text |
| 3 Technical approach | 3 | Explicit peer RF/IF branches and scoring path |
| 4 Feasibility | 4 | Add actual generated corpus and validation figures |
| 5 Impact | 5 | Focus on observable capabilities and intended benefits |
| 6 References | 5 footer + notes | Preserve essential references without a sixth page |
