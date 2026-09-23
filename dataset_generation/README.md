# Reproducible data and isolated live lab

The checked-in `public/captures` files are constructed wire-format PCAP fixtures. They exercise the real upload and parser pipeline, but are not recordings of successful live cryptographic connections. Encrypted record placeholders are not cryptographic proof. Addresses use documentation-only networks. Passwords are disposable synthetic values, redacted by the parser.

Generate all 20 scenarios and independently specified labels from the repository root:

```powershell
backend/.venv/Scripts/python.exe dataset_generation/generate_traffic.py --all --sessions 20
backend/.venv/Scripts/python.exe dataset_generation/label_manifest.py public/captures/manifest.json
```

Use `--disorder` to introduce reordered packets and a retransmission. Tests also cover TCP gaps, missing SYNs and truncated containers. Structurally truncated files are rejected; structurally valid captures with incomplete streams are marked partial.

Visible TLS 1.2 fixture certificates are self-signed, so CERT-003 is expected in addition to deliberate weaknesses. TLS 1.3 certificates are not fabricated. The fixture library cannot sign SHA-1; the optional container lab supplies that scenario. RC4/export suites are wire fixtures because current OpenSSL builds may no longer support them.

## Training

```powershell
cd backend
.venv/Scripts/python.exe -m app.ml.train_model
```

The script parses 20 sessions per scenario (440 total because combined cleartext has three protocols), extracts 11 normalized features, and uses a 70/15/15 scenario-group split. Random Forest is deployed, XGBoost is saved as a challenger, and Isolation Forest trains only on Low/hardened sessions. Models, features, split membership, per-class validation/test metrics, anomaly Precision@K and rule agreement are saved under `backend/app/ml/models`.

These fixtures have limited feature diversity. Hardened TLS 1.3 vectors are mostly identical; Isolation Forest may assign identical scores and miss anomalies. Metrics validate the pipeline, not real-world accuracy. Held-out groups do not cover every class; zero support is reported. Rule-derived features also make agreement partly circular. A realistic, independently validated corpus remains necessary before operational use.

## Optional Linux/Docker live lab

The Compose matrix contains 17 Postfix/Dovecot services, an SMTP STARTTLS-stripping proxy and a scripted client. The network is internal and no mail ports are published. All mailbox credentials are disposable lab values. Build-time downloads require internet; runtime stays inside the network.

```sh
cd dataset_generation
mkdir -p captures
docker compose build
docker compose up -d hardened cleartext_auth expired_cert
# Capture in a separate terminal; stop with Ctrl+C after running clients:
docker compose exec hardened tcpdump -i eth0 -s 0 -w /captures/hardened-live.pcap tcp
docker compose run --rm client hardened --protocol SMTP --sessions 20
docker compose run --rm client cleartext_auth --protocol IMAP --sessions 20
docker compose run --rm client expired_cert --protocol POP3 --sessions 20
```

Introduce reordering inside a lab container only with `docker compose exec hardened tc qdisc add dev eth0 root netem delay 30ms 10ms loss 1% reorder 10%`; remove it with `tc qdisc del dev eth0 root`. Do not apply this to the host interface.

Start `starttls_stripped` and `self_signed` to use the proxy, then run the client against `starttls_stripped`. It removes STARTTLS capabilities and captures the plaintext AUTH attempt. One passive trace cannot prove stripping without an independent baseline; findings describe only observed behavior.

Validation status: Docker/TShark were unavailable on the implementation host, so live services and TShark extraction are unverified. Modern OpenSSL may reject obsolete TLS/cipher/signature configurations; a failed handshake is not evidence of successful weak negotiation. Use bundled PCAPs for the guaranteed presentation flow.
