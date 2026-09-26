# SecureMailScope synthetic training corpus

## Contents and use

- dataset.csv: 30,000 labeled session-level records; NOT 30,000 raw packet captures.
- train.csv / validation.csv / test.csv: fixed, disjoint configuration-group partitions.
- metadata.json: feature lists, class/scenario/split counts, SHA-256 and limitations.
- feature_dictionary.csv: field meanings and encoding.
- evaluation.json: isolated candidate RF/IF results, including anomaly false positives.
- candidate_models.pkl: fitted candidates with an explicit ordered 28-feature schema. These are NOT a drop-in replacement for the app's 23-input bundle.
- build_training_corpus.py / validate_training_corpus.py: copies of project scripts for review; run the original copies from dataset_generation in the project.

## Dataset design

30,000 unique model-input vectors, balanced at 7,500 rows per class. Covers 16 scenario families and SMTP/IMAP/POP3, explicit STARTTLS and implicit TLS. The generator builds simulated SessionRecord metadata, evaluates the real rule engine, and uses the real feature extractor. Labels are specified from the selected scenario before evaluation and checked against rule severity. These are policy-consistency labels, not independent real-world expert annotations.

There are 23 legacy numeric fields plus seven additional evidence fields. The recommended 28 model inputs exclude num_rule_findings and max_finding_severity_ordinal. Those two columns remain available for compatibility and comparison, but using them supplies the classifier with rule-engine conclusions. All identifiers, scenario names, finding IDs, labels, hashes and split fields must also be excluded from model inputs.

Seven additions: certificate_observed, tls_observed, certificate_expired, certificate_not_yet_valid, certificate_extensions_valid, certificate_weak_key, client_offered_higher_version. These close gaps in the old inputs without copying finding severity. Unknown certificate booleans use -1. Legacy columns retain the application's original default encodings, so the observation masks matter.

No raw credentials, email bodies or personal traffic are used. Certificate fields represent hypothetical validator output; synthetic fingerprints are not actual certificate evidence. TLS 1.3 certificate fields remain unavailable. Auth-before-TLS cases may later upgrade successfully; this does not undo the earlier exposure. num_commands represents a simulated parsed-event count, not a stored command transcript.

## Splits and evaluation

Train 21,239; validation 4,121; test 4,640. Configuration templates (scenario, protocol, port, TLS version, cipher, key size and chain length) are assigned wholly to one split via a fixed hash. All classes appear in every split. Full recommended feature vectors are unique across the corpus. This tests new configuration groups within known synthetic scenario families; it does not test unseen attack families or new real organizations. Do not replace the supplied split with random row splitting.

The current legacy train_model.py ignores the split column and re-splits by scenario. Use validate_training_corpus.py for the supplied grouped benchmark; do not assume the legacy command reproduces these metrics.

Random Forest is trained on all four labels. Isolation Forest trains only on Low rows. is_anomaly means severity != Low and is merely an evaluation proxy; it is neither a training feature nor validated novelty ground truth. Anomalies and high risk are different concepts.

Baseline test RF accuracy and macro-F1 are 1.00 because this corpus encodes controlled policies; this is not a production accuracy claim. Baseline IF test normal false-positive rate is about 15.1%, with proxy average precision about 0.705. Further calibration on independent normal validation traffic is needed. Candidate models were saved separately; existing deployed app models were not changed.

## Reproduce from the repository root

```powershell
backend/.venv/Scripts/python.exe dataset_generation/build_training_corpus.py
backend/.venv/Scripts/python.exe dataset_generation/validate_training_corpus.py
```

Default seed: 26159. Regeneration writes the output/ml_dataset_30k corpus. Requires the project's Python dependencies (including pandas, numpy, scikit-learn and the backend imports). This dataset is for development and controlled evaluation. Add authorized live/lab captures, independent labels, missing-evidence scenarios and temporal/server holdouts before operational deployment.

## Coverage boundaries

The corpus covers the current rule IDs, but is not exhaustive of all possible combinations or applications. It excludes partial/unassessed streams from severity training, does not verify real cryptographic handshakes, and is not a phishing/malware-content dataset. Oversampling unique combinations changes per-scenario proportions; the metadata reports actual counts. Balanced classes are a training choice, not an estimate of production prevalence.
