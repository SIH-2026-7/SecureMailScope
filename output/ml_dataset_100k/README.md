# SecureMailScope 100,000-record training corpus

Generated as requested: exactly 100,000 unique synthetic session-feature vectors, 85,000 train and 15,000 test. Four balanced classes: Low, Medium, High, Critical. Each has 21,250 training and 3,750 test records. Covers 16 scenario families and SMTP/IMAP/POP3. Records are simulated session metadata, not live packet captures.

## Reproduce from the repository root

```powershell
.\backend\.venv\Scripts\python.exe dataset_generation\build_training_corpus.py --output output/ml_dataset_100k --per-class 25000 --train-fraction 0.85 --seed 26160
.\backend\.venv\Scripts\python.exe dataset_generation\validate_training_corpus.py --folder output/ml_dataset_100k
```

Scripts in this package are review copies; use their dataset_generation paths in the project, since they import project modules. The earlier 30,000-record corpus and its results are retained separately.

## What is trained

Random Forest: all 85,000 training records, 200 trees, maximum depth 14, minimum leaf size 2, balanced class weights, random seed 26159.

Isolation Forest: only the 21,250 Low-risk records in the training partition, 200 trees, contamination 0.05, default max_samples=256 per tree, random seed 26159. Its default per-tree sample size remains 256 even with a larger corpus. It is not trained on all 85,000 records because its baseline is normal behavior.

Models use 28 evidence inputs specified in metadata.json. The original 23 fields are retained in the CSV, with seven added evidence fields; two direct rule-result fields are excluded from recommended input. Metadata, target labels and IDs are also excluded. A separate 23-input RF benchmark includes rule outputs and should not be presented as independent detection performance.

## Split integrity

A configuration template is defined by scenario, protocol, service port, TLS version, cipher, key bits and chain length. Its hash assigns it wholly to train (85 hash buckets) or test (15 buckets). Generation accepts records until the exact per-class split quotas are filled; entire groups stay disjoint. Duplicate recommended vectors are rejected globally. Labels are assigned by scenario before rule evaluation and then checked for consistency.

There is no separate validation partition in this requested 85k/15k experiment. Model parameters were fixed before test evaluation; no test-set threshold tuning was performed. For future tuning, reserve an internal validation partition within the 85k training allocation and keep the 15k test partition fixed. Because this test set has now been examined, use a fresh independent holdout for a final deployment claim after repeated tuning.

## Results

- RF accuracy: 100.00%; macro-F1: 1.0000.
- IF normal false-positive rate: 11.15%, or 418 of 3,750 Low test records.
- IF non-Low proxy average precision: 0.7260.
- Earlier 30k run normal false-positive rate: 15.09%.

The lower false-positive rate is an observed result for this run. Corpus size, seed and split proportions changed, so this is not an isolated causal measurement of more training data. Both corpora share controlled synthetic scenario policies. RF's 100% accuracy is not evidence of real-world accuracy. is_anomaly simply means non-Low severity, not independently annotated novelty or maliciousness. See evaluation.json for anomaly recall/precision and confusion matrices; false positives alone do not measure useful detection.

## Outputs

- dataset.csv, train.csv, test.csv
- metadata.json and feature_dictionary.csv
- evaluation.json and comparison_30k_vs_100k.json
- candidate_models.pkl (RF and IF, feature schema included)
- validation_checks.json and checksums.json

Candidates are not deployed. The current application expects 23 inputs, whereas these candidates need the specified 28. Do not overwrite the app model bundle without integrating the feature adapter and verifying end-to-end behavior.

Certificate fields are synthetic validator outputs. TLS1.3 certificate evidence remains absent; incomplete sessions are excluded from severity training. Revocation acknowledgements are not good-status proof. Refer to metadata.json for remaining limitations. Add authorized live/lab captures and independent labels before operational evaluation.

At the baseline anomaly threshold, non-Low proxy recall is 5.03% and precision is 57.52%. Low recall means the current anomaly flag misses most non-Low proxy cases; lower normal false positives alone do not make it operationally reliable. Previous proxy recall was 3.78%.
