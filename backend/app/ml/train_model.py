"""Train only from parsed synthetic captures; split by scenario to prevent leakage."""
import argparse
import json
import pickle
import sys
import tempfile
from pathlib import Path
import numpy as np
from scapy.all import wrpcap
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import classification_report
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder
from .features import FEATURES, extract_features
from ..core.pcap_extractor import extract
from ..core.stream_reassembly import reassemble
from ..core.protocol_parser import parse
from ..core.cert_validator import validate_certificates
from ..core.rule_engine import evaluate
from ..core.ml_scoring import MODEL_DIR

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'dataset_generation'))
from generate_traffic import SCENARIOS, generate


def main():
    vectors, labels, groups = [], [], []
    with tempfile.TemporaryDirectory() as temp:
        for index, (name, config) in enumerate(SCENARIOS.items()):
            path = Path(temp) / f'{name}.pcap'
            wrpcap(str(path), generate(name, count=20, seed=42 + index))
            packets, _ = extract(path)
            for stream in reassemble(packets):
                s, ders, ev = parse(stream)
                s.certificate = validate_certificates(ders, ev, s.tls.get('sni'), ev['timestamp'] if ev else s.evidence['timestamp'])
                s.findings = evaluate(s)
                vectors.append(extract_features(s)); labels.append(config[3]); groups.append(name)
    X, y, groups = np.asarray(vectors), np.asarray(labels), np.asarray(groups)
    # Find a deterministic group split retaining all four labels in training and a hardened baseline.
    for seed in range(1000):
        train, other = next(GroupShuffleSplit(n_splits=1, train_size=.7, random_state=seed).split(X, y, groups))
        if len(set(y[train])) == 4 and 'hardened' in groups[train]:
            break
    val_local, test_local = next(GroupShuffleSplit(n_splits=1, train_size=.5, random_state=42).split(X[other], y[other], groups[other]))
    val, test = other[val_local], other[test_local]
    classifier = RandomForestClassifier(n_estimators=150, max_depth=8, class_weight='balanced', random_state=42).fit(X[train], y[train])
    normal = train[y[train] == 'Low']
    anomaly = IsolationForest(n_estimators=100, contamination=.05, random_state=42).fit(X[normal])
    encoder = LabelEncoder().fit(y[train])
    xgb = XGBClassifier(n_estimators=80, max_depth=3, random_state=42, n_jobs=2).fit(X[train], encoder.transform(y[train]))
    predictions = classifier.predict(X[test])
    anomaly_order = np.argsort(anomaly.decision_function(X[test]))
    k = min(20, len(test))
    rule_labels = np.array([['Low', 'Low', 'Medium', 'High', 'Critical'][int(row[-1])] for row in X[test]])
    evaluation = dict(status='synthetic_training_demo', sample_count=len(X), seed=seed, features=FEATURES,
                      classifier='RandomForest', challenger='XGBoost', anomaly='IsolationForest',
                      split={name: sorted(set(groups[index])) for name, index in [('train', train), ('validation', val), ('test', test)]},
                      test=classification_report(y[test], predictions, labels=encoder.classes_, output_dict=True, zero_division=0),
                      validation=classification_report(y[val], classifier.predict(X[val]), labels=encoder.classes_, output_dict=True, zero_division=0),
                      xgboost_test=classification_report(y[test], encoder.inverse_transform(xgb.predict(X[test])), labels=encoder.classes_, output_dict=True, zero_division=0),
                      anomaly_precision_at_k=float(np.mean(y[test][anomaly_order[:k]] != 'Low')), anomaly_k=k,
                      rule_ml_agreement=float(np.mean(rule_labels == predictions)),
                      limitations='Synthetic wire fixtures with low within-scenario feature diversity. Not a production accuracy estimate. Rule-derived features make agreement partly circular; unseen classes may have zero test support.')
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    with (MODEL_DIR / 'risk.pkl').open('wb') as handle:
        pickle.dump({'classifier': classifier, 'anomaly': anomaly}, handle)
    xgb.save_model(MODEL_DIR / 'xgboost.json')
    (MODEL_DIR / 'evaluation.json').write_text(json.dumps(evaluation, indent=2))
    print(json.dumps({'samples': len(X), 'split': evaluation['split'], 'test_accuracy': evaluation['test'].get('accuracy')}, indent=2))


if __name__ == '__main__':
    main()
