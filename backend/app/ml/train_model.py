"""Train severity classifier (Random Forest) and anomaly detector (Isolation Forest).

Supports two modes:
1. From CSV dataset (preferred): python -m backend.app.ml.train_model --dataset dataset_generation/dataset.csv
2. Inline generation (legacy): python -m backend.app.ml.train_model

Split by scenario group to prevent data leakage. Saves models and evaluation metrics.
"""
import argparse
import json
import pickle
import sys
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
from scapy.all import wrpcap
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import GroupShuffleSplit, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
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


def load_from_csv(csv_path):
    """Load feature vectors, labels, and groups from a pre-built CSV dataset."""
    df = pd.read_csv(csv_path)
    feature_cols = [c for c in FEATURES if c in df.columns]
    if len(feature_cols) != len(FEATURES):
        missing = set(FEATURES) - set(feature_cols)
        raise ValueError(f'CSV is missing features: {missing}')
    X = df[feature_cols].values.astype(float)
    y = df['severity_label'].values
    groups = df['scenario'].values
    anomaly_ground_truth = df['is_anomaly'].values if 'is_anomaly' in df.columns else None
    return X, y, groups, anomaly_ground_truth


def generate_inline():
    """Generate feature vectors inline from all scenarios (legacy fallback)."""
    vectors, labels, groups = [], [], []
    with tempfile.TemporaryDirectory() as temp:
        for index, (name, config) in enumerate(SCENARIOS.items()):
            risk = config[3]
            path = Path(temp) / f'{name}.pcap'
            wrpcap(str(path), generate(name, count=20, seed=42 + index))
            packets, _ = extract(path)
            for stream in reassemble(packets):
                s, ders, ev = parse(stream)
                try:
                    s.certificate = validate_certificates(
                        ders, ev, s.tls.get('sni'),
                        ev['timestamp'] if ev else s.evidence['timestamp']
                    )
                except (ValueError, Exception):
                    pass
                s.findings = evaluate(s)
                vectors.append(extract_features(s))
                labels.append(risk)
                groups.append(name)
    return np.asarray(vectors), np.asarray(labels), np.asarray(groups), None


def find_valid_split(X, y, groups, required_labels=4, max_attempts=1000):
    """Find a group-based train/test split with all severity labels represented."""
    for seed in range(max_attempts):
        train, other = next(
            GroupShuffleSplit(n_splits=1, train_size=0.7, random_state=seed)
            .split(X, y, groups)
        )
        if len(set(y[train])) >= required_labels:
            # Ensure we have a 'hardened' or 'Low' baseline in training
            if any('hardened' in g for g in groups[train]):
                return train, other, seed
    # Fallback: use the last attempt even if not all labels present
    return train, other, seed


def main():
    parser = argparse.ArgumentParser(description='Train ML models for SecureMailScope')
    parser.add_argument('--dataset', type=Path, default=None,
                        help='Path to pre-built CSV dataset (from build_dataset.py)')
    args = parser.parse_args()

    # Load data
    print('Loading data...')
    if args.dataset and args.dataset.exists():
        print(f'  Using CSV dataset: {args.dataset}')
        X, y, groups, anomaly_gt = load_from_csv(args.dataset)
    else:
        print('  Generating inline (no CSV provided)')
        X, y, groups, anomaly_gt = generate_inline()

    print(f'  Total samples: {len(X)}')
    print(f'  Features: {len(FEATURES)}')
    print(f'  Label distribution: {dict(zip(*np.unique(y, return_counts=True)))}')
    print(f'  Scenarios: {len(set(groups))}')

    # --- Split data ---
    print('\nSplitting data (group-based to prevent leakage)...')
    train, other, split_seed = find_valid_split(X, y, groups)
    val_local, test_local = next(
        GroupShuffleSplit(n_splits=1, train_size=0.5, random_state=42)
        .split(X[other], y[other], groups[other])
    )
    val, test = other[val_local], other[test_local]

    print(f'  Split seed: {split_seed}')
    print(f'  Train: {len(train)} samples, {len(set(groups[train]))} scenarios')
    print(f'  Validation: {len(val)} samples, {len(set(groups[val]))} scenarios')
    print(f'  Test: {len(test)} samples, {len(set(groups[test]))} scenarios')
    print(f'  Train labels: {dict(zip(*np.unique(y[train], return_counts=True)))}')

    # --- Train Random Forest Classifier ---
    print('\nTraining Random Forest classifier...')
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X[train], y[train])

    # Cross-validation on training set
    cv_scores = cross_val_score(rf, X[train], y[train], cv=5, scoring='accuracy')
    print(f'  5-fold CV accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}')

    # Feature importances
    importances = dict(zip(FEATURES, rf.feature_importances_))
    sorted_importances = sorted(importances.items(), key=lambda x: x[1], reverse=True)
    print('\n  Top 10 feature importances:')
    for feat, imp in sorted_importances[:10]:
        print(f'    {feat:<35} {imp:.4f}')

    # --- Train XGBoost challenger ---
    print('\nTraining XGBoost challenger...')
    encoder = LabelEncoder().fit(y[train])
    xgb = XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        random_state=42,
        n_jobs=2,
    )
    xgb.fit(X[train], encoder.transform(y[train]))

    # --- Train Isolation Forest anomaly detector ---
    print('\nTraining Isolation Forest anomaly detector...')
    normal_mask = y[train] == 'Low'
    normal_indices = train[normal_mask]
    if len(normal_indices) < 10:
        print('  ⚠ Very few "Low" samples for anomaly training; using all training data.')
        normal_indices = train
    anomaly = IsolationForest(
        n_estimators=150,
        contamination=0.05,
        max_features=0.8,
        random_state=42,
        n_jobs=-1,
    )
    anomaly.fit(X[normal_indices])
    print(f'  Trained on {len(normal_indices)} normal samples')

    # --- Evaluate on test set ---
    print('\n' + '='*60)
    print('TEST SET EVALUATION')
    print('='*60)

    # Random Forest
    rf_predictions = rf.predict(X[test])
    print('\nRandom Forest:')
    print(classification_report(y[test], rf_predictions, zero_division=0))

    # XGBoost
    xgb_predictions = encoder.inverse_transform(xgb.predict(X[test]))
    print('XGBoost:')
    print(classification_report(y[test], xgb_predictions, zero_division=0))

    # Confusion matrix
    labels_order = sorted(set(y))
    cm = confusion_matrix(y[test], rf_predictions, labels=labels_order)
    print('Confusion Matrix (RF):')
    print(f'  Labels: {labels_order}')
    for row_label, row in zip(labels_order, cm):
        print(f'  {row_label:>10}: {row}')

    # Isolation Forest evaluation
    anomaly_scores = anomaly.decision_function(X[test])
    anomaly_predictions = anomaly.predict(X[test])
    anomaly_order = np.argsort(anomaly_scores)
    k = min(20, len(test))
    anomaly_precision = float(np.mean(y[test][anomaly_order[:k]] != 'Low'))

    print(f'\nIsolation Forest:')
    print(f'  Anomalies detected in test: {sum(anomaly_predictions == -1)} / {len(test)}')
    print(f'  Precision@{k}: {anomaly_precision:.4f}')

    if anomaly_gt is not None:
        test_anomaly_gt = anomaly_gt[test]
        anomaly_pred_binary = (anomaly_predictions == -1).astype(int)
        agreement = float(np.mean(anomaly_pred_binary == test_anomaly_gt))
        print(f'  Agreement with ground truth: {agreement:.4f}')

    # Validation set evaluation
    print('\n' + '='*60)
    print('VALIDATION SET EVALUATION')
    print('='*60)
    val_predictions = rf.predict(X[val])
    print('\nRandom Forest:')
    print(classification_report(y[val], val_predictions, zero_division=0))

    # Rule-ML agreement
    rule_labels = np.array(
        [['Low', 'Low', 'Medium', 'High', 'Critical'][int(row[10])] for row in X[test]]
    )
    rule_ml_agreement = float(np.mean(rule_labels == rf_predictions))
    print(f'\nRule-ML agreement on test: {rule_ml_agreement:.4f}')

    # --- Save models ---
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    with (MODEL_DIR / 'risk.pkl').open('wb') as handle:
        pickle.dump({'classifier': rf, 'anomaly': anomaly}, handle)
    xgb.save_model(str(MODEL_DIR / 'xgboost.json'))
    print(f'\nModels saved to {MODEL_DIR}')

    # --- Save evaluation metrics ---
    evaluation = {
        'status': 'synthetic_training_demo',
        'sample_count': len(X),
        'split_seed': split_seed,
        'features': FEATURES,
        'num_features': len(FEATURES),
        'classifier': 'RandomForest',
        'classifier_params': {
            'n_estimators': 200, 'max_depth': 10,
            'min_samples_split': 5, 'min_samples_leaf': 2,
        },
        'challenger': 'XGBoost',
        'anomaly_detector': 'IsolationForest',
        'split': {
            name: sorted(set(groups[index].tolist() if hasattr(groups[index], 'tolist') else [groups[index]]))
            for name, index in [('train', train), ('validation', val), ('test', test)]
        },
        'cv_accuracy_mean': float(cv_scores.mean()),
        'cv_accuracy_std': float(cv_scores.std()),
        'feature_importances': {feat: float(imp) for feat, imp in sorted_importances},
        'test': classification_report(
            y[test], rf_predictions,
            labels=encoder.classes_ if hasattr(encoder, 'classes_') else sorted(set(y)),
            output_dict=True, zero_division=0
        ),
        'validation': classification_report(
            y[val], val_predictions,
            labels=encoder.classes_ if hasattr(encoder, 'classes_') else sorted(set(y)),
            output_dict=True, zero_division=0
        ),
        'xgboost_test': classification_report(
            y[test], xgb_predictions,
            labels=encoder.classes_ if hasattr(encoder, 'classes_') else sorted(set(y)),
            output_dict=True, zero_division=0
        ),
        'confusion_matrix': {
            'labels': labels_order,
            'matrix': cm.tolist(),
        },
        'anomaly_precision_at_k': anomaly_precision,
        'anomaly_k': k,
        'anomaly_detected_count': int(sum(anomaly_predictions == -1)),
        'rule_ml_agreement': rule_ml_agreement,
        'limitations': (
            'Synthetic wire fixtures with controlled feature diversity. '
            'Not a production accuracy estimate. Rule-derived features '
            '(num_rule_findings, max_finding_severity_ordinal) make agreement '
            'partly circular; unseen attack classes may have zero test support.'
        ),
    }
    (MODEL_DIR / 'evaluation.json').write_text(json.dumps(evaluation, indent=2))
    print(f'Evaluation saved to {MODEL_DIR / "evaluation.json"}')

    # Summary
    test_accuracy = evaluation['test'].get('accuracy', 0)
    print(f'\n{"="*60}')
    print(f'SUMMARY')
    print(f'{"="*60}')
    print(f'  Samples: {len(X)}')
    print(f'  Features: {len(FEATURES)}')
    print(f'  CV Accuracy: {cv_scores.mean():.4f}')
    print(f'  Test Accuracy (RF): {test_accuracy:.4f}')
    print(f'  Anomaly Precision@{k}: {anomaly_precision:.4f}')
    print(f'  Rule-ML Agreement: {rule_ml_agreement:.4f}')


if __name__ == '__main__':
    main()
