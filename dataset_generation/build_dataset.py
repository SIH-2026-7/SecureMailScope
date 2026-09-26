"""Build a labeled CSV dataset from all synthetic scenarios for ML training.

Runs each scenario through the full backend pipeline (extract → reassemble →
parse → cert_validate → rule_evaluate) and exports extracted features alongside
severity labels, scenario names, and anomaly ground truth.

Usage:
    python -m dataset_generation.build_dataset [--output dataset.csv] [--sessions 50]

The output CSV is suitable for direct use by train_model.py.
"""
import argparse
import csv
import json
import sys
import tempfile
from pathlib import Path

import numpy as np
from scapy.all import wrpcap

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dataset_generation.generate_traffic import SCENARIOS, generate
from backend.app.core.pcap_extractor import extract
from backend.app.core.stream_reassembly import reassemble
from backend.app.core.protocol_parser import parse
from backend.app.core.cert_validator import validate_certificates
from backend.app.core.rule_engine import evaluate
from backend.app.ml.features import FEATURES, extract_features


def build_dataset(sessions_per_scenario=50, seed_base=42):
    """Generate feature vectors and labels for all scenarios.

    Args:
        sessions_per_scenario: How many independent sessions to generate per
            scenario (each with a different random seed for variety).
        seed_base: Starting seed; each scenario/session combo gets a unique seed.

    Returns:
        List of dicts, one per parsed session, containing feature values,
        the severity label, scenario name, and anomaly ground truth.
    """
    rows = []
    scenario_names = list(SCENARIOS.keys())
    total = len(scenario_names) * sessions_per_scenario
    done = 0

    with tempfile.TemporaryDirectory() as temp:
        for scenario_idx, name in enumerate(scenario_names):
            config = SCENARIOS[name]
            risk_class = config[3]  # 'Low', 'Medium', 'High', 'Critical'

            for session_idx in range(sessions_per_scenario):
                seed = seed_base + scenario_idx * 1000 + session_idx
                path = Path(temp) / f'{name}_{session_idx}.pcap'

                try:
                    packets = generate(name, count=1, seed=seed)
                    wrpcap(str(path), packets)
                    extracted_packets, _ = extract(path)

                    for stream in reassemble(extracted_packets):
                        s, ders, ev = parse(stream)
                        try:
                            s.certificate = validate_certificates(
                                ders, ev, s.tls.get('sni'),
                                ev['timestamp'] if ev else s.evidence['timestamp']
                            )
                        except (ValueError, Exception):
                            s.warnings.append('Certificate decode failed.')
                        s.findings = evaluate(s)
                        features = extract_features(s)

                        # Anomaly ground truth: sessions with critical findings
                        # that no standard rule cleanly covers, OR any "novel"
                        # pattern. For synthetic data we use risk class != 'Low'.
                        is_anomaly = risk_class != 'Low'

                        row = dict(zip(FEATURES, features))
                        row['severity_label'] = risk_class
                        row['scenario'] = name
                        row['session_id'] = s.session_id
                        row['protocol'] = s.protocol
                        row['server_port'] = s.server_port
                        row['is_anomaly'] = int(is_anomaly)
                        row['num_findings'] = len(s.findings)
                        row['finding_ids'] = '|'.join(f.rule_id for f in s.findings)
                        rows.append(row)

                except Exception as exc:
                    print(f'  ⚠ Failed {name} seed={seed}: {exc}')

                done += 1
                if done % 50 == 0 or done == total:
                    print(f'  Progress: {done}/{total} sessions processed')

                # Clean up temp file
                path.unlink(missing_ok=True)

    return rows


def main():
    parser = argparse.ArgumentParser(
        description='Generate labeled ML dataset from synthetic email protocol captures.'
    )
    parser.add_argument(
        '--output', type=Path,
        default=ROOT / 'dataset_generation' / 'dataset.csv',
        help='Output CSV file path'
    )
    parser.add_argument(
        '--sessions', type=int, default=50,
        help='Number of sessions per scenario (default: 50)'
    )
    parser.add_argument(
        '--seed', type=int, default=42,
        help='Base random seed (default: 42)'
    )
    args = parser.parse_args()

    print(f'Building dataset: {len(SCENARIOS)} scenarios × {args.sessions} sessions')
    print(f'Target: {args.output}')
    print()

    rows = build_dataset(
        sessions_per_scenario=args.sessions,
        seed_base=args.seed,
    )

    if not rows:
        print('ERROR: No sessions were generated.')
        sys.exit(1)

    # Write CSV
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys())
    with args.output.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # Print summary statistics
    labels = [r['severity_label'] for r in rows]
    scenarios = [r['scenario'] for r in rows]
    unique_labels = sorted(set(labels))
    unique_scenarios = sorted(set(scenarios))

    print(f'\n[OK] Dataset saved: {args.output}')
    print(f'  Total sessions: {len(rows)}')
    print(f'  Features per session: {len(FEATURES)}')
    print(f'  Scenarios covered: {len(unique_scenarios)}')
    print(f'\n  Label distribution:')
    for label in unique_labels:
        count = labels.count(label)
        print(f'    {label:>10}: {count:>4} ({100*count/len(rows):5.1f}%)')

    print(f'\n  Scenario breakdown:')
    for scenario in unique_scenarios:
        count = scenarios.count(scenario)
        risk = SCENARIOS[scenario][3]
        print(f'    {scenario:<25} {count:>4} sessions  [{risk}]')

    # Also save a metadata JSON
    meta_path = args.output.with_suffix('.meta.json')
    meta = {
        'total_sessions': len(rows),
        'features': FEATURES,
        'num_features': len(FEATURES),
        'scenarios': {s: SCENARIOS[s][3] for s in unique_scenarios},
        'label_distribution': {label: labels.count(label) for label in unique_labels},
        'sessions_per_scenario': args.sessions,
        'seed_base': args.seed,
    }
    meta_path.write_text(json.dumps(meta, indent=2))
    print(f'\n  Metadata saved: {meta_path}')


if __name__ == '__main__':
    main()
