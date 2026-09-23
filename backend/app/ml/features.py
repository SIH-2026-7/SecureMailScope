from ..core.rule_engine import ORDINAL

FEATURES = ['tls_version_ordinal', 'cipher_strength_score', 'forward_secrecy', 'starttls_used',
            'auth_before_tls', 'cert_days_until_expiry', 'cert_key_bits', 'cert_self_signed',
            'cert_sig_algo_weak', 'num_rule_findings', 'max_finding_severity_ordinal']


def extract_features(s):
    c, cipher = s.certificate or {}, s.tls.get('cipher_suite', '')
    strength = 0 if not cipher or any(v in cipher for v in ('RC4', 'DES', 'NULL', 'EXPORT')) else 3 if 'GCM' in cipher or 'CHACHA20' in cipher else 2
    return [ORDINAL.get(s.tls.get('version'), -1), strength,
            int('ECDHE' in cipher or 'DHE_' in cipher or s.tls.get('version') == 'TLS1.3'),
            int(s.starttls_used), int(s.auth_before_tls), c.get('days_until_expiry', 0), c.get('key_bits') or 0,
            int(c.get('self_signed', False)), int(c.get('weak_signature', False)), len(s.findings),
            max(({'Info': 0, 'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}[f.severity] for f in s.findings), default=0)]
