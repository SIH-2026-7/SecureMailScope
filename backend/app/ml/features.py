from ..core.rule_engine import ORDINAL

FEATURES = [
    # --- Original 11 features ---
    'tls_version_ordinal',
    'cipher_strength_score',
    'forward_secrecy',
    'starttls_used',
    'auth_before_tls',
    'cert_days_until_expiry',
    'cert_key_bits',
    'cert_self_signed',
    'cert_sig_algo_weak',
    'num_rule_findings',
    'max_finding_severity_ordinal',
    # --- New 12 rule-independent behavioral features ---
    'protocol_ordinal',
    'port_is_implicit_tls',
    'starttls_advertised',
    'starttls_requested',
    'plaintext_after_starttls',
    'handshake_complete',
    'session_complete',
    'num_commands',
    'cert_chain_length',
    'cert_hostname_match',
    'cert_trust_status_ordinal',
    'tls_ocsp_stapled',
]

SEVERITY_ORDINAL = {'Info': 0, 'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
PROTOCOL_ORDINAL = {'SMTP': 0, 'IMAP': 1, 'POP3': 2, 'TLS': 3}
IMPLICIT_TLS_PORTS = {465, 993, 995}
TRUST_ORDINAL = {'validation_failed': 0, 'unknown_no_hostname': 1, 'trusted': 2}


def extract_features(s):
    """Extract a 23-element feature vector from a parsed SessionRecord.

    Features are designed to be a mix of cryptographic evidence (TLS version,
    cipher strength) and behavioral/structural signals (protocol type, port
    class, session completeness) to reduce circularity with the rule engine.
    """
    c = s.certificate or {}
    cipher = s.tls.get('cipher_suite', '')

    # Cipher strength: 0 = broken/missing, 1 = weak, 2 = adequate, 3 = strong
    if not cipher or any(v in cipher for v in ('RC4', 'DES', 'NULL', 'EXPORT')):
        strength = 0
    elif 'GCM' in cipher or 'CHACHA20' in cipher:
        strength = 3
    else:
        strength = 2

    # Forward secrecy: ephemeral key exchange or TLS 1.3 (always ECDHE)
    forward_secrecy = int(
        'ECDHE' in cipher or 'DHE_' in cipher
        or s.tls.get('version') == 'TLS1.3'
    )

    # Certificate chain details
    chain = c.get('chain', [])
    hostname_match = c.get('hostname_match')
    trust_status = c.get('trust_status', 'unknown_no_hostname')

    # TLS handshake completeness
    handshake_done = bool(
        s.tls.get('server_hello')
        and (s.tls.get('encrypted_records_observed') or s.tls.get('change_cipher_spec_observed'))
    )

    return [
        # Original 11 features
        ORDINAL.get(s.tls.get('version'), -1),
        strength,
        forward_secrecy,
        int(s.starttls_used),
        int(s.auth_before_tls),
        c.get('days_until_expiry', 0),
        c.get('key_bits') or 0,
        int(c.get('self_signed', False)),
        int(c.get('weak_signature', False)),
        len(s.findings),
        max((SEVERITY_ORDINAL[f.severity] for f in s.findings), default=0),
        # New 12 behavioral features
        PROTOCOL_ORDINAL.get(s.protocol, 3),
        int(s.server_port in IMPLICIT_TLS_PORTS),
        int(s.starttls_advertised),
        int(s.starttls_requested),
        int(s.plaintext_after_starttls),
        int(handshake_done),
        int(s.complete),
        len(s.commands),
        len(chain),
        int(hostname_match) if hostname_match is not None else -1,
        TRUST_ORDINAL.get(trust_status, 1),
        int(s.tls.get('ocsp_stapling_acknowledged', False)),
    ]
