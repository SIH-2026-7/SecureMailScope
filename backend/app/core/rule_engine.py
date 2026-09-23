from ..models.schemas import Finding

SEVERITY = {'Critical': 30, 'High': 15, 'Medium': 7, 'Low': 2, 'Info': 0}
ORDINAL = {'SSLv2': -1, 'SSLv3': 0, 'TLS1.0': 1, 'TLS1.1': 2, 'TLS1.2': 3, 'TLS1.3': 4}
RULES = []


def rule(fn):
    RULES.append(fn)
    return fn


def finding(s, id, severity, title, description, remediation, evidence=None):
    return Finding(rule_id=id, severity=severity, title=title, description=description,
                   remediation=remediation, evidence=evidence or s.evidence)


@rule
def rule_tls_version(s):
    version = s.tls.get('version')
    ev = s.tls.get('ServerHello_evidence')
    if version in ('SSLv2', 'SSLv3'):
        yield finding(s, 'TLS-001', 'Critical', 'Obsolete SSL negotiated', version, 'Require TLS 1.2 or TLS 1.3.', ev)
    if version in ('TLS1.0', 'TLS1.1'):
        yield finding(s, 'TLS-002', 'High', 'Legacy TLS negotiated', version, 'Disable TLS 1.0 and 1.1.', ev)
    if version in ORDINAL and any(ORDINAL.get(v, -2) > ORDINAL[version] for v in s.tls.get('offered_versions', [])):
        yield finding(s, 'TLS-003', 'Medium', 'Lower version selected', 'Client offered a higher version; this is an indicator, not proof of attack.', 'Review server policy and downgrade protections.', ev)


@rule
def rule_cipher_suite(s):
    cipher = s.tls.get('cipher_suite', '')
    if any(token in cipher for token in ('RC4', 'DES', 'NULL', 'EXPORT')):
        yield finding(s, 'CIPHER-001', 'Critical', 'Weak cipher negotiated', cipher, 'Use ECDHE with AES-GCM or ChaCha20-Poly1305.', s.tls.get('ServerHello_evidence'))
    if cipher.startswith('TLS_RSA_'):
        yield finding(s, 'CIPHER-002', 'High', 'No forward secrecy', cipher, 'Replace static RSA key exchange with ECDHE.', s.tls.get('ServerHello_evidence'))


@rule
def rule_starttls_downgrade(s):
    if s.plaintext_after_starttls:
        yield finding(s, 'STARTTLS-001', 'Critical', 'Plaintext after STARTTLS request', 'A client command continued without an observed TLS handshake.', 'Fail closed when STARTTLS fails; require TLS before authentication.', s.tls.get('plaintext_after_starttls_evidence'))
    if s.starttls_advertised and not s.starttls_used and s.complete:
        yield finding(s, 'STARTTLS-002', 'Medium', 'Advertised STARTTLS not used', 'The observed session did not upgrade.', 'Enforce STARTTLS on client and server.', s.tls.get('capability_evidence'))


@rule
def rule_cleartext_auth(s):
    if s.auth_before_tls:
        yield finding(s, 'AUTH-001', 'Critical', 'Authentication exposed in plaintext', 'Authentication was attempted before encryption. Credential content is redacted.', 'Require TLS before AUTH, LOGIN or PASS; rotate exposed credentials.', s.tls.get('auth_evidence'))


@rule
def rule_certificate(s):
    c = s.certificate
    if not c:
        return
    checks = [
        ('CERT-001', 'High', c['expired'], 'Certificate expired at capture time', 'Renew the certificate and deploy the full chain.'),
        ('CERT-002', 'High', c['hostname_match'] is False, 'Certificate hostname mismatch', 'Issue a certificate covering the requested SNI hostname.'),
        ('CERT-003', 'Medium', c['trust_status'] == 'validation_failed' or c['self_signed'], 'Certificate chain not validated', 'Deploy a valid chain anchored in a trusted CA; check validity and constraints.'),
        ('CERT-004', 'High', c['weak_key'], 'Weak certificate public key', 'Use RSA 2048+ or an approved elliptic curve.'),
        ('CERT-005', 'Medium', c['weak_signature'], 'Weak certificate signature', 'Reissue with SHA-256 or stronger.'),
        ('CERT-006', 'High', c['not_yet_valid'], 'Certificate not yet valid at capture time', 'Check certificate validity and deployment dates.'),
        ('CERT-007', 'Medium', not c['extensions_valid'], 'Unexpected leaf certificate extensions', 'Set CA:FALSE and use serverAuth extended key usage.'),
    ]
    for id, severity, triggered, title, remediation in checks:
        if triggered:
            yield finding(s, id, severity, title, f'Certificate SHA-256: {c["fingerprint_sha256"]}', remediation, c['evidence'])


def evaluate(s):
    return [finding for fn in RULES for finding in fn(s)]
