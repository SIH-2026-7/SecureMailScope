"""Attach independently specified expected rule IDs to generated fixture manifests."""
import argparse
import json
from pathlib import Path

EXPECTED = {
    'hardened': [], 'imap_hardened': [], 'pop3_hardened': [], 'tls13_alt': [],
    'cleartext_auth': ['AUTH-001', 'STARTTLS-002'],
    'imap_cleartext': ['AUTH-001'], 'pop3_cleartext': ['AUTH-001'],
    'expired_cert': ['CERT-001', 'CERT-003'], 'imap_expired': ['CERT-001', 'CERT-003'],
    'starttls_downgrade': ['STARTTLS-001', 'STARTTLS-002', 'AUTH-001'],
    'tls10_weak': ['TLS-002', 'CIPHER-001', 'CIPHER-002', 'CERT-003'],
    'san_mismatch': ['CERT-002', 'CERT-003'], 'static_rsa': ['CIPHER-002', 'CERT-003'],
    'self_signed': ['CERT-003'], 'weak_key': ['CERT-003', 'CERT-004'],
    'tls11': ['TLS-002', 'CERT-003'], 'pop3_static_rsa': ['CIPHER-002', 'CERT-003'],
    'export_cipher': ['TLS-002', 'CIPHER-001', 'CIPHER-002', 'CERT-003'],
    'null_cipher': ['CIPHER-001', 'CERT-003'],
    'des_cipher': ['TLS-002', 'CIPHER-001', 'CIPHER-002', 'CERT-003'],
}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('manifest', type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    for item in manifest:
        item['expected_findings'] = EXPECTED[item['scenario']]
        item['expected_cert_valid'] = None if item['expected_tls_version'] in (None, 'TLS1.3') else False
    args.manifest.write_text(json.dumps(manifest, indent=2))
