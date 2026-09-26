"""Reproducible wire-format lab captures. No external servers or credentials required.

These deliberately constructed packets exercise passive parsing, not successful
live cryptographic handshakes. TLS 1.3 Certificate is intentionally not fabricated.
"""
import argparse
import json
import random
import struct
from datetime import datetime, timezone, timedelta
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from scapy.all import Ether, IP, TCP, Raw, wrpcap

ROOT = Path(__file__).resolve().parents[1]
CAPTURE_TIME = datetime(2026, 9, 19, 10, tzinfo=timezone.utc)
IMPLICIT_TLS_PORTS = {465, 993, 995}

# Tuple format: (protocol, tls_version, cipher_hex, risk_class[, port_override])
# When port_override is present, it indicates implicit TLS (no STARTTLS exchange).
SCENARIOS = {
    # --- Existing STARTTLS scenarios ---
    'hardened': ('SMTP', 'TLS1.3', 0x1301, 'Low'),
    'cleartext_auth': ('ALL', None, 0, 'Critical'),
    'expired_cert': ('SMTP', 'TLS1.2', 0xc02f, 'High'),
    'starttls_downgrade': ('SMTP', None, 0, 'Critical'),
    'tls10_weak': ('SMTP', 'TLS1.0', 0x0005, 'Critical'),
    'san_mismatch': ('SMTP', 'TLS1.2', 0xc02f, 'High'),
    'static_rsa': ('SMTP', 'TLS1.2', 0x009c, 'High'),
    'self_signed': ('SMTP', 'TLS1.2', 0xc02f, 'Medium'),
    'weak_key': ('SMTP', 'TLS1.2', 0xc02f, 'High'),
    'tls11': ('SMTP', 'TLS1.1', 0xc02f, 'High'),
    'imap_hardened': ('IMAP', 'TLS1.3', 0x1302, 'Low'),
    'pop3_hardened': ('POP3', 'TLS1.3', 0x1303, 'Low'),
    'imap_cleartext': ('IMAP', None, 0, 'Critical'),
    'pop3_cleartext': ('POP3', None, 0, 'Critical'),
    'imap_expired': ('IMAP', 'TLS1.2', 0xc02f, 'High'),
    'pop3_static_rsa': ('POP3', 'TLS1.2', 0x002f, 'High'),
    'export_cipher': ('SMTP', 'TLS1.0', 0x0003, 'Critical'),
    'null_cipher': ('SMTP', 'TLS1.2', 0, 'Critical'),
    'des_cipher': ('SMTP', 'TLS1.0', 0x000a, 'Critical'),
    'tls13_alt': ('SMTP', 'TLS1.3', 0x1302, 'Low'),
    # --- New implicit TLS scenarios (SMTPS/IMAPS/POP3S) ---
    'smtps_hardened': ('SMTP', 'TLS1.3', 0x1301, 'Low', 465),
    'imaps_hardened': ('IMAP', 'TLS1.3', 0x1302, 'Low', 993),
    'pop3s_hardened': ('POP3', 'TLS1.3', 0x1303, 'Low', 995),
    'imaps_expired': ('IMAP', 'TLS1.2', 0xc02f, 'High', 993),
    'pop3s_weak_key': ('POP3', 'TLS1.2', 0xc02f, 'High', 995),
    'smtps_static_rsa': ('SMTP', 'TLS1.2', 0x009c, 'High', 465),
    'imaps_san_mismatch': ('IMAP', 'TLS1.2', 0xc02f, 'High', 993),
    'smtps_legacy_tls10': ('SMTP', 'TLS1.0', 0x0005, 'Critical', 465),
}


def ext(kind, value):
    return struct.pack('!HH', kind, len(value)) + value


def handshake(kind, body):
    message = bytes([kind]) + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x03' + len(message).to_bytes(2, 'big') + message


def hello_pair(version, cipher):
    versions = {'TLS1.0': 0x0301, 'TLS1.1': 0x0302, 'TLS1.2': 0x0303, 'TLS1.3': 0x0304}
    wire = versions[version]
    name = b'mail.example.test'
    sni = b'\x00' + len(name).to_bytes(2, 'big') + name
    extensions = ext(0, len(sni).to_bytes(2, 'big') + sni)
    if version == 'TLS1.3':
        extensions += ext(43, b'\x02\x03\x04')
    prefix = struct.pack('!H', min(wire, 0x0303)) + bytes(range(32)) + b'\x00'
    client = prefix + b'\x00\x02' + struct.pack('!H', cipher) + b'\x01\x00' + len(extensions).to_bytes(2, 'big') + extensions
    extensions = ext(43, b'\x03\x04') if version == 'TLS1.3' else b''
    server = prefix + struct.pack('!H', cipher) + b'\x00' + len(extensions).to_bytes(2, 'big') + extensions
    return handshake(1, client), handshake(2, server)


def certificate(name, bits=2048, expired=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    end = CAPTURE_TIME - timedelta(days=18) if expired else CAPTURE_TIME + timedelta(days=180)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(CAPTURE_TIME - timedelta(days=365))
            .not_valid_after(end).add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def generate(name, count=1, seed=42, disorder=False):
    scenario = SCENARIOS[name]
    protocol, version, cipher, risk = scenario[:4]
    port_override = scenario[4] if len(scenario) > 4 else None
    implicit_tls = port_override in IMPLICIT_TLS_PORTS if port_override else False
    rng, packets = random.Random(seed), []
    cert = None
    cert_name = 'mail.example.test'
    if 'san_mismatch' in name:
        cert_name = 'wrong.example.test'
    cert_bits = 1024 if 'weak_key' in name else 2048
    cert_expired = 'expired' in name
    if version and version != 'TLS1.3':
        cert = certificate(cert_name, cert_bits, cert_expired)
    for i in range(count):
        protocols = ['SMTP', 'IMAP', 'POP3'] if protocol == 'ALL' else [protocol]
        for offset, proto in enumerate(protocols):
            if port_override:
                port = port_override
            else:
                port = {'SMTP': 587, 'IMAP': 143, 'POP3': 110}[proto]
            sport = 40000 + i * 3 + offset
            seq = {'client': 1000, 'server': 9000}
            timestamp = CAPTURE_TIME.timestamp() + i * 3 + offset * 0.1
            def packet(direction, payload=b'', flags='PA'):
                nonlocal timestamp
                client = direction == 'client'
                item = Ether()/IP(src='192.0.2.10' if client else '198.51.100.25', dst='198.51.100.25' if client else '192.0.2.10')/TCP(sport=sport if client else port, dport=port if client else sport, seq=seq[direction], flags=flags)
                if payload:
                    item = item/Raw(payload)
                item.time = timestamp
                timestamp += rng.uniform(0.001, 0.025)
                seq[direction] += len(payload) + int('S' in flags or 'F' in flags)
                packets.append(item)
            packet('client', flags='S'); packet('server', flags='SA'); packet('client', flags='A')
            if implicit_tls:
                # Implicit TLS: TLS handshake starts immediately after TCP handshake
                # No plaintext greeting or STARTTLS negotiation
                pass
            else:
                # Explicit TLS (STARTTLS) flow
                packet('server', {'SMTP': b'220 mail.example.test ESMTP\r\n', 'IMAP': b'* OK IMAP ready\r\n', 'POP3': b'+OK POP3 ready\r\n'}[proto])
                if proto == 'SMTP':
                    packet('client', b'EHLO client.example.test\r\n')
                    packet('server', b'250-mail.example.test\r\n250 STARTTLS\r\n')
                if version or name == 'starttls_downgrade':
                    packet('client', {'SMTP': b'STARTTLS\r\n', 'IMAP': b'a1 STARTTLS\r\n', 'POP3': b'STLS\r\n'}[proto])
                    packet('server', {'SMTP': b'220 Ready for TLS\r\n', 'IMAP': b'a1 OK Begin TLS\r\n', 'POP3': b'+OK Begin TLS\r\n'}[proto])
            if version:
                client_hello, server_hello = hello_pair(version, cipher)
                # Segment ClientHello and Certificate to exercise stream reassembly.
                packet('client', client_hello[:17]); packet('client', client_hello[17:])
                packet('server', server_hello)
                if cert:
                    cert_list = len(cert).to_bytes(3, 'big') + cert
                    record = handshake(11, len(cert_list).to_bytes(3, 'big') + cert_list)
                    packet('server', record[:100]); packet('server', record[100:])
                # Opaque record marker: demo fixture, not a usable encrypted connection.
                packet('server', b'\x17\x03\x03\x00\x10' + bytes(16))
            else:
                if proto == 'POP3':
                    packet('client', b'USER demo-user\r\n'); packet('server', b'+OK user\r\n')
                packet('client', {'SMTP': b'AUTH PLAIN ZGVtby11c2VyAGRlbW8tcGFzc3dvcmQ=\r\n', 'IMAP': b'a2 LOGIN demo-user demo-password\r\n', 'POP3': b'PASS demo-password\r\n'}[proto])
                packet('server', {'SMTP': b'235 Authentication successful\r\n', 'IMAP': b'a2 OK Logged in\r\n', 'POP3': b'+OK authenticated\r\n'}[proto])
                packet('client', b'QUIT\r\n' if proto != 'IMAP' else b'a3 LOGOUT\r\n')
            packet('client', flags='FA'); packet('server', flags='FA')
    if disorder and len(packets) > 10:
        packets[8], packets[9] = packets[9], packets[8]
        packets.insert(10, packets[8].copy())
    return packets


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=ROOT / 'public' / 'captures')
    parser.add_argument('--sessions', type=int, default=1)
    parser.add_argument('--all', action='store_true')
    parser.add_argument('--disorder', action='store_true')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    names = list(SCENARIOS) if args.all else list(SCENARIOS)[:4]
    manifest = []
    for name in names:
        path = args.output / f'{name}.pcap'
        wrpcap(str(path), generate(name, args.sessions, disorder=args.disorder))
        manifest.append({'pcap': path.name, 'scenario': name, 'protocol': SCENARIOS[name][0],
                         'expected_tls_version': SCENARIOS[name][1], 'expected_risk_class': SCENARIOS[name][3],
                         'provenance': 'Constructed wire-format laboratory fixture, not a live server capture'})
    (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    print(f'Generated {len(names)} captures in {args.output}')


if __name__ == '__main__':
    main()
