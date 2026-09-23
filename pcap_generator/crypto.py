"""Cryptographic and TLS record helpers for synthetic PCAPNG generation."""

import struct
from datetime import datetime, timezone, timedelta
from functools import lru_cache
from typing import Optional, List
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

# Canonical reference capture time: 2026-09-19 10:00:00 UTC
CAPTURE_TIME = datetime(2026, 9, 19, 10, 0, 0, tzinfo=timezone.utc)
BASE_TIMESTAMP = CAPTURE_TIME.timestamp()  # 1789812000.0

# Standard cipher suite identifiers
CIPHER_SUITES = {
    # TLS 1.3
    'TLS_AES_128_GCM_SHA256': 0x1301,
    'TLS_AES_256_GCM_SHA384': 0x1302,
    'TLS_CHACHA20_POLY1305_SHA256': 0x1303,
    # TLS 1.2 modern (ECDHE)
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256': 0xc02f,
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384': 0xc030,
    # Legacy / Static RSA (no forward secrecy)
    'TLS_RSA_WITH_AES_128_CBC_SHA': 0x002f,
    'TLS_RSA_WITH_AES_256_CBC_SHA': 0x0035,
    'TLS_RSA_WITH_AES_128_GCM_SHA256': 0x009c,
    # Weak / Deprecated ciphers
    'TLS_RSA_WITH_RC4_128_SHA': 0x0005,
    'TLS_RSA_WITH_DES_CBC_SHA': 0x0009,
    'TLS_RSA_WITH_3DES_EDE_CBC_SHA': 0x000a,
    'TLS_RSA_EXPORT_WITH_RC4_40_MD5': 0x0003,
}

TLS_VERSIONS = {
    'TLS1.0': 0x0301,
    'TLS1.1': 0x0302,
    'TLS1.2': 0x0303,
    'TLS1.3': 0x0304,
}


@lru_cache(maxsize=8)
def _get_rsa_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Cache private keys to guarantee deterministic and rapid test execution."""
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def generate_certificate(
    common_name: str = 'mail.example.test',
    san_list: Optional[List[str]] = None,
    key_bits: int = 2048,
    expired: bool = False,
    days_valid_before: int = 365,
    days_valid_after: int = 180,
    weak_signature: bool = False,
    serial: int = 10001,
) -> bytes:
    """Generate a deterministic self-signed synthetic X.509 certificate in DER format.
    
    Adheres strictly to the given capture time (2026-09-19 10:00:00 UTC).
    """
    key = _get_rsa_private_key(key_bits)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Example Mail Test Org'),
    ])

    not_before = CAPTURE_TIME - timedelta(days=days_valid_before)
    if expired:
        not_after = CAPTURE_TIME - timedelta(days=30)
    else:
        not_after = CAPTURE_TIME + timedelta(days=days_valid_after)

    if san_list is None:
        san_list = [common_name]

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in san_list]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    )

    sig_hash = hashes.SHA1() if weak_signature else hashes.SHA256()
    cert = builder.sign(key, sig_hash)
    return cert.public_bytes(serialization.Encoding.DER)


def build_extension(ext_type: int, ext_data: bytes) -> bytes:
    """Pack a standard TLS extension (Type: 2B, Length: 2B, Data)."""
    return struct.pack('!HH', ext_type, len(ext_data)) + ext_data


def build_sni_extension(hostname: str) -> bytes:
    """Build RFC 6066 Server Name Indication (SNI) extension."""
    name_bytes = hostname.encode('ascii')
    # ServerName: NameType (1B=0), NameLength (2B), NameBytes
    entry = b'\x00' + struct.pack('!H', len(name_bytes)) + name_bytes
    # ServerNameList: ListLength (2B), Entries
    sni_list = struct.pack('!H', len(entry)) + entry
    return build_extension(0, sni_list)


def build_supported_versions_client(versions: List[int]) -> bytes:
    """Build supported_versions (type 43) extension for ClientHello."""
    version_bytes = b''.join(struct.pack('!H', v) for v in versions)
    # 1-byte length of version list in bytes + list of 2-byte versions
    data = bytes([len(version_bytes)]) + version_bytes
    return build_extension(43, data)


def build_supported_versions_server(selected_version: int) -> bytes:
    """Build supported_versions (type 43) extension for ServerHello."""
    return build_extension(43, struct.pack('!H', selected_version))


def build_tls_record(content_type: int, payload: bytes, version: int = 0x0303) -> bytes:
    """Wrap a payload into a TLS record (Type: 1B, Version: 2B, Length: 2B, Payload)."""
    return bytes([content_type]) + struct.pack('!H', version) + struct.pack('!H', len(payload)) + payload


def build_handshake_message(msg_type: int, body: bytes) -> bytes:
    """Build a TLS Handshake message (Type: 1B, Length: 3B, Body)."""
    return bytes([msg_type]) + len(body).to_bytes(3, 'big') + body


def build_client_hello(
    ciphers: List[int],
    sni: str = 'mail.example.test',
    version: str = 'TLS1.3',
    offered_versions: Optional[List[str]] = None,
    client_random: Optional[bytes] = None,
) -> bytes:
    """Build a complete TLS ClientHello record."""
    if offered_versions is None:
        if version == 'TLS1.3':
            offered_versions = ['TLS1.3', 'TLS1.2']
        elif version == 'TLS1.2':
            offered_versions = ['TLS1.2']
        elif version == 'TLS1.1':
            offered_versions = ['TLS1.1', 'TLS1.0']
        else:
            offered_versions = ['TLS1.0']

    wire_version = min(TLS_VERSIONS.get(version, 0x0303), 0x0303)
    if client_random is None:
        client_random = bytes(range(32))

    session_id = b'\x00'  # 0 length session ID

    cipher_bytes = b''.join(struct.pack('!H', c) for c in ciphers)
    cipher_suites = struct.pack('!H', len(cipher_bytes)) + cipher_bytes
    compression_methods = b'\x01\x00'  # 1 method: null compression

    # Extensions
    ext_payload = b''
    if sni:
        ext_payload += build_sni_extension(sni)

    if 'TLS1.3' in offered_versions:
        version_ints = [TLS_VERSIONS[v] for v in offered_versions if v in TLS_VERSIONS]
        ext_payload += build_supported_versions_client(version_ints)

    extensions_block = struct.pack('!H', len(ext_payload)) + ext_payload

    body = (
        struct.pack('!H', wire_version)
        + client_random
        + session_id
        + cipher_suites
        + compression_methods
        + extensions_block
    )

    handshake = build_handshake_message(1, body)
    return build_tls_record(22, handshake, version=wire_version)


def build_server_hello(
    cipher: int,
    version: str = 'TLS1.3',
    server_random: Optional[bytes] = None,
) -> bytes:
    """Build a complete TLS ServerHello record."""
    wire_version = 0x0303 if version in ('TLS1.2', 'TLS1.3') else TLS_VERSIONS[version]
    if server_random is None:
        server_random = bytes((i + 32) % 256 for i in range(32))

    session_id = b'\x00'
    cipher_suite = struct.pack('!H', cipher)
    compression = b'\x00'

    ext_payload = b''
    if version == 'TLS1.3':
        ext_payload += build_supported_versions_server(0x0304)

    extensions_block = struct.pack('!H', len(ext_payload)) + ext_payload

    body = (
        struct.pack('!H', wire_version)
        + server_random
        + session_id
        + cipher_suite
        + compression
        + extensions_block
    )

    handshake = build_handshake_message(2, body)
    return build_tls_record(22, handshake, version=wire_version)


def build_certificate_message(der_certs: List[bytes]) -> bytes:
    """Build a TLS Handshake Certificate record (msg_type=11)."""
    cert_list = b''
    for cert in der_certs:
        cert_list += len(cert).to_bytes(3, 'big') + cert

    # First 3 bytes: total length of certificates list
    body = len(cert_list).to_bytes(3, 'big') + cert_list
    handshake = build_handshake_message(11, body)
    return build_tls_record(22, handshake, version=0x0303)


def build_change_cipher_spec(version: int = 0x0303) -> bytes:
    """Build a TLS ChangeCipherSpec record (ContentType=20)."""
    return build_tls_record(20, b'\x01', version=version)


def build_encrypted_application_data(payload: bytes, version: int = 0x0303) -> bytes:
    """Build an encrypted TLS Application Data record (ContentType=23)."""
    return build_tls_record(23, payload, version=version)
