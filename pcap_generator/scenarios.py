"""Scenario definitions for SecureMailScope PCAPNG fixtures."""

import random
from typing import List, Dict, Any, Tuple
from scapy.all import Packet
from .crypto import (
    BASE_TIMESTAMP,
    generate_certificate,
    build_client_hello,
    build_server_hello,
    build_certificate_message,
    build_change_cipher_spec,
    build_encrypted_application_data,
    CIPHER_SUITES,
)
from .builder import TCPFlow


def scenario_hardened_smtp(seed: int = 42) -> Tuple[List[Packet], Dict[str, Any]]:
    """Scenario 1: Hardened SMTP with STARTTLS and TLS 1.3 AES-256-GCM."""
    rng = random.Random(seed)
    flow = TCPFlow(
        client_ip="10.24.1.10",
        server_ip="10.24.1.25",
        client_port=45101,
        server_port=587,
        start_time=BASE_TIMESTAMP,
        rng=rng,
    )

    flow.handshake()
    flow.send("server", b"220 mail.example.test ESMTP SecureMailScope\r\n", marker="greeting")
    flow.send("client", b"EHLO client.example.test\r\n")
    flow.send(
        "server",
        b"250-mail.example.test\r\n250-PIPELINING\r\n250-SIZE 52428800\r\n250-8BITMIME\r\n250 STARTTLS\r\n",
        marker="capabilities",
    )
    flow.send("client", b"STARTTLS\r\n", marker="starttls_request")
    flow.send("server", b"220 2.0.0 Ready to start TLS\r\n")

    # TLS 1.3 Handshake
    client_hello = build_client_hello(
        ciphers=[CIPHER_SUITES['TLS_AES_256_GCM_SHA384'], CIPHER_SUITES['TLS_AES_128_GCM_SHA256']],
        sni="mail.example.test",
        version="TLS1.3",
    )
    flow.send("client", client_hello, marker="client_hello")

    server_hello = build_server_hello(
        cipher=CIPHER_SUITES['TLS_AES_256_GCM_SHA384'],
        version="TLS1.3",
    )
    flow.send("server", server_hello, marker="server_hello")

    # Encrypted Application Data (TLS 1.3 records)
    flow.send("server", build_encrypted_application_data(b"\x00" * 48), marker="encrypted_traffic")
    flow.send("client", build_encrypted_application_data(b"\x00" * 64))
    flow.send("server", build_encrypted_application_data(b"\x00" * 32))

    flow.close()

    meta = {
        "scenario": "hardened_smtp",
        "protocol": "SMTP",
        "port": 587,
        "client_ip": flow.client_ip,
        "server_ip": flow.server_ip,
        "expected_findings": [],
        "expected_severity": "None",
        "expected_posture": "Strong",
        "description": "SMTP submission on port 587 with STARTTLS, TLS 1.3, AES-256-GCM cipher, forward secrecy, and no credentials exposed before encryption.",
        "important_frames": flow.markers,
    }
    return flow.packets, meta


def scenario_hardened_imap(seed: int = 42) -> Tuple[List[Packet], Dict[str, Any]]:
    """Scenario 2: Hardened IMAP on port 143 upgraded using STARTTLS and TLS 1.3."""
    rng = random.Random(seed)
    flow = TCPFlow(
        client_ip="10.24.1.12",
        server_ip="10.24.1.25",
        client_port=45102,
        server_port=143,
        start_time=BASE_TIMESTAMP + 1.0,
        rng=rng,
    )

    flow.handshake()
    flow.send(
        "server",
        b"* OK [CAPABILITY IMAP4rev1 STARTTLS IDLE] mail.example.test IMAP4rev1 ready\r\n",
        marker="greeting",
    )
    flow.send("client", b"a1 STARTTLS\r\n", marker="starttls_request")
    flow.send("server", b"a1 OK Begin TLS negotiation now\r\n")

    # TLS 1.3
    client_hello = build_client_hello(
        ciphers=[CIPHER_SUITES['TLS_AES_256_GCM_SHA384'], CIPHER_SUITES['TLS_AES_128_GCM_SHA256']],
        sni="mail.example.test",
        version="TLS1.3",
    )
    flow.send("client", client_hello, marker="client_hello")

    server_hello = build_server_hello(
        cipher=CIPHER_SUITES['TLS_AES_256_GCM_SHA384'],
        version="TLS1.3",
    )
    flow.send("server", server_hello, marker="server_hello")

    # Encrypted session (LOGIN happens securely inside encryption)
    flow.send("server", build_encrypted_application_data(b"\x00" * 48), marker="encrypted_traffic")
    flow.send("client", build_encrypted_application_data(b"\x00" * 64))
    flow.send("server", build_encrypted_application_data(b"\x00" * 32))

    flow.close()

    meta = {
        "scenario": "hardened_imap",
        "protocol": "IMAP",
        "port": 143,
        "client_ip": flow.client_ip,
        "server_ip": flow.server_ip,
        "expected_findings": [],
        "expected_severity": "None",
        "expected_posture": "Strong",
        "description": "IMAP on port 143 with STARTTLS upgrade, TLS 1.3, modern cipher, and encrypted authentication.",
        "important_frames": flow.markers,
    }
    return flow.packets, meta


def scenario_hardened_pop3(seed: int = 42) -> Tuple[List[Packet], Dict[str, Any]]:
    """Scenario 3: Hardened POP3 on port 110 upgraded using STLS and TLS 1.3."""
    rng = random.Random(seed)
    flow = TCPFlow(
        client_ip="10.24.1.14",
        server_ip="10.24.1.25",
        client_port=45103,
        server_port=110,
        start_time=BASE_TIMESTAMP + 2.0,
        rng=rng,
    )

    flow.handshake()
    flow.send("server", b"+OK POP3 server ready <mail.example.test>\r\n", marker="greeting")
    flow.send("client", b"CAPA\r\n")
    flow.send(
        "server",
        b"+OK Capability list follows\r\nSTLS\r\nUSER\r\nIMPLEMENTATION SecureMailScope\r\n.\r\n",
        marker="capabilities",
    )
    flow.send("client", b"STLS\r\n", marker="starttls_request")
    flow.send("server", b"+OK Begin TLS negotiation\r\n")

    # TLS 1.3
    client_hello = build_client_hello(
        ciphers=[CIPHER_SUITES['TLS_AES_256_GCM_SHA384'], CIPHER_SUITES['TLS_AES_128_GCM_SHA256']],
        sni="mail.example.test",
        version="TLS1.3",
    )
    flow.send("client", client_hello, marker="client_hello")

    server_hello = build_server_hello(
        cipher=CIPHER_SUITES['TLS_AES_256_GCM_SHA384'],
        version="TLS1.3",
    )
    flow.send("server", server_hello, marker="server_hello")

    # Encrypted application data
    flow.send("server", build_encrypted_application_data(b"\x00" * 48), marker="encrypted_traffic")
    flow.send("client", build_encrypted_application_data(b"\x00" * 64))
    flow.send("server", build_encrypted_application_data(b"\x00" * 32))

    flow.close()

    meta = {
        "scenario": "hardened_pop3",
        "protocol": "POP3",
        "port": 110,
        "client_ip": flow.client_ip,
        "server_ip": flow.server_ip,
        "expected_findings": [],
        "expected_severity": "None",
        "expected_posture": "Strong",
        "description": "POP3 on port 110 upgraded via STLS to TLS 1.3. USER/PASS authentication occurs strictly after encryption.",
        "important_frames": flow.markers,
    }
    return flow.packets, meta


def scenario_cleartext_auth_smtp(seed: int = 42) -> Tuple[List[Packet], Dict[str, Any]]:
    """Scenario 4: Cleartext AUTH LOGIN on SMTP port 587 without encryption."""
    rng = random.Random(seed)
    flow = TCPFlow(
        client_ip="10.24.1.16",
        server_ip="10.24.1.25",
        client_port=45104,
        server_port=587,
        start_time=BASE_TIMESTAMP + 3.0,
        rng=rng,
    )

    flow.handshake()
    flow.send("server", b"220 mail.example.test ESMTP Cleartext Warning\r\n", marker="greeting")
    flow.send("client", b"EHLO client.example.test\r\n")
    flow.send(
        "server",
        b"250-mail.example.test\r\n250-AUTH LOGIN PLAIN\r\n250 8BITMIME\r\n",
        marker="capabilities",
    )

    # AUTH LOGIN flow with dummy credentials
    flow.send("client", b"AUTH LOGIN\r\n", marker="auth_command")
    flow.send("server", b"334 VXNlcm5hbWU6\r\n")  # Base64 "Username:"
    flow.send("client", b"ZGVtby11c2Vy\r\n", marker="auth_username")  # Base64 "demo-user"
    flow.send("server", b"334 UGFzc3dvcmQ6\r\n")  # Base64 "Password:"
    flow.send("client", b"ZGVtby1wYXNzd29yZA==\r\n", marker="auth_password")  # Base64 "demo-password"
    flow.send("server", b"235 2.7.0 Authentication successful\r\n")

    flow.send("client", b"QUIT\r\n")
    flow.send("server", b"221 2.0.0 Bye\r\n")

    flow.close()

    meta = {
        "scenario": "cleartext_auth_smtp",
        "protocol": "SMTP",
        "port": 587,
        "client_ip": flow.client_ip,
        "server_ip": flow.server_ip,
        "expected_findings": ["AUTH-001"],
        "expected_severity": "Critical",
        "expected_posture": "Poor",
        "description": "SMTP on port 587 where server advertises AUTH before STARTTLS, and client submits cleartext credentials (AUTH LOGIN).",
        "important_frames": flow.markers,
    }
    return flow.packets, meta


def scenario_cleartext_auth_imap(seed: int = 42) -> Tuple[List[Packet], Dict[str, Any]]:
    """Scenario 5: Cleartext LOGIN on IMAP port 143."""
    rng = random.Random(seed)
    flow = TCPFlow(
        client_ip="10.24.1.18",
        server_ip="10.24.1.25",
        client_port=45105,
        server_port=143,
        start_time=BASE_TIMESTAMP + 4.0,
        rng=rng,
    )

    flow.handshake()
    flow.send(
        "server",
        b"* OK [CAPABILITY IMAP4rev1 LOGINDISABLED_OFF] mail.example.test IMAP4rev1 ready\r\n",
        marker="greeting",
    )
    # Cleartext LOGIN
    flow.send("client", b"a1 LOGIN demo-user demo-password\r\n", marker="auth_command")
    flow.send("server", b"a1 OK [CAPABILITY IMAP4rev1] LOGIN completed\r\n")

    flow.send("client", b"a2 LOGOUT\r\n")
    flow.send("server", b"* BYE IMAP4rev1 Server logging out\r\na2 OK LOGOUT completed\r\n")

    flow.close()

    meta = {
        "scenario": "cleartext_auth_imap",
        "protocol": "IMAP",
        "port": 143,
        "client_ip": flow.client_ip,
        "server_ip": flow.server_ip,
        "expected_findings": ["AUTH-001"],
        "expected_severity": "Critical",
        "expected_posture": "Poor",
        "description": "IMAP on port 143 where client sends plaintext LOGIN before STARTTLS.",
        "important_frames": flow.markers,
    }
    return flow.packets, meta


def scenario_cleartext_auth_pop3(seed: int = 42) -> Tuple[List[Packet], Dict[str, Any]]:
    """Scenario 6: Cleartext USER and PASS on POP3 port 110."""
    rng = random.Random(seed)
    flow = TCPFlow(
        client_ip="10.24.1.20",
        server_ip="10.24.1.25",
        client_port=45106,
        server_port=110,
        start_time=BASE_TIMESTAMP + 5.0,
        rng=rng,
    )

    flow.handshake()
    flow.send("server", b"+OK POP3 server ready\r\n", marker="greeting")
    flow.send("client", b"USER demo-user\r\n", marker="user_command")
    flow.send("server", b"+OK please send PASS command\r\n")
    flow.send("client", b"PASS demo-password\r\n", marker="auth_command")
    flow.send("server", b"+OK Mailbox open, 0 messages\r\n")

    flow.send("client", b"QUIT\r\n")
    flow.send("server", b"+OK Goodbye\r\n")

    flow.close()

    meta = {
        "scenario": "cleartext_auth_pop3",
        "protocol": "POP3",
        "port": 110,
        "client_ip": flow.client_ip,
        "server_ip": flow.server_ip,
        "expected_findings": ["AUTH-001"],
        "expected_severity": "Critical",
        "expected_posture": "Poor",
        "description": "POP3 on port 110 where client sends cleartext USER and PASS commands before STLS.",
        "important_frames": flow.markers,
    }
    return flow.packets, meta


def scenario_starttls_downgrade(seed: int = 42) -> Tuple[List[Packet], Dict[str, Any]]:
    """Scenario 7: STARTTLS downgrade attack where STARTTLS fails and client continues in plaintext."""
    rng = random.Random(seed)
    flow = TCPFlow(
        client_ip="10.24.1.22",
        server_ip="10.24.1.25",
        client_port=45107,
        server_port=587,
        start_time=BASE_TIMESTAMP + 6.0,
        rng=rng,
    )

    flow.handshake()
    flow.send("server", b"220 mail.example.test ESMTP\r\n", marker="greeting")
    flow.send("client", b"EHLO client.example.test\r\n")
    flow.send("server", b"250-mail.example.test\r\n250 STARTTLS\r\n", marker="starttls_advertised")

    # Client issues STARTTLS
    flow.send("client", b"STARTTLS\r\n", marker="starttls_request")
    # Server / MitM responds with temporary error or strips TLS
    flow.send("server", b"454 4.7.0 TLS not available due to temporary reason\r\n", marker="starttls_rejection")

    # Client insecurely downgrades and falls back to cleartext AUTH
    flow.send(
        "client",
        b"AUTH PLAIN ZGVtby11c2VyAGRlbW8tdXNlcgBkZW1vLXBhc3N3b3Jk\r\n",
        marker="plaintext_auth",
    )
    flow.send("server", b"235 2.7.0 Authentication successful\r\n")

    flow.send("client", b"QUIT\r\n")
    flow.send("server", b"221 2.0.0 Bye\r\n")

    flow.close()

    meta = {
        "scenario": "starttls_downgrade",
        "protocol": "SMTP",
        "port": 587,
        "client_ip": flow.client_ip,
        "server_ip": flow.server_ip,
        "expected_findings": ["STARTTLS-001", "AUTH-001"],
        "expected_severity": "Critical",
        "expected_posture": "Critical Risk",
        "description": "STARTTLS advertised on port 587; STARTTLS fails and client continues with plaintext AUTH command without TLS handshake.",
        "important_frames": flow.markers,
    }
    return flow.packets, meta


def scenario_expired_certificate(seed: int = 42) -> Tuple[List[Packet], Dict[str, Any]]:
    """Scenario 8: SMTP with STARTTLS and TLS 1.2 presenting an expired X.509 certificate."""
    rng = random.Random(seed)
    flow = TCPFlow(
        client_ip="10.24.1.24",
        server_ip="10.24.1.25",
        client_port=45108,
        server_port=587,
        start_time=BASE_TIMESTAMP + 7.0,
        rng=rng,
    )

    flow.handshake()
    flow.send("server", b"220 mail.example.test ESMTP\r\n", marker="greeting")
    flow.send("client", b"EHLO client.example.test\r\n")
    flow.send("server", b"250-mail.example.test\r\n250 STARTTLS\r\n")
    flow.send("client", b"STARTTLS\r\n", marker="starttls_request")
    flow.send("server", b"220 2.0.0 Ready to start TLS\r\n")

    # TLS 1.2 Handshake
    client_hello = build_client_hello(
        ciphers=[CIPHER_SUITES['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256']],
        sni="mail.example.test",
        version="TLS1.2",
    )
    flow.send("client", client_hello, marker="client_hello")

    server_hello = build_server_hello(
        cipher=CIPHER_SUITES['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'],
        version="TLS1.2",
    )
    flow.send("server", server_hello, marker="server_hello")

    # Expired certificate (expired 30 days before capture time 2026-09-19)
    cert_der = generate_certificate(
        common_name="mail.example.test",
        san_list=["mail.example.test"],
        key_bits=2048,
        expired=True,
    )
    cert_msg = build_certificate_message([cert_der])
    flow.send("server", cert_msg, marker="certificate_message")

    # ChangeCipherSpec + Encrypted record to mark handshake complete
    flow.send("server", build_change_cipher_spec(0x0303), marker="change_cipher_spec")
    flow.send("server", build_encrypted_application_data(b"\x00" * 32))

    flow.close()

    meta = {
        "scenario": "expired_certificate",
        "protocol": "SMTP",
        "port": 587,
        "client_ip": flow.client_ip,
        "server_ip": flow.server_ip,
        "expected_findings": ["CERT-001", "CERT-003"],
        "expected_severity": "High",
        "expected_posture": "Degraded",
        "description": "SMTP submission with STARTTLS and TLS 1.2 presenting an X.509 certificate expired at capture timestamp.",
        "important_frames": flow.markers,
    }
    return flow.packets, meta


def scenario_san_mismatch(seed: int = 42) -> Tuple[List[Packet], Dict[str, Any]]:
    """Scenario 9: TLS 1.2 SMTP session where certificate SAN does not match requested SNI."""
    rng = random.Random(seed)
    flow = TCPFlow(
        client_ip="10.24.1.26",
        server_ip="10.24.1.25",
        client_port=45109,
        server_port=587,
        start_time=BASE_TIMESTAMP + 8.0,
        rng=rng,
    )

    flow.handshake()
    flow.send("server", b"220 mail.example.test ESMTP\r\n", marker="greeting")
    flow.send("client", b"EHLO client.example.test\r\n")
    flow.send("server", b"250-mail.example.test\r\n250 STARTTLS\r\n")
    flow.send("client", b"STARTTLS\r\n", marker="starttls_request")
    flow.send("server", b"220 2.0.0 Ready to start TLS\r\n")

    # Client requests mail.example.test
    client_hello = build_client_hello(
        ciphers=[CIPHER_SUITES['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256']],
        sni="mail.example.test",
        version="TLS1.2",
    )
    flow.send("client", client_hello, marker="client_hello_sni")

    server_hello = build_server_hello(
        cipher=CIPHER_SUITES['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'],
        version="TLS1.2",
    )
    flow.send("server", server_hello, marker="server_hello")

    # Server presents valid certificate, but SAN contains other.example.test
    cert_der = generate_certificate(
        common_name="other.example.test",
        san_list=["other.example.test"],
        key_bits=2048,
        expired=False,
    )
    cert_msg = build_certificate_message([cert_der])
    flow.send("server", cert_msg, marker="certificate_message")

    flow.send("server", build_change_cipher_spec(0x0303), marker="change_cipher_spec")
    flow.send("server", build_encrypted_application_data(b"\x00" * 32))

    flow.close()

    meta = {
        "scenario": "san_mismatch",
        "protocol": "SMTP",
        "port": 587,
        "client_ip": flow.client_ip,
        "server_ip": flow.server_ip,
        "expected_findings": ["CERT-002", "CERT-003"],
        "expected_severity": "High",
        "expected_posture": "Degraded",
        "description": "TLS 1.2 SMTP session where requested SNI is mail.example.test, but server certificate SAN only covers other.example.test.",
        "important_frames": flow.markers,
    }
    return flow.packets, meta


def scenario_weak_crypto(seed: int = 42) -> Tuple[List[Packet], Dict[str, Any]]:
    """Scenario 10: Deprecated TLS 1.0, weak RC4 cipher, static RSA, and weak 1024-bit key."""
    rng = random.Random(seed)
    flow = TCPFlow(
        client_ip="10.24.1.28",
        server_ip="10.24.1.25",
        client_port=45110,
        server_port=587,
        start_time=BASE_TIMESTAMP + 9.0,
        rng=rng,
    )

    flow.handshake()
    flow.send("server", b"220 mail.example.test ESMTP Legacy\r\n", marker="greeting")
    flow.send("client", b"EHLO client.example.test\r\n")
    flow.send("server", b"250-mail.example.test\r\n250 STARTTLS\r\n")
    flow.send("client", b"STARTTLS\r\n", marker="starttls_request")
    flow.send("server", b"220 2.0.0 Ready to start TLS\r\n")

    # TLS 1.0 ClientHello with RC4
    client_hello = build_client_hello(
        ciphers=[CIPHER_SUITES['TLS_RSA_WITH_RC4_128_SHA']],
        sni="mail.example.test",
        version="TLS1.0",
    )
    flow.send("client", client_hello, marker="client_hello")

    server_hello = build_server_hello(
        cipher=CIPHER_SUITES['TLS_RSA_WITH_RC4_128_SHA'],
        version="TLS1.0",
    )
    flow.send("server", server_hello, marker="server_hello")

    # 1024-bit RSA weak key
    cert_der = generate_certificate(
        common_name="mail.example.test",
        san_list=["mail.example.test"],
        key_bits=1024,
        expired=False,
    )
    cert_msg = build_certificate_message([cert_der])
    flow.send("server", cert_msg, marker="certificate_message")

    flow.send("server", build_change_cipher_spec(0x0301), marker="change_cipher_spec")
    flow.send("server", build_encrypted_application_data(b"\x00" * 32, version=0x0301))

    flow.close()

    meta = {
        "scenario": "weak_crypto",
        "protocol": "SMTP",
        "port": 587,
        "client_ip": flow.client_ip,
        "server_ip": flow.server_ip,
        "expected_findings": ["TLS-002", "CIPHER-001", "CIPHER-002", "CERT-004", "CERT-003"],
        "expected_severity": "Critical",
        "expected_posture": "Critical Risk",
        "description": "Legacy TLS 1.0 session negotiating weak RC4 cipher (TLS_RSA_WITH_RC4_128_SHA), missing forward secrecy, and 1024-bit RSA public key.",
        "important_frames": flow.markers,
    }
    return flow.packets, meta


def scenario_partial_capture(seed: int = 42) -> Tuple[List[Packet], Dict[str, Any]]:
    """Scenario 11: Incomplete capture truncated before TLS handshake completes."""
    rng = random.Random(seed)
    flow = TCPFlow(
        client_ip="10.24.1.30",
        server_ip="10.24.1.25",
        client_port=45111,
        server_port=587,
        start_time=BASE_TIMESTAMP + 10.0,
        rng=rng,
    )

    flow.handshake()
    flow.send("server", b"220 mail.example.test ESMTP\r\n", marker="greeting")
    flow.send("client", b"EHLO client.example.test\r\n")
    flow.send("server", b"250-mail.example.test\r\n250 STARTTLS\r\n")
    flow.send("client", b"STARTTLS\r\n", marker="starttls_request")
    flow.send("server", b"220 2.0.0 Ready to start TLS\r\n")

    # Client issues ClientHello
    client_hello = build_client_hello(
        ciphers=[CIPHER_SUITES['TLS_AES_256_GCM_SHA384']],
        sni="mail.example.test",
        version="TLS1.3",
    )
    flow.send("client", client_hello, marker="client_hello")

    # Server issues ServerHello, but capture terminates abruptly before handshake completes
    server_hello = build_server_hello(
        cipher=CIPHER_SUITES['TLS_AES_256_GCM_SHA384'],
        version="TLS1.3",
    )
    flow.send("server", server_hello, auto_ack=False, marker="server_hello")
    # Truncated capture: No ChangeCipherSpec, no encrypted application data, no FIN/RST

    meta = {
        "scenario": "partial_capture",
        "protocol": "SMTP",
        "port": 587,
        "client_ip": flow.client_ip,
        "server_ip": flow.server_ip,
        "expected_findings": [],
        "expected_severity": "None",
        "expected_posture": "Unassessed",
        "description": "SMTP session truncated during TLS handshake prior to handshake completion. Resulting session is unassessed with posture score unavailable.",
        "important_frames": flow.markers,
    }
    return flow.packets, meta


def scenario_multi_protocol_mix(seed: int = 42) -> Tuple[List[Packet], Dict[str, Any]]:
    """Scenario 12: Multi-stream capture containing independent SMTP, IMAP, and POP3 sessions."""
    # Build 4 distinct flows:
    # 1. Hardened SMTP (client 10.24.1.101:45001 -> server 10.24.1.25:587)
    # 2. Cleartext IMAP (client 10.24.1.102:45002 -> server 10.24.1.25:143)
    # 3. Cleartext POP3 (client 10.24.1.103:45003 -> server 10.24.1.25:110)
    # 4. Expired cert SMTP (client 10.24.1.104:45004 -> server 10.24.1.25:587)

    rng1 = random.Random(seed + 1)
    rng2 = random.Random(seed + 2)
    rng3 = random.Random(seed + 3)
    rng4 = random.Random(seed + 4)

    # Stream 1: Hardened SMTP
    f1 = TCPFlow("10.24.1.101", "10.24.1.25", 45001, 587, start_time=BASE_TIMESTAMP, rng=rng1)
    f1.handshake()
    f1.send("server", b"220 mail.example.test ESMTP\r\n")
    f1.send("client", b"EHLO client1.example.test\r\n")
    f1.send("server", b"250-mail.example.test\r\n250 STARTTLS\r\n")
    f1.send("client", b"STARTTLS\r\n")
    f1.send("server", b"220 Ready to start TLS\r\n")
    f1.send("client", build_client_hello([CIPHER_SUITES['TLS_AES_256_GCM_SHA384']], "mail.example.test", "TLS1.3"))
    f1.send("server", build_server_hello(CIPHER_SUITES['TLS_AES_256_GCM_SHA384'], "TLS1.3"))
    f1.send("server", build_encrypted_application_data(b"\x00" * 32))
    f1.close()

    # Stream 2: Cleartext IMAP
    f2 = TCPFlow("10.24.1.102", "10.24.1.25", 45002, 143, start_time=BASE_TIMESTAMP + 0.1, rng=rng2)
    f2.handshake()
    f2.send("server", b"* OK IMAP4rev1 Ready\r\n")
    f2.send("client", b"a1 LOGIN demo-user demo-password\r\n")
    f2.send("server", b"a1 OK LOGIN completed\r\n")
    f2.send("client", b"a2 LOGOUT\r\n")
    f2.send("server", b"* BYE IMAP logging out\r\na2 OK LOGOUT completed\r\n")
    f2.close()

    # Stream 3: Cleartext POP3
    f3 = TCPFlow("10.24.1.103", "10.24.1.25", 45003, 110, start_time=BASE_TIMESTAMP + 0.2, rng=rng3)
    f3.handshake()
    f3.send("server", b"+OK POP3 ready\r\n")
    f3.send("client", b"USER demo-user\r\n")
    f3.send("server", b"+OK password required\r\n")
    f3.send("client", b"PASS demo-password\r\n")
    f3.send("server", b"+OK logged in\r\n")
    f3.send("client", b"QUIT\r\n")
    f3.send("server", b"+OK bye\r\n")
    f3.close()

    # Stream 4: Expired Cert SMTP
    f4 = TCPFlow("10.24.1.104", "10.24.1.25", 45004, 587, start_time=BASE_TIMESTAMP + 0.3, rng=rng4)
    f4.handshake()
    f4.send("server", b"220 mail.example.test ESMTP\r\n")
    f4.send("client", b"EHLO client4.example.test\r\n")
    f4.send("server", b"250-mail.example.test\r\n250 STARTTLS\r\n")
    f4.send("client", b"STARTTLS\r\n")
    f4.send("server", b"220 Ready to start TLS\r\n")
    f4.send("client", build_client_hello([CIPHER_SUITES['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256']], "mail.example.test", "TLS1.2"))
    f4.send("server", build_server_hello(CIPHER_SUITES['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'], "TLS1.2"))
    cert_expired = generate_certificate("mail.example.test", ["mail.example.test"], key_bits=2048, expired=True)
    f4.send("server", build_certificate_message([cert_expired]))
    f4.send("server", build_change_cipher_spec(0x0303))
    f4.send("server", build_encrypted_application_data(b"\x00" * 32))
    f4.close()

    # Interleave all packets chronologically
    all_packets = f1.packets + f2.packets + f3.packets + f4.packets
    all_packets.sort(key=lambda pkt: float(pkt.time))

    meta = {
        "scenario": "multi_protocol_mix",
        "protocol": "SMTP, IMAP, POP3",
        "port": "587, 143, 110",
        "client_ip": "10.24.1.101-104",
        "server_ip": "10.24.1.25",
        "expected_findings": ["AUTH-001", "CERT-001", "CERT-003"],
        "expected_severity": "Critical",
        "expected_posture": "Mixed",
        "description": "Multi-stream PCAPNG containing 4 independent sessions (Hardened SMTP, Cleartext IMAP, Cleartext POP3, Expired Cert SMTP) demonstrating concurrent multi-session analysis.",
        "important_frames": {
            "stream1_hardened_smtp": 1,
            "stream2_cleartext_imap": 2,
            "stream3_cleartext_pop3": 3,
            "stream4_expired_cert_smtp": 4,
        },
    }
    return all_packets, meta


SCENARIO_BUILDERS = {
    "hardened_smtp": scenario_hardened_smtp,
    "hardened_imap": scenario_hardened_imap,
    "hardened_pop3": scenario_hardened_pop3,
    "cleartext_auth_smtp": scenario_cleartext_auth_smtp,
    "cleartext_auth_imap": scenario_cleartext_auth_imap,
    "cleartext_auth_pop3": scenario_cleartext_auth_pop3,
    "starttls_downgrade": scenario_starttls_downgrade,
    "expired_certificate": scenario_expired_certificate,
    "san_mismatch": scenario_san_mismatch,
    "weak_crypto": scenario_weak_crypto,
    "partial_capture": scenario_partial_capture,
    "multi_protocol_mix": scenario_multi_protocol_mix,
}
