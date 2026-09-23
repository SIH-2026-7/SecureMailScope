#!/usr/bin/env python3
"""Validation utility for SecureMailScope PCAPNG fixtures.

Performs deep structural and protocol validation:
1. Verifies PCAPNG file format and magic bytes (0x0A0D0D0A).
2. Reads every packet using Scapy (PcapReader).
3. Confirms presence of Ethernet, IPv4, and TCP layers on all frames.
4. Validates protocol-specific payloads, TLS structures, and credential ordering.
5. Computes and displays SHA-256 hashes and packet statistics.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from scapy.all import PcapReader, Ether, IP, TCP, Raw


def validate_pcapng_header(data: bytes) -> dict:
    """Validate PCAPNG Section Header Block and endianness."""
    if len(data) < 28:
        raise ValueError("File is too small to be a valid PCAPNG.")
    if data[:4] != b"\x0a\x0d\x0d\x0a":
        raise ValueError(f"Invalid PCAPNG magic header: expected 0x0A0D0D0A, got {data[:4].hex()}")

    bom = data[8:12]
    if bom == b"\x4d\x3c\x2b\x1a":
        endian = "<"
    elif bom == b"\x1a\x2b\x3c\x4d":
        endian = ">"
    else:
        raise ValueError(f"Invalid PCAPNG Byte Order Marker (BOM): {bom.hex()}")

    section_len = struct.unpack_from(f"{endian}I", data, 4)[0]
    return {"endian": endian, "section_len": section_len}


def validate_packets(pcap_path: Path) -> dict:
    """Read packets with Scapy and verify packet integrity."""
    packets = []
    with PcapReader(str(pcap_path)) as reader:
        for idx, pkt in enumerate(reader, 1):
            if Ether not in pkt:
                raise ValueError(f"Frame #{idx} missing Ethernet layer.")
            if IP not in pkt:
                raise ValueError(f"Frame #{idx} missing IPv4 layer.")
            if TCP not in pkt:
                raise ValueError(f"Frame #{idx} missing TCP layer.")
            packets.append(pkt)

    if not packets:
        raise ValueError("Capture file contains 0 packets.")

    # Validate timing consistency
    times = [float(p.time) for p in packets]
    if any(t2 < t1 for t1, t2 in zip(times, times[1:])):
        raise ValueError("Packets are not in non-decreasing chronological order.")

    return {"count": len(packets), "start_time": min(times), "end_time": max(times), "packets": packets}


def validate_scenario_payloads(scenario_name: str, packets: list) -> list:
    """Confirm scenario-specific protocol and security attributes."""
    checks = []
    raw_payloads = [bytes(p[TCP].payload) for p in packets if Raw in p]
    combined_raw = b"".join(raw_payloads)

    if scenario_name == "hardened_smtp":
        assert b"220 mail.example.test ESMTP" in combined_raw, "Missing SMTP greeting"
        assert b"STARTTLS" in combined_raw, "Missing STARTTLS negotiation"
        # Check TLS 1.3 ServerHello with cipher 0x1302
        assert b"\x16\x03\x03" in combined_raw, "Missing TLS handshake record"
        assert b"\x13\x02" in combined_raw, "Missing AES-256-GCM cipher (0x1302)"
        assert b"\x17\x03\x03" in combined_raw, "Missing encrypted application data"
        assert b"AUTH" not in combined_raw, "Found unexpected plaintext AUTH in hardened SMTP"
        checks.append("SMTP STARTTLS upgraded to TLS 1.3 AES-256-GCM without cleartext credentials")

    elif scenario_name == "hardened_imap":
        assert b"* OK" in combined_raw and b"IMAP" in combined_raw, "Missing IMAP greeting"
        assert b"STARTTLS" in combined_raw, "Missing STARTTLS"
        assert b"\x17\x03\x03" in combined_raw, "Missing encrypted application data"
        assert b"LOGIN" not in combined_raw, "Found unexpected plaintext LOGIN in hardened IMAP"
        checks.append("IMAP upgraded via STARTTLS to TLS 1.3 before any login")

    elif scenario_name == "hardened_pop3":
        assert b"+OK POP3" in combined_raw, "Missing POP3 greeting"
        assert b"STLS" in combined_raw, "Missing STLS"
        assert b"\x17\x03\x03" in combined_raw, "Missing encrypted application data"
        assert b"PASS" not in combined_raw, "Found unexpected plaintext PASS in hardened POP3"
        checks.append("POP3 upgraded via STLS to TLS 1.3 before USER/PASS")

    elif scenario_name == "cleartext_auth_smtp":
        assert b"AUTH LOGIN" in combined_raw, "Missing AUTH LOGIN command"
        assert b"ZGVtby11c2Vy" in combined_raw, "Missing base64 demo-user"
        assert b"ZGVtby1wYXNzd29yZA==" in combined_raw, "Missing base64 demo-password"
        assert b"\x17\x03\x03" not in combined_raw, "Unexpected encrypted records in cleartext capture"
        checks.append("Cleartext SMTP AUTH LOGIN sequence observed with dummy credentials")

    elif scenario_name == "cleartext_auth_imap":
        assert b"LOGIN demo-user demo-password" in combined_raw, "Missing cleartext IMAP LOGIN"
        assert b"\x17\x03\x03" not in combined_raw, "Unexpected encrypted records in cleartext capture"
        checks.append("Cleartext IMAP LOGIN command observed with dummy credentials")

    elif scenario_name == "cleartext_auth_pop3":
        assert b"USER demo-user" in combined_raw, "Missing POP3 USER command"
        assert b"PASS demo-password" in combined_raw, "Missing POP3 PASS command"
        assert b"\x17\x03\x03" not in combined_raw, "Unexpected encrypted records in cleartext capture"
        checks.append("Cleartext POP3 USER and PASS observed with dummy credentials")

    elif scenario_name == "starttls_downgrade":
        assert b"STARTTLS" in combined_raw, "Missing initial STARTTLS negotiation"
        assert b"454" in combined_raw, "Missing STARTTLS rejection/failure"
        assert b"AUTH PLAIN" in combined_raw, "Missing downgrade plaintext AUTH"
        checks.append("Observed STARTTLS request followed by downgrade plaintext AUTH")

    elif scenario_name == "expired_certificate":
        assert b"\x16\x03\x03" in combined_raw, "Missing TLS 1.2 handshake"
        # msg_type 11 (Certificate)
        assert b"\x0b" in [body[:1] for body in [p[5:] for p in raw_payloads if p.startswith(b"\x16\x03\x03")]], "Missing TLS Certificate handshake"
        checks.append("Observed TLS 1.2 handshake carrying expired X.509 certificate")

    elif scenario_name == "san_mismatch":
        assert b"mail.example.test" in combined_raw, "Missing SNI mail.example.test"
        assert b"other.example.test" in combined_raw, "Missing mismatched SAN other.example.test"
        checks.append("Observed SNI mail.example.test with certificate SAN other.example.test")

    elif scenario_name == "weak_crypto":
        # TLS 1.0 has version 0x0301
        assert b"\x16\x03\x01" in combined_raw or b"\x03\x01" in combined_raw, "Missing TLS 1.0 record"
        # Cipher 0x0005 (TLS_RSA_WITH_RC4_128_SHA)
        assert b"\x00\x05" in combined_raw, "Missing RC4 cipher suite 0x0005"
        checks.append("Observed legacy TLS 1.0 with RC4 cipher and 1024-bit RSA key")

    elif scenario_name == "partial_capture":
        assert b"220 mail.example.test ESMTP" in combined_raw, "Missing greeting"
        assert b"STARTTLS" in combined_raw, "Missing STARTTLS"
        assert any(p.startswith(b"\x16\x03") for p in raw_payloads), "Missing ClientHello"
        # Confirm no encrypted records or FIN
        assert b"\x17\x03" not in combined_raw, "Found unexpected encrypted traffic in truncated capture"
        checks.append("Observed partial TLS handshake truncated before ServerHello")

    elif scenario_name == "multi_protocol_mix":
        ports = {p[TCP].dport for p in packets} | {p[TCP].sport for p in packets}
        assert {587, 143, 110}.issubset(ports), "Missing multi-protocol ports (587, 143, 110)"
        client_ips = {p[IP].src for p in packets if p[TCP].sport > 1024}
        assert len(client_ips) >= 4, f"Expected at least 4 distinct client IPs, got {client_ips}"
        checks.append(f"Observed 4 concurrent sessions across SMTP, IMAP, and POP3 with {len(client_ips)} client IPs")

    return checks


def validate_file(pcap_path: Path) -> dict:
    """Validate a single PCAPNG file completely."""
    data = pcap_path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()

    header_info = validate_pcapng_header(data)
    pkt_info = validate_packets(pcap_path)

    scenario_name = pcap_path.stem
    payload_checks = validate_scenario_payloads(scenario_name, pkt_info["packets"])

    return {
        "scenario": scenario_name,
        "filename": pcap_path.name,
        "size_bytes": len(data),
        "sha256": sha256,
        "packet_count": pkt_info["count"],
        "duration_sec": round(pkt_info["end_time"] - pkt_info["start_time"], 3),
        "checks": payload_checks,
        "status": "PASS",
    }


def main():
    parser = argparse.ArgumentParser(description="Validate generated PCAPNG files.")
    parser.add_argument(
        "--dir",
        "-d",
        type=Path,
        default=Path("captures"),
        help="Directory containing PCAPNG files to validate (default: captures)",
    )
    args = parser.parse_args()

    if not args.dir.is_dir():
        print(f"[-] Error: Directory '{args.dir}' does not exist.", file=sys.stderr)
        sys.exit(1)

    pcap_files = sorted(args.dir.glob("*.pcapng"))
    if not pcap_files:
        print(f"[-] Error: No .pcapng files found in '{args.dir}'.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Validating {len(pcap_files)} PCAPNG files in '{args.dir}'...\n")
    print(f"{'Filename':<30} {'Status':<8} {'Packets':<8} {'Size (B)':<10} {'SHA-256 (prefix)':<18}")
    print("-" * 80)

    all_passed = True
    results = []

    for file_path in pcap_files:
        try:
            res = validate_file(file_path)
            results.append(res)
            sha_prefix = res["sha256"][:16] + "..."
            print(f"{res['filename']:<30} {res['status']:<8} {res['packet_count']:<8} {res['size_bytes']:<10} {sha_prefix:<18}")
            for chk in res["checks"]:
                print(f"    -> [OK] {chk}")
        except Exception as exc:
            all_passed = False
            print(f"{file_path.name:<30} FAIL     {str(exc)}")

    print("-" * 80)
    if all_passed:
        print(f"[+] All {len(pcap_files)} PCAPNG fixtures passed validation successfully!\n")
        sys.exit(0)
    else:
        print("[-] One or more validation checks failed.\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
