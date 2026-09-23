"""Integration test suite for synthetic PCAPNG fixtures and SecureMailScope analyzer."""

import json
import sys
from pathlib import Path
import pytest
from scapy.all import PcapReader, Ether, IP, TCP

ROOT_DIR = Path(__file__).resolve().parents[1]
CAPTURES_DIR = ROOT_DIR / "captures"
MANIFEST_PATH = CAPTURES_DIR / "manifest.json"

# Ensure backend package is in python path
sys.path.insert(0, str(ROOT_DIR / "backend"))
from app.core.pipeline import run_analysis  # noqa: E402
from app.core.integrity import validate  # noqa: E402


def test_manifest_exists_and_valid():
    """Verify that manifest.json exists, contains 12 scenarios, and has required fields."""
    assert MANIFEST_PATH.exists(), "captures/manifest.json does not exist"
    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert len(data) == 12, f"Expected 12 scenarios in manifest, found {len(data)}"

    scenarios = {item["scenario"] for item in data}
    expected_scenarios = {
        "hardened_smtp",
        "hardened_imap",
        "hardened_pop3",
        "cleartext_auth_smtp",
        "cleartext_auth_imap",
        "cleartext_auth_pop3",
        "starttls_downgrade",
        "expired_certificate",
        "san_mismatch",
        "weak_crypto",
        "partial_capture",
        "multi_protocol_mix",
    }
    assert scenarios == expected_scenarios

    for entry in data:
        assert "pcap_path" in entry
        assert "packet_count" in entry
        assert entry["packet_count"] > 0
        assert "sha256" in entry
        assert len(entry["sha256"]) == 64
        assert "important_frames" in entry
        assert isinstance(entry["important_frames"], dict)
        pcap_file = CAPTURES_DIR / f"{entry['scenario']}.pcapng"
        assert pcap_file.exists(), f"File {pcap_file} referenced in manifest does not exist"


@pytest.mark.parametrize("scenario_name", [
    "hardened_smtp",
    "hardened_imap",
    "hardened_pop3",
    "cleartext_auth_smtp",
    "cleartext_auth_imap",
    "cleartext_auth_pop3",
    "starttls_downgrade",
    "expired_certificate",
    "san_mismatch",
    "weak_crypto",
    "partial_capture",
    "multi_protocol_mix",
])
def test_pcapng_integrity_and_layers(scenario_name):
    """Confirm file is valid PCAPNG and packets contain Ether/IP/TCP layers."""
    pcap_file = CAPTURES_DIR / f"{scenario_name}.pcapng"
    meta = validate(pcap_file)
    assert meta["format"] == "pcapng"
    assert meta["size_bytes"] > 0

    with PcapReader(str(pcap_file)) as reader:
        packets = list(reader)
        assert len(packets) > 0
        for pkt in packets:
            assert Ether in pkt
            assert IP in pkt
            assert TCP in pkt


def test_hardened_scenarios():
    """Verify that hardened scenarios have no findings and score >= 90."""
    for name in ["hardened_smtp", "hardened_imap", "hardened_pop3"]:
        report = run_analysis(CAPTURES_DIR / f"{name}.pcapng")
        assert len(report.sessions) == 1
        assert report.sessions[0].complete
        findings = [f.rule_id for f in report.sessions[0].findings]
        assert findings == []
        assert report.overall_posture_score >= 90


def test_cleartext_auth_scenarios():
    """Verify cleartext auth scenarios trigger AUTH-001 (Critical)."""
    for name in ["cleartext_auth_smtp", "cleartext_auth_imap", "cleartext_auth_pop3"]:
        report = run_analysis(CAPTURES_DIR / f"{name}.pcapng")
        assert len(report.sessions) == 1
        findings = [f.rule_id for f in report.sessions[0].findings]
        assert "AUTH-001" in findings


def test_starttls_downgrade():
    """Verify STARTTLS downgrade triggers STARTTLS-001 and AUTH-001."""
    report = run_analysis(CAPTURES_DIR / "starttls_downgrade.pcapng")
    findings = {f.rule_id for f in report.sessions[0].findings}
    assert "STARTTLS-001" in findings
    assert "AUTH-001" in findings


def test_certificate_scenarios():
    """Verify expired certificate and SAN mismatch findings."""
    report_expired = run_analysis(CAPTURES_DIR / "expired_certificate.pcapng")
    findings_expired = {f.rule_id for f in report_expired.sessions[0].findings}
    assert "CERT-001" in findings_expired

    report_san = run_analysis(CAPTURES_DIR / "san_mismatch.pcapng")
    findings_san = {f.rule_id for f in report_san.sessions[0].findings}
    assert "CERT-002" in findings_san


def test_weak_crypto():
    """Verify weak crypto triggers TLS-002, CIPHER-001/002, and CERT-004."""
    report = run_analysis(CAPTURES_DIR / "weak_crypto.pcapng")
    findings = {f.rule_id for f in report.sessions[0].findings}
    assert "TLS-002" in findings
    assert "CIPHER-001" in findings
    assert "CIPHER-002" in findings
    assert "CERT-004" in findings


def test_partial_capture_unassessed():
    """Verify truncated capture is marked incomplete and unassessed."""
    report = run_analysis(CAPTURES_DIR / "partial_capture.pcapng")
    assert not report.sessions[0].complete
    assert report.overall_posture_score is None


def test_multi_protocol_mix():
    """Verify multi-stream PCAP contains independent SMTP, IMAP, and POP3 sessions."""
    report = run_analysis(CAPTURES_DIR / "multi_protocol_mix.pcapng")
    assert len(report.sessions) == 4
    protocols = {s.protocol for s in report.sessions}
    assert protocols == {"SMTP", "IMAP", "POP3"}
