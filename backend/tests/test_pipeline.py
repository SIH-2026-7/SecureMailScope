import json
import pytest
from scapy.all import wrpcap, PcapNgWriter
from generate_traffic import generate
from app.core.pipeline import run_analysis


@pytest.mark.parametrize('scenario,expected', [
    ('hardened', []), ('cleartext_auth', ['AUTH-001']),
    ('starttls_downgrade', ['STARTTLS-001', 'AUTH-001']),
    ('expired_cert', ['CERT-001']), ('san_mismatch', ['CERT-002']),
    ('weak_key', ['CERT-004']), ('tls10_weak', ['TLS-002', 'CIPHER-001', 'CIPHER-002']),
])
def test_capture_analysis(tmp_path, scenario, expected):
    path = tmp_path / 'capture.pcap'
    wrpcap(str(path), generate(scenario))
    report = run_analysis(path)
    ids = {f.rule_id for s in report.sessions for f in s.findings}
    assert set(expected) <= ids
    assert report.summary['assessed_sessions'] == len(report.sessions)
    assert all(f.evidence.frame_no > 0 for s in report.sessions for f in s.findings)
    output = report.model_dump_json()
    assert 'demo-password' not in output and 'ZGVtby11c2Vy' not in output
    if scenario == 'hardened':
        assert report.overall_posture_score >= 90
        assert report.sessions[0].tls['version'] == 'TLS1.3'
        assert report.sessions[0].certificate is None
    if scenario == 'cleartext_auth':
        assert {s.protocol for s in report.sessions} == {'SMTP', 'IMAP', 'POP3'}


def test_pcapng(tmp_path):
    path = tmp_path / 'capture.pcapng'
    with PcapNgWriter(str(path)) as writer:
        writer.write(generate('hardened'))
    assert run_analysis(path).capture_meta['format'] == 'pcapng'


def test_partial_evidence_unassessed(tmp_path):
    path = tmp_path / 'partial.pcap'
    wrpcap(str(path), generate('hardened')[4:])
    report = run_analysis(path)
    assert report.overall_posture_score is None
    assert not report.sessions[0].complete


def test_reordered_retransmitted_capture(tmp_path):
    path = tmp_path / 'reordered.pcap'
    wrpcap(str(path), generate('expired_cert', disorder=True))
    report = run_analysis(path)
    assert report.sessions[0].certificate['expired']
    assert any('overlap' in w for w in report.sessions[0].warnings)


def test_nonstandard_tls_with_split_header(tmp_path):
    from scapy.all import Ether, IP, TCP, Raw
    from generate_traffic import hello_pair
    client, server = hello_pair('TLS1.3', 0x1301)
    packets = [Ether()/IP(src='192.0.2.1', dst='192.0.2.2')/TCP(sport=44444, dport=8443, seq=100, flags='S')]
    for seq, body in [(101, client[:3]), (104, client[3:])]:
        packets.append(Ether()/IP(src='192.0.2.1', dst='192.0.2.2')/TCP(sport=44444, dport=8443, seq=seq, flags='PA')/Raw(body))
    packets.append(Ether()/IP(src='192.0.2.2', dst='192.0.2.1')/TCP(sport=8443, dport=44444, seq=200, flags='PA')/Raw(server))
    path = tmp_path / 'nonstandard.pcap'
    wrpcap(str(path), packets)
    result = run_analysis(path)
    assert len(result.sessions) == 1
    assert result.sessions[0].tls['version'] == 'TLS1.3'
    assert result.sessions[0].session_score is None  # no subsequent encrypted record
