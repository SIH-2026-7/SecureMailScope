import pytest
from scapy.all import wrpcap
from generate_traffic import generate
from app.core.integrity import validate


def test_truncated_packet_is_rejected(tmp_path):
    path = tmp_path / 'truncated.pcap'
    wrpcap(str(path), generate('hardened'))
    path.write_bytes(path.read_bytes()[:-8])
    with pytest.raises(ValueError, match='Truncated'):
        validate(path)


def test_packet_credentials_never_escape_multiline_responses(tmp_path):
    from scapy.all import Raw, TCP, IP
    from app.core.pipeline import run_analysis
    packets = generate('cleartext_auth')
    # First server reply is followed by further data: preserve its length and seq accounting.
    raw = packets[3][Raw].load
    packets[3][Raw].load = b'220-supersecret' + b' ' * (len(raw) - 17) + b'\r\n'
    path = tmp_path / 'redaction.pcap'
    wrpcap(str(path), packets)
    assert 'supersecret' not in run_analysis(path).model_dump_json()
