from generate_traffic import certificate, CAPTURE_TIME
from app.core.cert_validator import validate_certificates, matches


def test_forensic_time_and_hostname():
    der = certificate('mail.example.test')
    ev = dict(frame_no=12, timestamp=CAPTURE_TIME.timestamp(), stream_id='smtp-1')
    c = validate_certificates([der], ev, 'wrong.example.test', CAPTURE_TIME.timestamp())
    assert not c['expired'] and not c['hostname_match']
    assert c['self_signed'] and c['trust_status'] == 'validation_failed'
    assert c['revocation_status'] == 'unknown_offline'
    assert validate_certificates([der], ev, None, CAPTURE_TIME.timestamp() + 400 * 86400)['expired']


def test_wildcards_only_match_one_label():
    assert matches('*.example.test', 'mail.example.test')
    assert not matches('*.example.test', 'x.mail.example.test')
    assert not matches('*.example.test', 'example.test')
