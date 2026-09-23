from app.models.schemas import SessionRecord
from app.core.rule_engine import evaluate
from app.core.posture_score import score


def test_downgrade_and_score_breakdown():
    s = SessionRecord(session_id='smtp-1', protocol='SMTP', client_ip='a', server_ip='b', server_port=25,
                      evidence={'frame_no': 1, 'timestamp': 100, 'stream_id': 'smtp-1'}, complete=True,
                      tls={'version': 'TLS1.0', 'offered_versions': ['TLS1.2'], 'cipher_suite': 'TLS_RSA_WITH_RC4_128_SHA'},
                      ml_risk_class='Critical')
    s.findings = evaluate(s)
    assert {f.rule_id for f in s.findings} == {'TLS-002', 'TLS-003', 'CIPHER-001', 'CIPHER-002'}
    score(s)
    assert s.session_score == 13
    assert s.score_breakdown[-1]['source'] == 'ml'


def test_no_false_cleartext_claim_on_encrypted_session():
    s = SessionRecord(session_id='x', protocol='IMAP', client_ip='a', server_ip='b', server_port=993,
                      evidence={'frame_no': 1, 'timestamp': 100, 'stream_id': 'x'}, tls={'version': 'TLS1.3'})
    assert not evaluate(s)
