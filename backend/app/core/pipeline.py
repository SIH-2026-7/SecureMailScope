from pathlib import Path
from .integrity import validate
from .pcap_extractor import extract
from .stream_reassembly import reassemble
from .protocol_parser import parse
from .cert_validator import validate_certificates
from .rule_engine import evaluate
from . import ml_scoring, posture_score
from ..models.schemas import Report


def run_analysis(pcap_path, job_id='', filename=None):
    path = Path(pcap_path)
    meta = validate(path)
    packets, capture = extract(path)
    sessions = []
    for stream in reassemble(packets):
        session, ders, ev = parse(stream)
        try:
            session.certificate = validate_certificates(ders, ev, session.tls.get('sni'), ev['timestamp'] if ev else session.evidence['timestamp'])
        except ValueError:
            session.warnings.append('Certificate could not be decoded; validation unavailable.')
        session.findings = evaluate(session)
        ml_scoring.score(session)
        posture_score.score(session)
        sessions.append(session)
    findings = [f for s in sessions for f in s.findings]
    return Report(job_id=job_id, capture_meta={**meta, **capture, 'filename': filename or path.name},
                  overall_posture_score=posture_score.overall(sessions), sessions=sessions,
                  summary={'total_sessions': len(sessions), 'assessed_sessions': sum(s.complete for s in sessions),
                           **{f'{level.lower()}_findings': sum(f.severity == level for f in findings) for level in ('Critical', 'High', 'Medium', 'Low', 'Info')}},
                  ml=ml_scoring.metadata(), limitations=[
                      'Scores describe observed evidence, not proof of endpoint security. Missing evidence is not a passing certificate check.',
                      'TLS 1.3 certificates and encrypted authentication are not visible without session secrets. No decryption is attempted.',
                      'Revocation is unknown offline. Chain validation uses bundled certifi roots and capture time; private roots may be untrusted.',
                      'ML is a synthetic-data demonstration, not a validated production detector. Only normalized cryptographic features are used.',
                      'Partial streams are excluded from overall posture. Conflicting TCP overlaps retain first observed bytes and are flagged.',
                      'Scapy extracts TCP; IP fragment reassembly, SSLv2 decoding, QUIC, and arbitrary application protocols are not supported.',
                  ])
