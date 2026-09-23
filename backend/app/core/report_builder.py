import html
import io
import json
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer


def html_report(report):
    esc = lambda value: html.escape(str(value))
    content = [f'<h1>SecureMailScope</h1><p>{esc(report["capture_meta"]["filename"])}</p>',
               f'<h2>Posture: {esc(report["overall_posture_score"])}/100</h2>',
               f'<p>SHA-256: {esc(report["capture_meta"]["sha256"])}</p>']
    for s in report['sessions']:
        content.append(f'<h2>{esc(s["session_id"])}</h2><p>{esc(s["client_ip"])} → {esc(s["server_ip"])} · Score {esc(s["session_score"])}</p>')
        content.append(f'<p>ML: {esc(s["ml_risk_class"])} · {esc(s["ml_status"])}. Structured cryptographic features only.</p>')
        for f in s['findings']:
            content.append(f'<h3>{esc(f["rule_id"])} · {esc(f["severity"])} · {esc(f["title"])}</h3><p>{esc(f["description"])}</p><p>Frame {f["evidence"]["frame_no"]} · Timestamp {f["evidence"]["timestamp"]}</p><p>{esc(f["remediation"])}</p>')
        content.append('<pre>' + esc(json.dumps({'tls': s['tls'], 'certificate': s['certificate'], 'timeline': s['commands'], 'score_breakdown': s['score_breakdown'], 'warnings': s['warnings']}, indent=2)) + '</pre>')
    content.append('<h2>Assessment limits</h2>' + ''.join(f'<p>{esc(item)}</p>' for item in report['limitations']))
    return '<!doctype html><html lang="en"><meta charset="utf-8"><title>SecureMailScope report</title><style>body{font:15px system-ui;max-width:1000px;margin:40px auto;padding:20px;color:#172331}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:11px}h2{border-top:1px solid #bbb;padding-top:18px}</style>' + ''.join(content) + '</html>'


def pdf_report(report):
    stream, story, styles = io.BytesIO(), [], getSampleStyleSheet()
    def add(text, style='BodyText'):
        story.append(Paragraph(html.escape(str(text)), styles[style]))
        story.append(Spacer(1, 7))
    add('SecureMailScope forensic report', 'Title')
    add(report['capture_meta']['filename'])
    add('SHA-256: ' + report['capture_meta']['sha256'])
    add(f'Overall posture: {report["overall_posture_score"]}/100', 'Heading2')
    for s in report['sessions']:
        add(s['session_id'], 'Heading2')
        add(f'{s["client_ip"]} → {s["server_ip"]}:{s["server_port"]} | Score: {s["session_score"]}')
        add(f'ML risk: {s["ml_risk_class"]}; anomaly: {s["ml_is_anomaly"]}. {s["ml_status"]}; normalized features only.')
        for f in s['findings']:
            add(f'{f["rule_id"]} / {f["severity"]}: {f["title"]}', 'Heading3')
            add(f['description'])
            add(f'Frame {f["evidence"]["frame_no"]}, timestamp {f["evidence"]["timestamp"]}')
            add(f['remediation'])
        add('Score deductions: ' + json.dumps(s['score_breakdown']))
        if s['certificate']:
            for key in ('subject', 'issuer', 'not_after', 'hostname_match', 'key_bits', 'trust_status', 'fingerprint_sha256'):
                add(f'{key}: {s["certificate"][key]}')
        for command in s['commands']:
            add(f'Frame {command["frame_no"]} [{command["direction"]}] {command["line"]}')
        for warning in s['warnings']:
            add(warning)
    add('Assessment limits', 'Heading2')
    for limit in report['limitations']:
        add(limit)
    SimpleDocTemplate(stream, title='SecureMailScope assessment').build(story)
    return stream.getvalue()
