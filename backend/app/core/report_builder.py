import html
import io
import json
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak


def display(value):
    return 'Unknown / not observed' if value is None else str(value)


def report_sections(report):
    """A common document outline keeps the two downloadable formats in sync."""
    sessions = report['sessions']
    findings = [(s, f) for s in sessions for f in s['findings']]
    rank = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
    findings.sort(key=lambda item: rank.get(item[1]['severity'], 5))
    sections = []
    overview = [('h2', 'Capture identity'), *[('p', f'{key.replace("_", " ").title()}: {display(value)}') for key, value in report['capture_meta'].items()],
                ('h2', 'Assessment summary'), ('p', f'Overall posture: {display(report["overall_posture_score"])}/100'),
                ('p', f'Sessions: {len(sessions)} | Findings: {len(findings)}'),
                ('p', 'Report guide: 01 Overview; 02 Findings and remediation; 03 Session evidence; 04 Assessment limits. Each section starts on a new page. Long sections continue onto additional pages.')]
    sections.append(('overview', '01 / Assessment overview', overview))
    if not findings:
        sections.append(('findings', '02 / Findings and remediation', [('p', 'No configured rules triggered. This does not establish that the capture or endpoints are secure.')]))
    for index, (session, finding) in enumerate(findings, 1):
        evidence = finding['evidence']
        sections.append((f'finding-{index}', f'02 / Finding {index} of {len(findings)}', [
            ('h2', f'{finding["severity"]} | {finding["rule_id"]} | {finding["title"]}'),
            ('p', f'Session: {session["session_id"]} | {session["client_ip"]} -> {session["server_ip"]}:{session["server_port"]}'),
            ('h2', 'Observation'), ('p', finding['description']),
            ('h2', 'Supporting evidence'), ('p', f'Frame: {evidence["frame_no"]} | Timestamp: {evidence["timestamp"]} | Stream: {evidence.get("stream_id", session["session_id"])}'),
            ('h2', 'Recommended remediation'), ('p', finding['remediation'])]))
    if not sessions:
        sections.append(('sessions', '03 / Session evidence', [('p', 'No sessions were identified in this capture.')]))
    for index, session in enumerate(sessions, 1):
        blocks = [('h2', session['session_id']), ('p', f'{session["client_ip"]} -> {session["server_ip"]}:{session["server_port"]} | {session["protocol"]} | Score: {display(session["session_score"])}'),
                  ('h2', 'Machine-learning assessment'), ('p', f'Risk: {display(session["ml_risk_class"])} | Anomaly: {display(session["ml_is_anomaly"])} | {session["ml_status"]}. Structured cryptographic features only.')]
        for title, value in [('TLS observations', session['tls']), ('Certificate observations', session['certificate']), ('Score deductions', session['score_breakdown'])]:
            blocks.extend([('h2', title), ('code', json.dumps(value, indent=2) if value else 'None recorded.')])
        blocks.append(('h2', 'Command timeline'))
        blocks.extend(('p', f'Frame {c["frame_no"]} [{c["direction"]}] {c["line"]}') for c in session['commands'])
        if not session['commands']:
            blocks.append(('p', 'No commands recorded.'))
        blocks.append(('h2', 'Session warnings'))
        blocks.extend(('p', warning) for warning in session['warnings'] or ['No session warnings recorded.'])
        sections.append((f'session-{index}', f'03 / Session evidence {index} of {len(sessions)}', blocks))
    sections.append(('limitations', '04 / Assessment limits', [('p', item) for item in report['limitations']] or [('p', 'No assessment limits supplied.')]))
    return sections


def html_report(report):
    sections = report_sections(report)
    esc = lambda value: html.escape(str(value))
    navigation = ''.join(f'<a href="#{key}">{esc(title)}</a>' for key, title, _ in sections)
    pages = []
    for key, title, blocks in sections:
        content = ''.join(f'<{("pre" if kind == "code" else kind)}>{esc(value)}</{("pre" if kind == "code" else kind)}>' for kind, value in blocks)
        pages.append(f'<section class="report-page" id="{key}"><header>SecureMailScope / Forensic assessment</header><h1>{esc(title)}</h1>{content}<footer>SecureMailScope | {esc(title)}</footer></section>')
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>SecureMailScope report</title><style>
    *{box-sizing:border-box}body{margin:0;background:#e9edf0;color:#172331;font:14px/1.6 Arial,sans-serif}nav{max-width:210mm;margin:24px auto;padding:20px}nav a{display:block;color:#126347}button{padding:10px 16px;background:#126347;color:white;border:0;cursor:pointer}.report-page{background:white;max-width:210mm;min-height:297mm;margin:24px auto;padding:20mm;box-shadow:0 2px 12px #17233118;overflow-wrap:anywhere}header,footer{font-size:11px;color:#596773}header{border-bottom:2px solid #126347;padding-bottom:12px}footer{border-top:1px solid #ccd6dc;margin-top:32px;padding-top:12px}h1{font-size:27px;line-height:1.25;color:#126347}h2{font-size:17px;margin-top:26px;break-after:avoid}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:11px/1.6 monospace;background:#f3f6f7;padding:12px}p{orphans:3;widows:3}@page{size:A4;margin:18mm}@media print{body{background:white}nav{display:none}.report-page{margin:0;padding:0;min-height:0;max-width:none;box-shadow:none;break-before:page}.report-page:first-of-type{break-before:auto}}@media screen and (max-width:800px){.report-page{margin:16px;min-height:0;padding:24px}}
    </style></head><body><nav aria-label="Report contents"><button onclick="window.print()">Print / Save as PDF</button><h2>Report contents</h2>''' + navigation + '</nav>' + ''.join(pages) + '</body></html>'


def pdf_report(report):
    stream, story, styles = io.BytesIO(), [], getSampleStyleSheet()
    styles['Title'].textColor = colors.HexColor('#126347')
    styles['Title'].alignment = TA_LEFT
    styles['BodyText'].leading = 15
    styles.add(ParagraphStyle('Evidence', fontName='Courier', fontSize=8, leading=12, spaceAfter=6, splitLongWords=True))
    for index, (_, title, blocks) in enumerate(report_sections(report)):
        if index:
            story.append(PageBreak())
        story.append(Paragraph(html.escape(title), styles['Title']))
        for kind, value in blocks:
            style = 'Heading2' if kind == 'h2' else 'Evidence' if kind == 'code' else 'BodyText'
            # Separate evidence lines allow arbitrarily long appendices to flow safely.
            for line in str(value).splitlines() or ['']:
                story.append(Paragraph(html.escape(line), styles[style]))
            story.append(Spacer(1, 8))

    def page_frame(canvas, doc):
        canvas.saveState()
        width, height = A4
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(colors.HexColor('#596773'))
        canvas.drawString(48, height - 32, 'SecureMailScope / Forensic assessment')
        canvas.drawString(48, 30, 'Capture assessment | Evidence and remediation')
        canvas.drawRightString(width - 48, 30, f'Page {doc.page}')
        canvas.restoreState()

    SimpleDocTemplate(stream, pagesize=A4, rightMargin=48, leftMargin=48, topMargin=56, bottomMargin=52,
                      title='SecureMailScope assessment').build(story, onFirstPage=page_frame, onLaterPages=page_frame)
    return stream.getvalue()
