from .rule_engine import SEVERITY

ML_PENALTY = {'Critical': 20, 'High': 10, 'Medium': 5, 'Low': 0}


def score(s):
    s.score_breakdown = [dict(source='rule', id=f.rule_id, severity=f.severity, deduction=SEVERITY[f.severity]) for f in s.findings]
    if s.ml_risk_class:
        s.score_breakdown.append(dict(source='ml', id=s.ml_risk_class, deduction=ML_PENALTY[s.ml_risk_class]))
    s.session_score = max(0, 100 - sum(item['deduction'] for item in s.score_breakdown)) if s.complete else None


def overall(sessions):
    values = [s.session_score for s in sessions if s.session_score is not None]
    return round(sum(values) / len(values), 1) if values else None
