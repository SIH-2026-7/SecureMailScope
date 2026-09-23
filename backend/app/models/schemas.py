from typing import Literal
from pydantic import BaseModel, Field


class Evidence(BaseModel):
    frame_no: int
    stream_id: str
    timestamp: float


class Finding(BaseModel):
    rule_id: str
    severity: Literal['Critical', 'High', 'Medium', 'Low', 'Info']
    title: str
    description: str
    evidence: Evidence
    remediation: str


class SessionRecord(BaseModel):
    session_id: str
    protocol: str
    client_ip: str
    server_ip: str
    server_port: int
    evidence: dict
    starttls_used: bool = False
    starttls_advertised: bool = False
    starttls_requested: bool = False
    plaintext_after_starttls: bool = False
    auth_before_tls: bool = False
    tls: dict = Field(default_factory=dict)
    certificate: dict | None = None
    commands: list[dict] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    complete: bool = False
    ml_status: str = 'unavailable'
    ml_risk_class: str | None = None
    ml_anomaly_score: float | None = None
    ml_is_anomaly: bool | None = None
    session_score: int | None = None
    score_breakdown: list[dict] = Field(default_factory=list)


class Report(BaseModel):
    job_id: str
    capture_meta: dict
    overall_posture_score: float | None
    sessions: list[SessionRecord]
    summary: dict
    limitations: list[str]
    ml: dict
