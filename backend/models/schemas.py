from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

# --- Email Link Schemas ---
class EmailLinkBase(BaseModel):
    url: str
    domain: Optional[str] = None
    is_shortened: bool = False
    is_suspicious_redirect: bool = False

class EmailLinkRead(EmailLinkBase):
    id: int
    incident_id: int
    vt_malicious_count: int
    vt_harmless_count: int
    vt_suspicious_count: int
    vt_undetected_count: int
    vt_scan_date: Optional[datetime] = None
    vt_reputation_score: int
    vt_verdict: str

    class Config:
        from_attributes = True

# --- Email Attachment Schemas ---
class EmailAttachmentBase(BaseModel):
    filename: str
    content_type: Optional[str] = None
    file_size: Optional[int] = None
    file_hash_sha256: Optional[str] = None
    is_suspicious: bool = False
    risk_reason: Optional[str] = None

class EmailAttachmentRead(EmailAttachmentBase):
    id: int
    incident_id: int

    class Config:
        from_attributes = True

# --- Case History Schemas ---
class CaseHistoryRead(BaseModel):
    id: int
    incident_id: int
    timestamp: datetime
    action: str
    details: Optional[str] = None
    analyst: Optional[str] = None

    class Config:
        from_attributes = True

# --- Email Incident Schemas ---
class EmailIncidentBase(BaseModel):
    sender: str
    sender_name: Optional[str] = None
    subject: Optional[str] = None
    received_at: Optional[datetime] = None
    reply_to: Optional[str] = None
    reply_to_mismatch: bool = False
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None

class EmailIncidentCreate(EmailIncidentBase):
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    headers_json: Optional[str] = None

class EmailIncidentUpdate(BaseModel):
    status: Optional[str] = None
    assigned_analyst: Optional[str] = None
    analyst_notes: Optional[str] = None
    resolution_reason: Optional[str] = None

class EmailIncidentShort(BaseModel):
    id: int
    message_id: Optional[str] = None
    sender: str
    sender_name: Optional[str] = None
    subject: Optional[str] = None
    received_at: Optional[datetime] = None
    ingested_at: datetime
    risk_score: float
    severity: str
    status: str
    assigned_analyst: Optional[str] = None

    class Config:
        from_attributes = True

class EmailIncidentRead(EmailIncidentBase):
    id: int
    message_id: Optional[str] = None
    ingested_at: datetime
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    headers_json: Optional[str] = None
    risk_score: float
    severity: str
    summary_ai: Optional[str] = None
    investigation_notes_ai: Optional[str] = None
    remediation_steps_ai: Optional[str] = None
    status: str
    assigned_analyst: Optional[str] = None
    analyst_notes: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolution_reason: Optional[str] = None
    
    links: List[EmailLinkRead] = []
    attachments: List[EmailAttachmentRead] = []
    history: List[CaseHistoryRead] = []

    class Config:
        from_attributes = True

# --- API Interaction Schemas ---
class ActionAssignRequest(BaseModel):
    analyst: str

class ActionResolveRequest(BaseModel):
    resolution_reason: str
    analyst_notes: Optional[str] = None

class ActionNoteRequest(BaseModel):
    note: str
    analyst: Optional[str] = None

# --- Dashboard Stats Schemas ---
class SeverityCounts(BaseModel):
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0

class StatusCounts(BaseModel):
    open: int = 0
    investigating: int = 0
    resolved: int = 0

class DashboardStats(BaseModel):
    total_incidents: int
    severity_distribution: SeverityCounts
    status_distribution: StatusCounts
    avg_phishing_score: float
    recent_criticals: List[EmailIncidentShort] = []

# --- IMAP Client Request Schema ---
class IMAPSyncRequest(BaseModel):
    server: str
    port: int = 993
    email_addr: str
    password: str
    limit: int = 5

