from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship
from datetime import datetime
from database.db import Base

class EmailIncident(Base):
    __tablename__ = "email_incidents"

    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(String, unique=True, index=True, nullable=True)
    sender = Column(String, index=True, nullable=False)
    sender_name = Column(String, nullable=True)
    subject = Column(String, nullable=True)
    received_at = Column(DateTime, nullable=True)
    ingested_at = Column(DateTime, default=datetime.utcnow)
    
    # Email Content
    body_text = Column(Text, nullable=True)
    body_html = Column(Text, nullable=True)
    
    # Headers & Authentication
    reply_to = Column(String, nullable=True)
    reply_to_mismatch = Column(Boolean, default=False)
    spf_result = Column(String, nullable=True)  # e.g., pass, fail, softfail, neutral, none
    dkim_result = Column(String, nullable=True)
    dmarc_result = Column(String, nullable=True)
    headers_json = Column(Text, nullable=True)  # Store raw/structured headers as JSON string
    
    # Phishing Scoring & Assessment
    risk_score = Column(Float, default=0.0)  # 0.0 to 100.0
    severity = Column(String, default="LOW")  # LOW, MEDIUM, HIGH, CRITICAL
    
    # AI Threat Intel (Gemini)
    summary_ai = Column(Text, nullable=True)
    investigation_notes_ai = Column(Text, nullable=True)
    remediation_steps_ai = Column(Text, nullable=True)
    
    # Case Management
    status = Column(String, default="OPEN")  # OPEN, INVESTIGATING, RESOLVED
    assigned_analyst = Column(String, nullable=True)
    analyst_notes = Column(Text, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolution_reason = Column(String, nullable=True)
    
    # Relationships
    links = relationship("EmailLink", back_populates="incident", cascade="all, delete-orphan")
    attachments = relationship("EmailAttachment", back_populates="incident", cascade="all, delete-orphan")
    history = relationship("CaseHistory", back_populates="incident", cascade="all, delete-orphan")

class EmailLink(Base):
    __tablename__ = "email_links"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("email_incidents.id", ondelete="CASCADE"), nullable=False)
    url = Column(Text, nullable=False)
    domain = Column(String, index=True, nullable=True)
    
    # Heuristics
    is_shortened = Column(Boolean, default=False)
    is_suspicious_redirect = Column(Boolean, default=False)
    
    # VirusTotal Threat Intel
    vt_malicious_count = Column(Integer, default=0)
    vt_harmless_count = Column(Integer, default=0)
    vt_suspicious_count = Column(Integer, default=0)
    vt_undetected_count = Column(Integer, default=0)
    vt_scan_date = Column(DateTime, nullable=True)
    vt_reputation_score = Column(Integer, default=0)
    vt_verdict = Column(String, default="CLEAN")  # CLEAN, SUSPICIOUS, MALICIOUS, UNKNOWN

    incident = relationship("EmailIncident", back_populates="links")

class EmailAttachment(Base):
    __tablename__ = "email_attachments"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("email_incidents.id", ondelete="CASCADE"), nullable=False)
    filename = Column(String, nullable=False)
    content_type = Column(String, nullable=True)
    file_size = Column(Integer, nullable=True)  # in bytes
    file_hash_sha256 = Column(String, index=True, nullable=True)
    is_suspicious = Column(Boolean, default=False)
    risk_reason = Column(String, nullable=True)

    incident = relationship("EmailIncident", back_populates="attachments")

class CaseHistory(Base):
    __tablename__ = "case_history"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("email_incidents.id", ondelete="CASCADE"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    action = Column(String, nullable=False)  # e.g., "STATUS_CHANGE", "ANALYST_NOTE_ADDED", "ASSIGNED"
    details = Column(Text, nullable=True)
    analyst = Column(String, nullable=True)

    incident = relationship("EmailIncident", back_populates="history")
