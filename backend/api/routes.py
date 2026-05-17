from fastapi import APIRouter, Depends, HTTPException, Query, status, File, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta
import io
import csv
import json
import logging
from typing import List, Optional

from database.db import get_db
from models import models, schemas
from services.email_service import EmailParser, IMAPEmailService
from services.analyzer_service import PhishingAnalyzer
from services.threat_intel import VirusTotalClient
from services.ai_assistant import AIAssistant
from utils.sample_data import SAMPLE_EMAILS

logger = logging.getLogger(__name__)
router = APIRouter()

# Helper to log case history events
def log_case_event(db: Session, incident_id: int, action: str, details: str, analyst: Optional[str] = None):
    history_entry = models.CaseHistory(
        incident_id=incident_id,
        action=action,
        details=details,
        analyst=analyst or "System Engine"
    )
    db.add(history_entry)
    db.commit()

# --- INGESTION ENDPOINTS ---

@router.post("/ingest/sample", status_code=status.HTTP_201_CREATED)
def ingest_sample_data(db: Session = Depends(get_db)):
    """Populates the SQLite database with high-quality sample phishing emails for demonstration."""
    vt_client = VirusTotalClient()
    ai_client = AIAssistant()
    ingested_count = 0
    
    for item in SAMPLE_EMAILS:
        try:
            # Parse the raw bytes
            email_data = EmailParser.parse_raw_email(item["raw"])
            
            # Check for existing message ID to prevent duplicates
            existing = db.query(models.EmailIncident).filter(models.EmailIncident.message_id == email_data["message_id"]).first()
            if existing:
                continue

            # 1. Analyze phishing heuristics
            risk_score, severity, findings = PhishingAnalyzer.calculate_phishing_score(email_data)
            
            # 2. Enrich URL Intel via VirusTotal
            enriched_links = []
            for link in email_data["links"]:
                vt_report = vt_client.get_url_report(link["url"])
                link.update(vt_report)
                enriched_links.append(link)
                # Boost risk score if VT confirms malicious URL
                if vt_report.get("vt_verdict") == "MALICIOUS":
                    risk_score = min(risk_score + 35.0, 100.0)
                    if "VirusTotal flag: malicious URL" not in findings["reasons"]:
                        findings["reasons"].append(f"VirusTotal detected malicious URL: {link['url']}")
            
            # Recalculate severity if VT boosted the score
            if risk_score >= 85.0:
                severity = "CRITICAL"
            elif risk_score >= 60.0:
                severity = "HIGH"
            elif risk_score >= 30.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            # 3. Generate Gemini AI Investigation report
            summary_ai, notes_ai, remediation_ai = ai_client.generate_investigation_report(
                email_data, findings, risk_score, severity
            )

            # 4. Save to Database
            incident = models.EmailIncident(
                message_id=email_data["message_id"],
                sender=email_data["sender"],
                sender_name=email_data["sender_name"],
                subject=email_data["subject"],
                received_at=email_data["received_at"],
                body_text=email_data["body_text"],
                body_html=email_data["body_html"],
                reply_to=email_data["reply_to"],
                reply_to_mismatch=email_data["reply_to_mismatch"],
                spf_result=email_data["spf_result"],
                dkim_result=email_data["dkim_result"],
                dmarc_result=email_data["dmarc_result"],
                headers_json=email_data["headers_json"],
                risk_score=risk_score,
                severity=severity,
                summary_ai=summary_ai,
                investigation_notes_ai=notes_ai,
                remediation_steps_ai=remediation_ai,
                status="OPEN"
            )
            db.add(incident)
            db.flush()  # Generates the incident ID

            # Save Links
            for link in enriched_links:
                db_link = models.EmailLink(
                    incident_id=incident.id,
                    url=link["url"],
                    domain=link["domain"],
                    is_shortened=link["is_shortened"],
                    is_suspicious_redirect=link["is_suspicious_redirect"],
                    vt_malicious_count=link.get("vt_malicious_count", 0),
                    vt_harmless_count=link.get("vt_harmless_count", 0),
                    vt_suspicious_count=link.get("vt_suspicious_count", 0),
                    vt_undetected_count=link.get("vt_undetected_count", 0),
                    vt_scan_date=link.get("vt_scan_date"),
                    vt_reputation_score=link.get("vt_reputation_score", 0),
                    vt_verdict=link.get("vt_verdict", "CLEAN")
                )
                db.add(db_link)

            # Save Attachments
            for attach in email_data["attachments"]:
                db_attach = models.EmailAttachment(
                    incident_id=incident.id,
                    filename=attach["filename"],
                    content_type=attach["content_type"],
                    file_size=attach["file_size"],
                    file_hash_sha256=attach["file_hash_sha256"],
                    is_suspicious=attach["is_suspicious"],
                    risk_reason=attach["risk_reason"]
                )
                db.add(db_attach)

            db.commit()
            
            # Log creation history
            log_case_event(
                db, 
                incident.id, 
                "INGESTED", 
                f"Automated ingestion completed. Risk Score: {risk_score:.1f}/100.0, Severity: {severity}."
            )
            ingested_count += 1
            
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to ingest sample email: {e}")
            continue

    return {"message": f"Successfully ingested {ingested_count} new sample incidents."}

@router.post("/ingest/imap")
def ingest_imap_emails(
    limit: int = Query(5, ge=1, le=20),
    request: Optional[schemas.IMAPSyncRequest] = None,
    db: Session = Depends(get_db)
):
    """Connects to configured or custom IMAP mail server and ingests latest unparsed emails."""
    if request:
        server = request.server
        port = request.port
        email_addr = request.email_addr
        password = request.password
        limit = request.limit
    else:
        import os
        server = os.getenv("IMAP_SERVER")
        port = int(os.getenv("IMAP_PORT", "993"))
        email_addr = os.getenv("IMAP_EMAIL")
        password = os.getenv("IMAP_PASSWORD")
        
    if not email_addr or password == "your_app_specific_password_here" or not password:
        raise HTTPException(
            status_code=400, 
            detail="IMAP server credentials are not fully configured. Provide them in the UI or update your backend .env file."
        )

    try:
        imap_service = IMAPEmailService(server, port, email_addr, password)
        emails = imap_service.fetch_latest_emails(limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed connection to IMAP server: {str(e)}")

    vt_client = VirusTotalClient()
    ai_client = AIAssistant()
    ingested_count = 0

    for email_data in emails:
        try:
            # Check duplicate
            existing = db.query(models.EmailIncident).filter(models.EmailIncident.message_id == email_data["message_id"]).first()
            if existing:
                continue

            risk_score, severity, findings = PhishingAnalyzer.calculate_phishing_score(email_data)
            
            # VT URL scan
            enriched_links = []
            for link in email_data["links"]:
                vt_report = vt_client.get_url_report(link["url"])
                link.update(vt_report)
                enriched_links.append(link)
                if vt_report.get("vt_verdict") == "MALICIOUS":
                    risk_score = min(risk_score + 35.0, 100.0)
                    findings["reasons"].append(f"VirusTotal detected malicious URL: {link['url']}")
            
            # Recalculate severity
            if risk_score >= 85.0:
                severity = "CRITICAL"
            elif risk_score >= 60.0:
                severity = "HIGH"
            elif risk_score >= 30.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            # Gemini report
            summary_ai, notes_ai, remediation_ai = ai_client.generate_investigation_report(
                email_data, findings, risk_score, severity
            )

            # DB Save
            incident = models.EmailIncident(
                message_id=email_data["message_id"],
                sender=email_data["sender"],
                sender_name=email_data["sender_name"],
                subject=email_data["subject"],
                received_at=email_data["received_at"],
                body_text=email_data["body_text"],
                body_html=email_data["body_html"],
                reply_to=email_data["reply_to"],
                reply_to_mismatch=email_data["reply_to_mismatch"],
                spf_result=email_data["spf_result"],
                dkim_result=email_data["dkim_result"],
                dmarc_result=email_data["dmarc_result"],
                headers_json=email_data["headers_json"],
                risk_score=risk_score,
                severity=severity,
                summary_ai=summary_ai,
                investigation_notes_ai=notes_ai,
                remediation_steps_ai=remediation_ai,
                status="OPEN"
            )
            db.add(incident)
            db.flush()

            for link in enriched_links:
                db_link = models.EmailLink(
                    incident_id=incident.id,
                    url=link["url"],
                    domain=link["domain"],
                    is_shortened=link["is_shortened"],
                    is_suspicious_redirect=link["is_suspicious_redirect"],
                    vt_malicious_count=link.get("vt_malicious_count", 0),
                    vt_harmless_count=link.get("vt_harmless_count", 0),
                    vt_suspicious_count=link.get("vt_suspicious_count", 0),
                    vt_undetected_count=link.get("vt_undetected_count", 0),
                    vt_scan_date=link.get("vt_scan_date"),
                    vt_reputation_score=link.get("vt_reputation_score", 0),
                    vt_verdict=link.get("vt_verdict", "CLEAN")
                )
                db.add(db_link)

            for attach in email_data["attachments"]:
                db_attach = models.EmailAttachment(
                    incident_id=incident.id,
                    filename=attach["filename"],
                    content_type=attach["content_type"],
                    file_size=attach["file_size"],
                    file_hash_sha256=attach["file_hash_sha256"],
                    is_suspicious=attach["is_suspicious"],
                    risk_reason=attach["risk_reason"]
                )
                db.add(db_attach)

            db.commit()
            log_case_event(db, incident.id, "INGESTED", f"IMAP Ingestion process completed. Severity: {severity}.")
            ingested_count += 1
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error ingesting email from IMAP list: {e}")
            continue

    return {"message": f"Successfully ingested {ingested_count} new emails via IMAP."}

@router.post("/ingest/upload", status_code=status.HTTP_201_CREATED)
async def upload_eml_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Parses an uploaded raw EML file and triggers immediate threat indexing and case registration."""
    try:
        raw_bytes = await file.read()
        email_data = EmailParser.parse_raw_email(raw_bytes)
        
        # Check duplicate
        if email_data.get("message_id"):
            existing = db.query(models.EmailIncident).filter(models.EmailIncident.message_id == email_data["message_id"]).first()
            if existing:
                return {
                    "id": existing.id,
                    "subject": existing.subject,
                    "message": "Incident already exists in triage database queue."
                }
    except Exception as e:
        logger.error(f"EML upload format error: {e}")
        raise HTTPException(
            status_code=400,
            detail=f"Failed to parse uploaded file. Make sure it is a valid EML file. Details: {str(e)}"
        )

    try:
        # 1. Heuristics Scorer
        risk_score, severity, findings = PhishingAnalyzer.calculate_phishing_score(email_data)
        
        # 2. VirusTotal link enrichment
        vt_client = VirusTotalClient()
        enriched_links = []
        for link in email_data["links"]:
            vt_report = vt_client.get_url_report(link["url"])
            link.update(vt_report)
            enriched_links.append(link)
            if vt_report.get("vt_verdict") == "MALICIOUS":
                risk_score = min(risk_score + 35.0, 100.0)
                findings["reasons"].append(f"VirusTotal detected malicious URL: {link['url']}")
        
        # Recalculate severity
        if risk_score >= 85.0:
            severity = "CRITICAL"
        elif risk_score >= 60.0:
            severity = "HIGH"
        elif risk_score >= 30.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # 3. Gemini AI Analysis
        ai_client = AIAssistant()
        summary_ai, notes_ai, remediation_ai = ai_client.generate_investigation_report(
            email_data, findings, risk_score, severity
        )

        # 4. DB Save
        incident = models.EmailIncident(
            message_id=email_data["message_id"],
            sender=email_data["sender"],
            sender_name=email_data["sender_name"],
            subject=email_data["subject"],
            received_at=email_data["received_at"],
            body_text=email_data["body_text"],
            body_html=email_data["body_html"],
            reply_to=email_data["reply_to"],
            reply_to_mismatch=email_data["reply_to_mismatch"],
            spf_result=email_data["spf_result"],
            dkim_result=email_data["dkim_result"],
            dmarc_result=email_data["dmarc_result"],
            headers_json=email_data["headers_json"],
            risk_score=risk_score,
            severity=severity,
            summary_ai=summary_ai,
            investigation_notes_ai=notes_ai,
            remediation_steps_ai=remediation_ai,
            status="OPEN"
        )
        db.add(incident)
        db.flush()

        for link in enriched_links:
            db_link = models.EmailLink(
                incident_id=incident.id,
                url=link["url"],
                domain=link["domain"],
                is_shortened=link["is_shortened"],
                is_suspicious_redirect=link["is_suspicious_redirect"],
                vt_malicious_count=link.get("vt_malicious_count", 0),
                vt_harmless_count=link.get("vt_harmless_count", 0),
                vt_suspicious_count=link.get("vt_suspicious_count", 0),
                vt_undetected_count=link.get("vt_undetected_count", 0),
                vt_scan_date=link.get("vt_scan_date"),
                vt_reputation_score=link.get("vt_reputation_score", 0),
                vt_verdict=link.get("vt_verdict", "CLEAN")
            )
            db.add(db_link)

        for attach in email_data["attachments"]:
            db_attach = models.EmailAttachment(
                incident_id=incident.id,
                filename=attach["filename"],
                content_type=attach["content_type"],
                file_size=attach["file_size"],
                file_hash_sha256=attach["file_hash_sha256"],
                is_suspicious=attach["is_suspicious"],
                risk_reason=attach["risk_reason"]
            )
            db.add(db_attach)

        db.commit()
        log_case_event(db, incident.id, "INGESTED", f"EML Upload completed. Ingested as a new incident case. Severity: {severity}.")
        
        return {
            "id": incident.id,
            "subject": incident.subject,
            "message": "Security incident uploader parsed and logged successfully."
        }

    except Exception as e:
        db.rollback()
        logger.error(f"Error processing uploaded EML: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal processing failure: {str(e)}"
        )

# --- INCIDENTS WORKFLOWS ---

@router.get("/incidents", response_model=List[schemas.EmailIncidentShort])
def get_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Retrieves all parsed incidents, applying filters for search, severity, and status."""
    query = db.query(models.EmailIncident)
    
    if status:
        query = query.filter(models.EmailIncident.status == status.upper())
    if severity:
        query = query.filter(models.EmailIncident.severity == severity.upper())
    if search:
        search_filter = f"%{search}%"
        query = query.filter(
            models.EmailIncident.sender.like(search_filter) | 
            models.EmailIncident.subject.like(search_filter) |
            models.EmailIncident.sender_name.like(search_filter)
        )
        
    return query.order_index(models.EmailIncident.received_at.desc() if hasattr(models.EmailIncident, "received_at") else models.EmailIncident.id.desc()).all() if hasattr(query, "order_index") else query.order_by(models.EmailIncident.received_at.desc()).all()

@router.get("/incidents/{incident_id}", response_model=schemas.EmailIncidentRead)
def get_incident_by_id(incident_id: int, db: Session = Depends(get_db)):
    """Returns detailed information of a single incident."""
    incident = db.query(models.EmailIncident).filter(models.EmailIncident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@router.post("/incidents/{incident_id}/assign", response_model=schemas.EmailIncidentShort)
def assign_incident(incident_id: int, request: schemas.ActionAssignRequest, db: Session = Depends(get_db)):
    """Assigns an incident to a designated SOC Analyst."""
    incident = db.query(models.EmailIncident).filter(models.EmailIncident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    old_analyst = incident.assigned_analyst or "Unassigned"
    incident.assigned_analyst = request.analyst
    
    # Auto transition state to INVESTIGATING if OPEN
    if incident.status == "OPEN":
        incident.status = "INVESTIGATING"
        log_case_event(db, incident.id, "STATUS_CHANGE", "Incident status auto-updated from OPEN to INVESTIGATING.", request.analyst)

    db.commit()
    db.refresh(incident)
    
    log_case_event(
        db, 
        incident.id, 
        "ASSIGNED", 
        f"Analyst assigned changed from '{old_analyst}' to '{request.analyst}'.",
        request.analyst
    )
    
    return incident

@router.post("/incidents/{incident_id}/resolve", response_model=schemas.EmailIncidentShort)
def resolve_incident(incident_id: int, request: schemas.ActionResolveRequest, db: Session = Depends(get_db)):
    """Closes and resolves a triage case with investigation closure reasons."""
    incident = db.query(models.EmailIncident).filter(models.EmailIncident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    incident.status = "RESOLVED"
    incident.resolved_at = datetime.utcnow()
    incident.resolution_reason = request.resolution_reason
    if request.analyst_notes:
        incident.analyst_notes = (incident.analyst_notes or "") + f"\n\n[Resolution Note {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}]\n" + request.analyst_notes

    db.commit()
    db.refresh(incident)
    
    log_case_event(
        db, 
        incident.id, 
        "STATUS_CHANGE", 
        f"Case resolved. Resolution Verdict: {request.resolution_reason}.",
        incident.assigned_analyst
    )
    
    return incident

@router.post("/incidents/{incident_id}/notes", response_model=schemas.EmailIncidentRead)
def add_analyst_note(incident_id: int, request: schemas.ActionNoteRequest, db: Session = Depends(get_db)):
    """Appends hand-written triage notes or incident updates to a case."""
    incident = db.query(models.EmailIncident).filter(models.EmailIncident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    analyst_name = request.analyst or incident.assigned_analyst or "SOC Analyst"
    timestamp_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M')
    
    new_note_block = f"\n\n[{timestamp_str} - {analyst_name}]:\n{request.note}"
    incident.analyst_notes = (incident.analyst_notes or "") + new_note_block
    
    db.commit()
    db.refresh(incident)
    
    log_case_event(
        db, 
        incident.id, 
        "ANALYST_NOTE_ADDED", 
        f"New triage analyst note added by {analyst_name}.",
        analyst_name
    )
    
    return incident

# --- DASHBOARD METRICS ---

@router.get("/dashboard/stats", response_model=schemas.DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Fetches high-level stats cards and status matrices for the main SOC console."""
    total = db.query(models.EmailIncident).count()
    
    # Severity split
    low = db.query(models.EmailIncident).filter(models.EmailIncident.severity == "LOW").count()
    medium = db.query(models.EmailIncident).filter(models.EmailIncident.severity == "MEDIUM").count()
    high = db.query(models.EmailIncident).filter(models.EmailIncident.severity == "HIGH").count()
    critical = db.query(models.EmailIncident).filter(models.EmailIncident.severity == "CRITICAL").count()
    
    # Status split
    opened = db.query(models.EmailIncident).filter(models.EmailIncident.status == "OPEN").count()
    investigating = db.query(models.EmailIncident).filter(models.EmailIncident.status == "INVESTIGATING").count()
    resolved = db.query(models.EmailIncident).filter(models.EmailIncident.status == "RESOLVED").count()
    
    # Average score
    avg_score_res = db.query(func.avg(models.EmailIncident.risk_score)).scalar()
    avg_score = round(avg_score_res, 1) if avg_score_res else 0.0
    
    # Recent criticals
    recent_criticals = db.query(models.EmailIncident)\
        .filter(models.EmailIncident.severity.in_(["HIGH", "CRITICAL"]))\
        .order_by(models.EmailIncident.id.desc()).limit(5).all()

    return {
        "total_incidents": total,
        "severity_distribution": {
            "low": low,
            "medium": medium,
            "high": high,
            "critical": critical
        },
        "status_distribution": {
            "open": opened,
            "investigating": investigating,
            "resolved": resolved
        },
        "avg_phishing_score": avg_score,
        "recent_criticals": recent_criticals
    }

@router.get("/dashboard/trends")
def get_incident_trends(db: Session = Depends(get_db)):
    """Returns a daily counts dataset of security incidents for timeline charts."""
    # SQLite friendly query to group by date
    # Format date: YYYY-MM-DD
    if db.bind.dialect.name == "sqlite":
        date_func = func.strftime("%Y-%m-%d", models.EmailIncident.ingested_at)
    else:
        date_func = func.cast(models.EmailIncident.ingested_at, func.Date)
        
    results = db.query(date_func.label("date"), func.count(models.EmailIncident.id).label("count"))\
        .group_by(date_func)\
        .order_by(date_func.desc())\
        .limit(7).all()
        
    # Standardize result array
    trends_list = [{"date": r.date, "count": r.count} for r in results]
    # Reverse to show past-to-present timeline (left to right)
    trends_list.reverse()
    return trends_list

# --- REPORT GENERATION & EXPORTS ---

@router.get("/reports/csv")
def export_incidents_csv(db: Session = Depends(get_db)):
    """Generates and streams a CSV database dump of all triaged incidents."""
    incidents = db.query(models.EmailIncident).order_by(models.EmailIncident.id.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Headers
    writer.writerow([
        "Incident ID", "Message ID", "Sender Address", "Sender Name", 
        "Subject", "Risk Score", "Severity", "Authentication (SPF/DKIM/DMARC)", 
        "Status", "Assigned Analyst", "Ingested At", "Resolved At", "Resolution Verdict"
    ])
    
    for inc in incidents:
        auth_str = f"SPF:{inc.spf_result or 'none'}|DKIM:{inc.dkim_result or 'none'}|DMARC:{inc.dmarc_result or 'none'}"
        writer.writerow([
            inc.id, inc.message_id, inc.sender, inc.sender_name or "", 
            inc.subject or "", inc.risk_score, inc.severity, auth_str,
            inc.status, inc.assigned_analyst or "Unassigned", 
            inc.ingested_at.strftime('%Y-%m-%d %H:%M:%S'),
            inc.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if inc.resolved_at else "",
            inc.resolution_reason or ""
        ])
    
    # Stream the output
    response = StreamingResponse(io.BytesIO(output.getvalue().encode("utf-8")), media_type="text/csv")
    response.headers["Content-Disposition"] = f"attachment; filename=soc_phishing_report_{datetime.now().strftime('%Y%m%d')}.csv"
    return response
