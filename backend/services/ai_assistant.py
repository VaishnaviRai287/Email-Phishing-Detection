import os
import json
import logging
from typing import Dict, Any, Tuple
import google.generativeai as genai

logger = logging.getLogger(__name__)

class AIAssistant:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.enabled = True
        
        if not self.api_key or self.api_key == "your_gemini_api_key_here":
            self.enabled = False
            logger.warning("Gemini API Key is missing or using placeholder. Running in mock AI analysis mode.")
        else:
            try:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel('gemini-1.5-flash')
            except Exception as e:
                logger.error(f"Error configuring Gemini SDK: {e}")
                self.enabled = False

    def generate_investigation_report(self, email_data: Dict[str, Any], findings: Dict[str, Any], risk_score: float, severity: str) -> Tuple[str, str, str]:
        """
        Generates a comprehensive analysis of the email using Gemini API.
        Returns:
            Tuple[Summary, InvestigationNotes, RemediationSteps]
        """
        if not self.enabled:
            return self._generate_mock_report(email_data, findings, risk_score, severity)

        # Prepare structural representation for Gemini to read
        links_data = [{"url": l.get("url"), "domain": l.get("domain"), "verdict": l.get("vt_verdict", "CLEAN")} for l in email_data.get("links", [])]
        attachments_data = [{"filename": a.get("filename"), "type": a.get("content_type"), "suspicious": a.get("is_suspicious", False)} for a in email_data.get("attachments", [])]

        analyst_context = {
            "email_metadata": {
                "sender": email_data.get("sender"),
                "sender_name": email_data.get("sender_name"),
                "subject": email_data.get("subject"),
                "reply_to": email_data.get("reply_to"),
                "reply_to_mismatch": email_data.get("reply_to_mismatch"),
                "spf_result": email_data.get("spf_result"),
                "dkim_result": email_data.get("dkim_result"),
                "dmarc_result": email_data.get("dmarc_result"),
            },
            "heuristic_findings": {
                "risk_score": risk_score,
                "severity": severity,
                "reasons": findings.get("reasons", []),
                "matched_keywords": findings.get("matched_keywords", [])
            },
            "threat_intelligence": {
                "links": links_data,
                "attachments": attachments_data
            },
            "email_body_excerpt": (email_data.get("body_text") or email_data.get("body_html") or "")[:2000] # Limit to 2000 chars
        }

        # Prompt for Gemini
        prompt = f"""
        You are a Senior SOC Analyst and Incident Response specialist. Analyze the following suspicious email data, which has been pre-processed by a detection engine.
        
        Suspicious Email Context:
        {json.dumps(analyst_context, indent=2)}
        
        Generate a professional, high-quality, 3-part incident response report. 
        Format your response EXACTLY in three sections separated by the boundary tokens `===SECTION_BREAK===`. Do not add any text before the first section or after the last section.

        --- START OF INSTRUCTIONS ---
        SECTION 1: Executive Summary (Target Audience: Non-technical managers)
        Write a concise, 2-3 sentence overview of this incident. Explain what the email claims to be, what it actually is, and the direct risk to the organization (e.g. credential theft, business email compromise, malware delivery).

        ===SECTION_BREAK===

        SECTION 2: Detailed Technical Analysis (Target Audience: Level 2/3 SOC Analysts)
        Provide a bulleted forensic breakdown.
        - Detail why this email is highly suspicious based on authentication records (SPF/DKIM/DMARC) and headers.
        - Highlight the spoofing or typosquatting techniques used in the sender's address or links.
        - Analyze the behavioral patterns (urgency, call-to-actions, financial requests).
        - Outline the potential technical impact if a user interacts with the links or attachments.

        ===SECTION_BREAK===

        SECTION 3: Incident Mitigation & Remediation (Target Audience: Helpdesk & Security Admin)
        Provide a step-by-step remediation guide.
        1. List immediate actions to contain the incident (e.g., search and purge from all mailboxes).
        2. Provide specific recommendation for the targeted user (e.g., force password reset, revoke active OAuth tokens, run endpoint scan).
        3. Mention infrastructure improvements (e.g., firewall block of IOC domains, email gateway rules update).
        --- END OF INSTRUCTIONS ---
        """

        try:
            response = self.model.generate_content(prompt)
            response_text = response.text
            
            sections = response_text.split("===SECTION_BREAK===")
            if len(sections) >= 3:
                summary = sections[0].strip()
                notes = sections[1].strip()
                remediation = sections[2].strip()
                return summary, notes, remediation
            else:
                # If separator was missed, try standard parsing or return text split
                logger.warning("Gemini response did not contain standard SECTION_BREAK separators.")
                return response_text[:500], response_text, "1. Purge email from mailboxes.\n2. Enable Multi-Factor Authentication.\n3. Train users."
        except Exception as e:
            logger.error(f"Error calling Gemini API: {e}")
            return self._generate_mock_report(email_data, findings, risk_score, severity)

    def _generate_mock_report(self, email_data: Dict[str, Any], findings: Dict[str, Any], risk_score: float, severity: str) -> Tuple[str, str, str]:
        """Generates a highly-personalized professional offline fallback report based strictly on the parsed email content."""
        sender = email_data.get("sender", "unknown@sender.com")
        subject = email_data.get("subject", "Suspicious Alert")
        
        # Dynamically determine the primary threat category and objective based on findings
        has_attachments = len(findings.get("suspicious_attachments", [])) > 0
        has_links = len(findings.get("suspicious_links", [])) > 0
        matched_keywords = findings.get("matched_keywords", [])
        
        threat_category = "Credential Harvesting / Brand Impersonation"
        objective = "Compromise corporate user single-sign-on (SSO) credentials through credential harvesting portal interaction."
        threat_detail = "impersonating a service provider to steal authorization credentials"
        remediation_extra = "Add the malicious destination domains to the local secure gateway blocklists and monitor DNS logs."
        
        if has_attachments:
            threat_category = "Malicious Attachment Delivery / Malware Vector"
            objective = "Execute malicious payloads, macros, or scripts embedded inside the email attachment to establish initial access."
            threat_detail = "delivering a high-risk payload designed to exploit local system applications"
            remediation_extra = "Submit the attachment file hash to the local EDR blocklist, isolate the endpoint of any clicker, and initiate a deep malware scan."
        elif not has_links and any(k in ["invoice due", "billing info", "wire transfer", "payment decline", "tax return", "overdue"] for k in matched_keywords):
            threat_category = "Business Email Compromise (BEC) / Financial Fraud"
            objective = "Manipulate financial or administrative roles into initiating unauthorized bank transfers or leaking invoice metadata."
            threat_detail = "social engineering the reader into executing fraudulent financial workflows"
            remediation_extra = "Contact the accounting department to halt any outbound transactions related to this request and review vendor account changes."

        summary = (
            f"This incident involves a highly suspicious {severity} severity email designed for {threat_category.lower()}. "
            f"The detection engine calculated a risk score of {risk_score:.1f}/100.0 based on heuristic indicators. "
            f"The primary target objective is to {objective.lower().replace('.', '')}."
        )
        
        # Build list of reasons
        reasons_list = ""
        for r in findings.get("reasons", []):
            reasons_list += f"- **Indicator**: {r}\n"
        if not reasons_list:
            reasons_list = "- **Indicator**: Suspicious sender patterns and missing validation signatures."

        notes = (
            f"### Forensic Analysis Summary\n"
            f"- **Threat Category**: {threat_category}\n"
            f"- **Target Domain/Brands**: Mimicking legitimate external communications\n"
            f"- **Ingestion Assessment**:\n"
            f"  - **Sender**: `{sender}`\n"
            f"  - **Subject**: \"{subject}\"\n"
            f"  - **SPF**: `{email_data.get('spf_result', 'none').upper()}` | **DKIM**: `{email_data.get('dkim_result', 'none').upper()}` | **DMARC**: `{email_data.get('dmarc_result', 'none').upper()}`\n\n"
            f"### Key Observations\n"
            f"{reasons_list}\n"
            f"- **Behavioral Indicators**: The email content contains social engineering prompts of high-urgency and call-to-actions.\n"
            f"- **Technical Vector**: The email is active in {threat_detail}. "
            f"If interacted with, it may compromise the endpoint integrity or account credentials of target users."
        )
        
        remediation = (
            f"### SOC Mitigation Actions\n"
            f"1. **Scope and Search**:\n"
            f"   - Run a tenant-wide search in the mail server for sender `{sender}` and subject `\"{subject}\"`.\n"
            f"   - Hard-delete matching emails from all user mailboxes immediately.\n\n"
            f"2. **User Isolation**:\n"
            f"   - Check mail delivery logs to identify if any internal users opened the email or interacted with its contents.\n"
            f"   - For any active users that engaged, trigger an immediate password reset, terminate active session tokens, and enable Step-Up authentication.\n\n"
            f"3. **Technical Controls**:\n"
            f"   - {remediation_extra}\n"
            f"   - Update the secure email gateway (SEG) policies to quarantine mails with similar mismatched headers."
        )
        
        return summary, notes, remediation
