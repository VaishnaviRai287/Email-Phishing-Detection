import re
from typing import Dict, List, Any, Tuple
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

# Core Lists for Heuristics
SUSPICIOUS_KEYWORDS = [
    # Urgency & Threatening
    r"urgent", r"immediate action", r"suspend(ed)?", r"deactivat(e|ed)", r"terminate(d)?", 
    r"lock(ed)? out", r"compromised", r"restrict(ed)?", r"unauthorized access", 
    r"verify your account", r"action required", r"within \d+ hours", r"asap",
    # Financial & Reward
    r"refund", r"invoice due", r"billing info(rmation)?", r"wire transfer", r"payment decline(d)?",
    r"tax return", r"claim prize", r"winning ticket", r"inheritance", r"overdue",
    # Credential Harvesting
    r"reset (your )?password", r"update (your )?credentials", r"sign in immediately",
    r"confirm (your )?identity", r"security alert", r"login attempt", r"verification required"
]

HIGH_RISK_EXTENSIONS = [".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".msi", ".pif", ".hta", ".cpl"]
MEDIUM_RISK_EXTENSIONS = [".docm", ".xlsm", ".pptm", ".zip", ".rar", ".7z", ".iso", ".img", ".cab"]

SHORT_URL_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "rebrand.ly", "ow.ly", "is.gd", 
    "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "su.pr", "goo.gl"
]

TRUSTED_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "facebook.com", "netflix.com", "github.com", "linkedin.com", "zoom.us"
]

class PhishingAnalyzer:
    @staticmethod
    def check_typosquatting(domain: str) -> Tuple[bool, str]:
        """Simple checks for lookalike domains or domain spoofing indicators."""
        if not domain:
            return False, ""
            
        domain = domain.lower()
        
        # Check if domain uses IP address format
        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        if re.match(ip_pattern, domain):
            return True, "IP address used as domain"
            
        # Check for typical subdomains prepended to mimic trusted brands (e.g. paypal.com-security-alert.net)
        for brand in TRUSTED_DOMAINS:
            brand_name = brand.split(".")[0]
            # Match brand name followed by hyphens/words but not the actual brand domain
            # e.g., paypal-verification-login.com
            if brand_name in domain and domain != brand and not domain.endswith("." + brand):
                # Ensure it's not a legitimate subdomain, like support.microsoft.com
                if f"-{brand_name}" in domain or f"{brand_name}-" in domain:
                    return True, f"Spoofed/Typosquatted brand pattern ({brand_name})"

        # Check for suspicious character substitutions (e.g. g00gle, paypa1)
        substitutions = [
            (r'g00gle', "google"),
            (r'paypa1', "paypal"),
            (r'micr0soft', "microsoft"),
            (r'sup0rt', "support")
        ]
        for pattern, brand in substitutions:
            if re.search(pattern, domain):
                return True, f"Character substitution spoofing ({brand})"
                
        # Check for overly complex subdomains (e.g. login.verification.secure.server-update.net)
        subdomains = domain.split(".")
        if len(subdomains) > 4:
            return True, "Excessive subdomains"

        return False, ""

    @staticmethod
    def analyze_keywords(subject: str, body_text: str) -> Tuple[int, List[str]]:
        """Scans email text content for phishing keywords and counts matches."""
        matches = []
        score = 0
        
        content = f"{subject or ''} {body_text or ''}".lower()
        
        for pattern in SUSPICIOUS_KEYWORDS:
            if re.search(pattern, content):
                match_word = pattern.replace("(ed)?", "").replace("(your )?", "").replace("info(rmation)?", "info")
                matches.append(match_word)
                score += 15  # 15 points per matched theme
                
        # Cap keyword-based score contribution at 40
        return min(score, 40), matches

    @staticmethod
    def analyze_authentication(spf: str, dkim: str, dmarc: str) -> Tuple[float, Dict[str, str]]:
        """Scores based on email authentication failures."""
        score = 0.0
        reasons = {}
        
        spf = (spf or "none").lower()
        dkim = (dkim or "none").lower()
        dmarc = (dmarc or "none").lower()
        
        # SPF scoring
        if spf in ["fail", "hardfail"]:
            score += 25.0
            reasons["spf"] = "SPF verification failed (Hard Fail)"
        elif spf in ["softfail"]:
            score += 15.0
            reasons["spf"] = "SPF verification failed (Soft Fail)"
        elif spf in ["neutral", "none"]:
            score += 5.0  # slight warning for missing protection
            reasons["spf"] = "Missing SPF email authentication"
            
        # DKIM scoring
        if dkim in ["fail"]:
            score += 20.0
            reasons["dkim"] = "DKIM signature failed validation"
        elif dkim in ["none"]:
            score += 5.0
            reasons["dkim"] = "Missing DKIM signature"

        # DMARC scoring
        if dmarc in ["fail"]:
            score += 30.0
            reasons["dmarc"] = "DMARC policy validation failed"
            
        return score, reasons

    @classmethod
    def calculate_phishing_score(cls, email_data: Dict[str, Any]) -> Tuple[float, str, Dict[str, Any]]:
        """
        Calculates an overall risk score from 0.0 to 100.0 based on various indicators.
        Returns:
            Tuple[risk_score, severity, analysis_findings]
        """
        score = 0.0
        findings = {
            "spf_dkim_fail": False,
            "domain_spoof": False,
            "reply_to_mismatch": False,
            "suspicious_links": [],
            "suspicious_attachments": [],
            "matched_keywords": [],
            "reasons": []
        }

        # 1. Email Auth Results (Max Contribution: 35)
        auth_score, auth_reasons = cls.analyze_authentication(
            email_data.get("spf_result"),
            email_data.get("dkim_result"),
            email_data.get("dmarc_result")
        )
        score += min(auth_score, 35.0)
        for key, desc in auth_reasons.items():
            findings["reasons"].append(desc)
            if "fail" in desc.lower():
                findings["spf_dkim_fail"] = True

        # 2. Reply-To Mismatch (Max Contribution: 20)
        if email_data.get("reply_to_mismatch", False):
            score += 20.0
            findings["reply_to_mismatch"] = True
            findings["reasons"].append(f"Reply-To address mismatch (Sender: {email_data.get('sender')}, Reply-To: {email_data.get('reply_to')})")

        # 3. Sender Domain Analysis (Max Contribution: 25)
        sender_email = email_data.get("sender", "")
        if "@" in sender_email:
            sender_domain = sender_email.split("@")[-1]
            is_typo, typo_reason = cls.check_typosquatting(sender_domain)
            if is_typo:
                score += 25.0
                findings["domain_spoof"] = True
                findings["reasons"].append(f"Sender domain suspicious: {typo_reason}")

        # 4. Keyword and Language Analysis (Max Contribution: 30)
        keyword_score, matched_keywords = cls.analyze_keywords(
            email_data.get("subject", ""),
            email_data.get("body_text", "")
        )
        score += keyword_score
        findings["matched_keywords"] = matched_keywords
        if matched_keywords:
            findings["reasons"].append(f"Detected suspicious themes: {', '.join(matched_keywords)}")

        # 5. Link Analysis (Max Contribution: 30)
        links = email_data.get("links", [])
        for link in links:
            url = link.get("url", "")
            domain = link.get("domain", "")
            
            # Check URL shorteners
            if domain in SHORT_URL_DOMAINS:
                link["is_shortened"] = True
                score += 15.0
                findings["suspicious_links"].append(url)
                findings["reasons"].append(f"Contains shortened URL: {url}")
                
            # Check typosquatting on link domains
            is_typo_link, typo_link_reason = cls.check_typosquatting(domain)
            if is_typo_link:
                link["is_suspicious_redirect"] = True
                score += 20.0
                findings["suspicious_links"].append(url)
                findings["reasons"].append(f"URL links to typosquatted domain: {url} ({typo_link_reason})")

        # 6. Attachment Analysis (Max Contribution: 30)
        attachments = email_data.get("attachments", [])
        for attach in attachments:
            filename = attach.get("filename", "").lower()
            file_ext = ""
            if "." in filename:
                file_ext = filename[filename.rfind("."):]
                
            if file_ext in HIGH_RISK_EXTENSIONS:
                attach["is_suspicious"] = True
                attach["risk_reason"] = "Executable or script extension"
                score += 30.0
                findings["suspicious_attachments"].append(attach["filename"])
                findings["reasons"].append(f"High-risk attachment: {attach['filename']}")
            elif file_ext in MEDIUM_RISK_EXTENSIONS:
                attach["is_suspicious"] = True
                attach["risk_reason"] = "Compressed or Office document with potential macro execution"
                score += 15.0
                findings["suspicious_attachments"].append(attach["filename"])
                findings["reasons"].append(f"Suspicious container/macro-enabled attachment: {attach['filename']}")

        # Clamp overall score between 0.0 and 100.0
        final_score = min(max(score, 0.0), 100.0)

        # Severity categorization
        if final_score < 30.0:
            severity = "LOW"
        elif final_score < 60.0:
            severity = "MEDIUM"
        elif final_score < 85.0:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        return final_score, severity, findings
