import imaplib
import email
from email.header import decode_header
import re
import hashlib
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EmailParser:
    @staticmethod
    def decode_mime_words(s: str) -> str:
        """Decode email header values that might be mime-encoded (e.g. =?utf-8?B?...=?)"""
        if not s:
            return ""
        try:
            decoded_parts = decode_header(s)
            result = []
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    try:
                        result.append(part.decode(encoding or "utf-8", errors="replace"))
                    except Exception:
                        result.append(part.decode("latin1", errors="replace"))
                else:
                    result.append(str(part))
            return "".join(result)
        except Exception as e:
            logger.error(f"Error decoding MIME words: {e}")
            return s

    @staticmethod
    def parse_sender(sender_raw: str) -> Tuple[str, str]:
        """Extract Name and Email Address from raw From header.
        e.g., 'Google Support <no-reply@google.com>' -> ('Google Support', 'no-reply@google.com')
        """
        if not sender_raw:
            return "", ""
        
        sender_raw = EmailParser.decode_mime_words(sender_raw)
        
        # Match 'Name <email@domain.com>'
        match = re.search(r'(.*?)\s*<([^>]+)>', sender_raw)
        if match:
            name = match.group(1).strip().strip('"').strip("'")
            email_addr = match.group(2).strip().lower()
            return name, email_addr
        
        # If no brackets, check if it is just an email or plain text
        email_addr = sender_raw.strip().lower()
        if "@" in email_addr:
            return "", email_addr
        return email_addr, ""

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract all unique URLs from plain text or HTML using regex."""
        if not text:
            return []
        # Regex to capture urls starting with http or https
        url_pattern = r'https?://[^\s\'"<>]+'
        urls = re.findall(url_pattern, text)
        
        # Clean trailing punctuation from URLs (e.g. periods, commas, parentheses)
        cleaned_urls = []
        for url in urls:
            # Strip trailing characters that are rarely part of a URL
            url = re.sub(r'[\.,;\)\]\}\?]+$', '', url)
            if url not in cleaned_urls:
                cleaned_urls.append(url)
        return cleaned_urls

    @staticmethod
    def parse_auth_headers(msg: email.message.Message) -> Dict[str, str]:
        """Parse authentication results from email headers (SPF, DKIM, DMARC)."""
        auth_results = {"spf": "none", "dkim": "none", "dmarc": "none"}
        
        # Look at Authentication-Results header
        auth_headers = msg.get_all("Authentication-Results", [])
        for header in auth_headers:
            header_decoded = EmailParser.decode_mime_words(header).lower()
            
            # Extract SPF
            spf_match = re.search(r'spf=(\w+)', header_decoded)
            if spf_match:
                auth_results["spf"] = spf_match.group(1)
                
            # Extract DKIM
            dkim_match = re.search(r'dkim=(\w+)', header_decoded)
            if dkim_match:
                auth_results["dkim"] = dkim_match.group(1)
                
            # Extract DMARC
            dmarc_match = re.search(r'dmarc=(\w+)', header_decoded)
            if dmarc_match:
                auth_results["dmarc"] = dmarc_match.group(1)

        # Fallback to Received-SPF header
        if auth_results["spf"] == "none":
            received_spf = msg.get("Received-SPF", "")
            if received_spf:
                received_spf = EmailParser.decode_mime_words(received_spf).lower()
                spf_match = re.match(r'^(\w+)', received_spf)
                if spf_match:
                    auth_results["spf"] = spf_match.group(1)

        return auth_results

    @classmethod
    def parse_raw_email(cls, raw_email_bytes: bytes) -> Dict[str, Any]:
        """Parses a raw email in RFC 822/bytes format into a structured Python dictionary."""
        msg = email.message_from_bytes(raw_email_bytes)
        
        # Extract basic headers
        subject = cls.decode_mime_words(msg.get("Subject", "(No Subject)"))
        sender_raw = msg.get("From", "")
        sender_name, sender_email = cls.parse_sender(sender_raw)
        
        reply_to_raw = msg.get("Reply-To", "")
        _, reply_to_email = cls.parse_sender(reply_to_raw)
        
        message_id = msg.get("Message-ID", "")
        
        # Parse timestamp
        received_date_str = msg.get("Date", "")
        received_at = None
        if received_date_str:
            try:
                # parsedate_to_datetime parses RFC 2822 datetime strings
                received_at = email.utils.parsedate_to_datetime(received_date_str)
                # Strip timezone if we want a naive datetime for sqlite
                received_at = received_at.replace(tzinfo=None)
            except Exception:
                logger.warning(f"Failed to parse email date: {received_date_str}")
                received_at = datetime.utcnow()
        else:
            received_at = datetime.utcnow()

        body_text = ""
        body_html = ""
        attachments = []
        
        # Process multi-part messages or single body message
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                # Check if attachment
                if "attachment" in content_disposition or part.get_filename():
                    filename = cls.decode_mime_words(part.get_filename() or "unnamed_attachment")
                    try:
                        payload = part.get_payload(decode=True) or b""
                        file_size = len(payload)
                        sha256_hash = hashlib.sha256(payload).hexdigest()
                    except Exception as e:
                        logger.error(f"Error parsing attachment payload for {filename}: {e}")
                        file_size = 0
                        sha256_hash = ""
                        
                    attachments.append({
                        "filename": filename,
                        "content_type": content_type,
                        "file_size": file_size,
                        "file_hash_sha256": sha256_hash,
                        "is_suspicious": False,  # Will be assessed by logic
                        "risk_reason": None
                    })
                else:
                    # Regular body part
                    if content_type == "text/plain" and "attachment" not in content_disposition:
                        try:
                            body_text += part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
                        except Exception:
                            body_text += part.get_payload(decode=True).decode("latin1", errors="replace")
                    elif content_type == "text/html" and "attachment" not in content_disposition:
                        try:
                            body_html += part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
                        except Exception:
                            body_html += part.get_payload(decode=True).decode("latin1", errors="replace")
        else:
            # Single part message
            content_type = msg.get_content_type()
            try:
                body = msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", errors="replace")
            except Exception:
                body = msg.get_payload(decode=True).decode("latin1", errors="replace")
                
            if content_type == "text/html":
                body_html = body
            else:
                body_text = body

        # Extract links from both HTML and Text bodies
        extracted_urls = set()
        extracted_urls.update(cls.extract_urls(body_text))
        extracted_urls.update(cls.extract_urls(body_html))
        
        # Also parse href attributes in HTML explicitly to make sure we don't miss hidden links
        if body_html:
            hrefs = re.findall(r'href=["\'](https?://[^"\']+)["\']', body_html, re.IGNORECASE)
            extracted_urls.update(hrefs)
            
        links = []
        for url in extracted_urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                links.append({
                    "url": url,
                    "domain": domain,
                    "is_shortened": False,  # Will be analyzed by scoring logic
                    "is_suspicious_redirect": False
                })
            except Exception:
                links.append({
                    "url": url,
                    "domain": "",
                    "is_shortened": False,
                    "is_suspicious_redirect": False
                })

        # Calculate authentication headers
        auth_results = cls.parse_auth_headers(msg)
        
        # Identify headers mismatch
        reply_to_mismatch = False
        if reply_to_email and sender_email and reply_to_email != sender_email:
            reply_to_mismatch = True

        # Capture complete headers as JSON
        headers_dict = {}
        for k, v in msg.items():
            k_decoded = cls.decode_mime_words(k)
            v_decoded = cls.decode_mime_words(v)
            if k_decoded in headers_dict:
                if isinstance(headers_dict[k_decoded], list):
                    headers_dict[k_decoded].append(v_decoded)
                else:
                    headers_dict[k_decoded] = [headers_dict[k_decoded], v_decoded]
            else:
                headers_dict[k_decoded] = v_decoded

        return {
            "message_id": message_id,
            "sender": sender_email,
            "sender_name": sender_name,
            "subject": subject,
            "received_at": received_at,
            "body_text": body_text,
            "body_html": body_html,
            "reply_to": reply_to_email,
            "reply_to_mismatch": reply_to_mismatch,
            "spf_result": auth_results["spf"],
            "dkim_result": auth_results["dkim"],
            "dmarc_result": auth_results["dmarc"],
            "headers_json": json.dumps(headers_dict),
            "links": links,
            "attachments": attachments
        }

class IMAPEmailService:
    def __init__(self, server: str, port: int, email_addr: str, password: str, folder: str = "INBOX"):
        self.server = server
        self.port = port
        self.email_addr = email_addr
        self.password = password
        self.folder = folder

    def fetch_latest_emails(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Connects to IMAP server and fetches the latest N emails."""
        parsed_emails = []
        try:
            # Initialize IMAP SSL connection
            mail = imaplib.IMAP4_SSL(self.server, self.port)
            mail.login(self.email_addr, self.password)
            mail.select(self.folder)
            
            # Search for all emails
            status, messages = mail.search(None, "ALL")
            if status != "OK":
                logger.error("Could not fetch messages list via IMAP search.")
                return []
                
            mail_ids = messages[0].split()
            # Fetch latest IDs
            latest_mail_ids = mail_ids[-limit:]
            latest_mail_ids.reverse()  # Start with the newest
            
            for mail_id in latest_mail_ids:
                status, data = mail.fetch(mail_id, "(RFC822)")
                if status != "OK" or not data:
                    logger.error(f"Failed to fetch mail ID: {mail_id}")
                    continue
                
                # Fetch response contents
                raw_email_bytes = data[0][1]
                try:
                    parsed_email = EmailParser.parse_raw_email(raw_email_bytes)
                    parsed_emails.append(parsed_email)
                except Exception as e:
                    logger.error(f"Error parsing raw email for ID {mail_id}: {e}")
                    
            mail.close()
            mail.logout()
            logger.info(f"Successfully fetched and parsed {len(parsed_emails)} emails via IMAP.")
        except Exception as e:
            logger.error(f"Failed to fetch emails via IMAP: {e}")
            raise e
            
        return parsed_emails
