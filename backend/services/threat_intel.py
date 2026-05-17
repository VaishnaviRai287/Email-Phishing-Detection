import requests
import base64
import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class VirusTotalClient:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        # Check if the key is a placeholder or empty
        if not self.api_key or self.api_key == "your_virustotal_api_key_here":
            self.api_key = None
            logger.warning("VirusTotal API Key is missing or using placeholder. Running in mock/offline fallback mode.")
        
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key or ""
        }

    def _get_url_id(self, url: str) -> str:
        """VirusTotal v3 requires a base64 encoded URL without padding as URL ID."""
        # Standard base64 encoding
        b64_bytes = base64.urlsafe_b64encode(url.encode("utf-8"))
        # Strip the padding '='
        return b64_bytes.decode("utf-8").strip("=")

    def get_url_report(self, url: str) -> Dict[str, Any]:
        """Queries VirusTotal for a URL threat intelligence report."""
        if not self.api_key:
            return self._get_mock_url_report(url)

        url_id = self._get_url_id(url)
        endpoint = f"{self.base_url}/urls/{url_id}"
        
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                reputation = attributes.get("reputation", 0)
                
                malicious = last_analysis_stats.get("malicious", 0)
                suspicious = last_analysis_stats.get("suspicious", 0)
                harmless = last_analysis_stats.get("harmless", 0)
                undetected = last_analysis_stats.get("undetected", 0)
                
                # Determine verdict
                verdict = "CLEAN"
                if malicious > 3:
                    verdict = "MALICIOUS"
                elif malicious > 0 or suspicious > 1:
                    verdict = "SUSPICIOUS"

                return {
                    "vt_malicious_count": malicious,
                    "vt_suspicious_count": suspicious,
                    "vt_harmless_count": harmless,
                    "vt_undetected_count": undetected,
                    "vt_reputation_score": reputation,
                    "vt_scan_date": datetime.utcnow(),
                    "vt_verdict": verdict,
                    "success": True
                }
            elif response.status_code == 404:
                # URL is unknown to VirusTotal, submit it for scanning
                logger.info(f"URL {url} not found in VirusTotal cache, submitting for scan...")
                self.submit_url_for_scan(url)
                return self._get_default_clean_report()
            else:
                logger.error(f"VirusTotal URL scan API returned error status {response.status_code}: {response.text}")
                return self._get_default_clean_report()
        except Exception as e:
            logger.error(f"Failed to query VirusTotal URL scan: {e}")
            return self._get_default_clean_report()

    def submit_url_for_scan(self, url: str) -> bool:
        """Submits a URL to VirusTotal to be scanned."""
        if not self.api_key:
            return False
            
        endpoint = f"{self.base_url}/urls"
        payload = {"url": url}
        try:
            response = requests.post(endpoint, headers=self.headers, data=payload, timeout=10)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to submit URL scan to VirusTotal: {e}")
            return False

    def _get_default_clean_report(self) -> Dict[str, Any]:
        """Default clean report returned when API is unavailable or URL is unscanned."""
        return {
            "vt_malicious_count": 0,
            "vt_suspicious_count": 0,
            "vt_harmless_count": 0,
            "vt_undetected_count": 0,
            "vt_reputation_score": 0,
            "vt_scan_date": datetime.utcnow(),
            "vt_verdict": "CLEAN",
            "success": False
        }

    def _get_mock_url_report(self, url: str) -> Dict[str, Any]:
        """Returns mock details for simulation and testing of the pipeline."""
        malicious = 0
        suspicious = 0
        harmless = 15
        undetected = 2
        verdict = "CLEAN"
        reputation = 5

        # Simulate detecting phishing indicators in the mock domain names
        suspicious_patterns = [
            "paypal", "g00gle", "secure-login", "reset", "billing", 
            "suspended", "signin", "update", "verify", "compromised"
        ]
        
        for pattern in suspicious_patterns:
            if pattern in url.lower():
                malicious = 8
                suspicious = 2
                harmless = 0
                undetected = 1
                verdict = "MALICIOUS"
                reputation = -25
                break

        return {
            "vt_malicious_count": malicious,
            "vt_suspicious_count": suspicious,
            "vt_harmless_count": harmless,
            "vt_undetected_count": undetected,
            "vt_reputation_score": reputation,
            "vt_scan_date": datetime.utcnow(),
            "vt_verdict": verdict,
            "success": True
        }
