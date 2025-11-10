"""
XSS Vulnerability Scanner Module
"""

import requests
import time
import html
from urllib.parse import urlparse, quote

class XSSScanner:
    def __init__(self):
        self.name = "XSS Scanner"
        self.version = "1.0"
        self.risk_level = "MEDIUM"
        
        # XSS test payloads (non-malicious)
        self.xss_payloads = [
            # Basic XSS vectors
            "<script>alert('XSS_TEST')</script>",
            "<img src=x onerror=alert('XSS_TEST')>",
            "<svg onload=alert('XSS_TEST')>",
            "\"><script>alert('XSS_TEST')</script>",
            "javascript:alert('XSS_TEST')",
            
            # Event handlers
            "onmouseover=alert('XSS_TEST')",
            "onload=alert('XSS_TEST')",
            "onerror=alert('XSS_TEST')",
            
            # Bypass attempts
            "<scr<script>ipt>alert('XSS_TEST')</script>",
            "%3Cscript%3Ealert('XSS_TEST')%3C/script%3E"
        ]
        
        # Safe detection string
        self.detection_string = "XSS_TEST"

    def safe_request(self, url, params=None, headers=None):
        """Make safe HTTP requests"""
        try:
            response = requests.get(
                url,
                params=params,
                headers=headers,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
            return response
        except Exception as e:
            return None

    def detect_xss_reflection(self, response_text, payload):
        """Detect XSS payload reflection in response"""
        # Check if payload is reflected without proper encoding
        if self.detection_string in response_text:
            # Check if the payload is properly encoded
            encoded_payload = html.escape(payload)
            if encoded_payload not in response_text:
                return True
        return False

    def scan_parameter(self, target_url, parameter, payload):
        """Test specific parameter for XSS"""
        try:
            # Test in GET parameter
            test_url = f"{target_url}?{parameter}={quote(payload)}"
            response = self.safe_request(test_url)
            
            if response and response.status_code == 200:
                if self.detect_xss_reflection(response.text, payload):
                    return {
                        'type': 'Cross-Site Scripting (XSS)',
                        'url': test_url,
                        'payload': payload,
                        'risk': 'MEDIUM',
                        'description': f'Reflected XSS vulnerability detected in parameter: {parameter}',
                        'remediation': 'Implement proper input sanitization and Content Security Policy',
                        'evidence': f'Payload reflection detected without proper encoding'
                    }
            
            return None
            
        except Exception as e:
            return None

    def scan(self, target_url):
        """Main XSS scanning function"""
        print(f"[*] Starting XSS scan for: {target_url}")
        
        findings = []
        
        # Common parameter names to test
        parameters = [
            'q', 'search', 'query', 'keyword', 'term',
            'name', 'message', 'comment', 'feedback',
            'url', 'redirect', 'return', 'next',
            'id', 'user', 'username', 'email'
        ]
        
        for param in parameters:
            print(f"    [*] Testing parameter: {param}")
            
            for payload in self.xss_payloads:
                finding = self.scan_parameter(target_url, param, payload)
                
                if finding:
                    findings.append(finding)
                    print(f"    [!] VULNERABLE: XSS detected in parameter {param}")
                
                # Rate limiting
                time.sleep(0.2)
        
        print(f"[+] XSS scan completed. Found {len(findings)} potential vulnerabilities")
        return findings