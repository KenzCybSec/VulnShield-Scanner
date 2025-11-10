"""
Security Headers Analysis Module
"""

import requests

class HeaderAnalyzer:
    def __init__(self):
        self.name = "Security Headers Analyzer"
        self.version = "1.0"
        
        # Critical security headers to check
        self.critical_headers = {
            'Content-Security-Policy': {
                'description': 'Content Security Policy - XSS protection',
                'risk': 'HIGH',
                'remediation': 'Implement CSP to prevent XSS attacks'
            },
            'X-Frame-Options': {
                'description': 'Clickjacking protection',
                'risk': 'MEDIUM', 
                'remediation': 'Set X-Frame-Options to DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'description': 'MIME type sniffing protection',
                'risk': 'MEDIUM',
                'remediation': 'Set X-Content-Type-Options: nosniff'
            },
            'Strict-Transport-Security': {
                'description': 'HTTP Strict Transport Security',
                'risk': 'HIGH',
                'remediation': 'Implement HSTS to enforce HTTPS'
            },
            'X-XSS-Protection': {
                'description': 'XSS protection (legacy browsers)',
                'risk': 'LOW',
                'remediation': 'Set X-XSS-Protection: 1; mode=block'
            },
            'Referrer-Policy': {
                'description': 'Referrer information control',
                'risk': 'LOW',
                'remediation': 'Implement appropriate Referrer-Policy'
            },
            'Permissions-Policy': {
                'description': 'Browser features control',
                'risk': 'MEDIUM',
                'remediation': 'Implement Permissions-Policy header'
            }
        }

    def analyze(self, target_url):
        """Analyze security headers of target URL"""
        print(f"[*] Analyzing security headers for: {target_url}")
        
        findings = []
        
        try:
            response = requests.get(target_url, timeout=10, verify=False)
            headers = response.headers
            
            print(f"    [*] Found {len(headers)} headers")
            
            for header, info in self.critical_headers.items():
                if header not in headers:
                    finding = {
                        'type': 'Missing Security Header',
                        'url': target_url,
                        'header': header,
                        'risk': info['risk'],
                        'description': f'Missing {header} - {info["description"]}',
                        'remediation': info['remediation'],
                        'evidence': f'Header {header} not present in response'
                    }
                    findings.append(finding)
                    print(f"    [!] MISSING: {header}")
                else:
                    print(f"    [✓] PRESENT: {header}: {headers[header]}")
                    
        except Exception as e:
            print(f"    [!] Error analyzing headers: {e}")
            
        print(f"[+] Header analysis completed. Found {len(findings)} issues")
        return findings