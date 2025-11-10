"""
SQL Injection Vulnerability Scanner Module
"""

import requests
import time
import re
from urllib.parse import urljoin, urlparse

class SQLScanner:
    def __init__(self):
        self.name = "SQL Injection Scanner"
        self.version = "1.0"
        self.risk_level = "HIGH"
        
        # SQL Injection test payloads (EDUCATIONAL ONLY)
        self.sql_payloads = [
            # Basic SQL detection
            "'",
            "\"",
            "`",
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT 1,2,3--",
            "' AND 1=1--",
            
            # Error-based detection
            "' AND 1=CAST(0x5f5f5f5f AS INT)--",
            "' OR EXISTS(SELECT 1 FROM users)--",
            
            # Time-based blind SQLi (simplified)
            "' ; WAITFOR DELAY '0:0:5'--",
            "' AND SLEEP(5)--"
        ]
        
        # Database error patterns
        self.db_errors = {
            'mysql': [
                r"mysql.*error",
                r"you have an error in your sql syntax",
                r"warning.*mysql",
                r"mysql_fetch_array",
                r"mysqli_"
            ],
            'postgresql': [
                r"postgresql.*error",
                r"pg_.*error",
                r"postgres.*error"
            ],
            'mssql': [
                r"microsoft.*database",
                r"sql server.*error",
                r"odbc.*driver",
                r"oledb.*provider"
            ],
            'oracle': [
                r"ora-[0-9]",
                r"oracle.*error",
                r"pl/sql.*error"
            ]
        }

    def safe_request(self, url, params=None, headers=None):
        """Make safe HTTP requests with error handling"""
        try:
            response = requests.get(
                url, 
                params=params,
                headers=headers,
                timeout=10,
                verify=False,  # For testing purposes only
                allow_redirects=False
            )
            return response
        except requests.exceptions.RequestException as e:
            return None

    def detect_sql_errors(self, response_text):
        """Detect database errors in response"""
        detected_errors = []
        
        for db_type, patterns in self.db_errors.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    detected_errors.append(db_type)
                    break
                    
        return detected_errors

    def scan_url(self, target_url):
        """Scan a single URL for SQL injection vulnerabilities"""
        findings = []
        
        print(f"    [*] Testing: {target_url}")
        
        for payload in self.sql_payloads:
            try:
                # Test in URL parameters
                test_url = f"{target_url}{payload}"
                response = self.safe_request(test_url)
                
                if response and response.status_code == 200:
                    errors = self.detect_sql_errors(response.text)
                    
                    if errors:
                        finding = {
                            'type': 'SQL Injection',
                            'url': test_url,
                            'payload': payload,
                            'risk': 'HIGH',
                            'description': f'Potential SQL Injection vulnerability detected. Database type: {", ".join(errors)}',
                            'remediation': 'Use parameterized queries and input validation',
                            'evidence': f'Database error pattern detected: {errors[0]}'
                        }
                        findings.append(finding)
                        print(f"    [!] VULNERABLE: SQLi detected with payload: {payload}")
                
                # Rate limiting
                time.sleep(0.2)
                
            except Exception as e:
                continue
                
        return findings

    def find_parameters(self, target_url):
        """Extract URL parameters for testing"""
        parsed_url = urlparse(target_url)
        query_params = []
        
        if parsed_url.query:
            # Extract existing parameters
            from urllib.parse import parse_qs
            params = parse_qs(parsed_url.query)
            query_params = list(params.keys())
        else:
            # Common parameter names for testing
            query_params = ['id', 'page', 'category', 'search', 'user', 'product']
            
        return query_params

    def scan(self, target_url):
        """Main SQL injection scanning function"""
        print(f"[*] Starting SQL Injection scan for: {target_url}")
        
        all_findings = []
        
        # Get parameters to test
        parameters = self.find_parameters(target_url)
        
        for param in parameters:
            # Test each parameter with SQL payloads
            for payload in self.sql_payloads:
                test_url = f"{target_url}?{param}={payload}"
                findings = self.scan_url(test_url)
                all_findings.extend(findings)
                
                # Brief pause between requests
                time.sleep(0.3)
        
        print(f"[+] SQL Injection scan completed. Found {len(all_findings)} potential vulnerabilities")
        return all_findings