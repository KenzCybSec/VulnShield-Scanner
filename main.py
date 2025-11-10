#!/usr/bin/env python3
"""
VulnShield Scanner - Advanced Web Security Assessment Tool
Author: Security Research Team
License: MIT
"""

import argparse
import sys
import time
from datetime import datetime

# Import custom modules
from modules.sql_scanner import SQLScanner
from modules.xss_scanner import XSSScanner
from modules.header_analyzer import HeaderAnalyzer
from utils.reporter import ReportGenerator


class VulnShieldScanner:
    def __init__(self):
        self.version = "1.0.0"
        self.banner = f"""
        ╔═══════════════════════════════════════════╗
        ║              VULNSHIELD SCANNER           ║
        ║           Advanced Security Suite         ║
        ║                 v{self.version}                 ║
        ╚═══════════════════════════════════════════╝
        """
        
        # Initialize scanners
        self.sql_scanner = SQLScanner()
        self.xss_scanner = XSSScanner()
        self.header_analyzer = HeaderAnalyzer()
        self.reporter = ReportGenerator()

    def display_banner(self):
        """Display professional banner"""
        print(self.banner)
        print(f"[+] Initialized at: {datetime.now()}")
        print("[!] LEGAL: Only use on authorized systems!\n")

    def run_scan(self, target_url, scan_type="full"):
        """Main scanning function"""
        print(f"[*] Starting scan against: {target_url}")
        
        results = {
            'target': target_url,
            'timestamp': datetime.now(),
            'findings': []
        }

        # Run security modules
        if scan_type in ["full", "sql"]:
            print("\n[+] Running SQL Injection Tests...")
            sql_results = self.sql_scanner.scan(target_url)
            results['findings'].extend(sql_results)

        if scan_type in ["full", "xss"]:
            print("[+] Running XSS Vulnerability Tests...")
            xss_results = self.xss_scanner.scan(target_url)
            results['findings'].extend(xss_results)

        if scan_type in ["full", "headers"]:
            print("[+] Analyzing Security Headers...")
            header_results = self.header_analyzer.analyze(target_url)
            results['findings'].extend(header_results)

        return results

    def generate_report(self, results, output_format="console"):
        """Generate comprehensive report"""
        return self.reporter.generate(results, output_format)


def main():
    scanner = VulnShieldScanner()
    scanner.display_banner()

    parser = argparse.ArgumentParser(description='VulnShield Security Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('--scan-type', choices=['full', 'sql', 'xss', 'headers'], 
                       default='full', help='Type of scan to perform')
    
    args = parser.parse_args()

    try:
        # Run security scan
        results = scanner.run_scan(args.url, args.scan_type)
        
        # Generate report
        if args.output:
            scanner.generate_report(results, "html")
            print(f"[+] Report saved to: {args.output}")
        else:
            scanner.generate_report(results, "console")
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error during scan: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()