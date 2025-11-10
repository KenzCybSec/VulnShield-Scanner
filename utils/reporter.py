"""
Advanced Report Generator Module
"""

import json
import datetime
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class ReportGenerator:
    def __init__(self):
        self.name = "VulnShield Reporter"
        self.version = "1.0"
        
        # Color coding for risk levels
        self.risk_colors = {
            'CRITICAL': Fore.RED + Style.BRIGHT,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.BLUE,
            'INFO': Fore.GREEN
        }

    def generate_console_report(self, results):
        """Generate detailed console report with colors"""
        print(f"\n{Fore.CYAN + Style.BRIGHT}╔═══════════════════════════════════════════╗")
        print(f"║           VULNSHIELD SCAN REPORT           ║")
        print(f"╚═══════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"\n{Fore.WHITE}Scan Summary:")
        print(f"  Target: {results['target']}")
        print(f"  Timestamp: {results['timestamp']}")
        print(f"  Total Findings: {len(results['findings'])}")
        
        # Risk level breakdown
        risk_counts = {}
        for finding in results['findings']:
            risk = finding.get('risk', 'INFO')
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        print(f"\n{Fore.WHITE}Risk Breakdown:")
        for risk, count in risk_counts.items():
            color = self.risk_colors.get(risk, Fore.WHITE)
            print(f"  {color}{risk}: {count}{Style.RESET_ALL}")
        
        # Detailed findings
        if results['findings']:
            print(f"\n{Fore.WHITE + Style.BRIGHT}Detailed Findings:")
            print("═" * 80)
            
            for i, finding in enumerate(results['findings'], 1):
                risk_color = self.risk_colors.get(finding.get('risk', 'INFO'), Fore.WHITE)
                
                print(f"\n{Fore.CYAN}[{i}] {finding['type']}{Style.RESET_ALL}")
                print(f"    {risk_color}Risk: {finding['risk']}{Style.RESET_ALL}")
                print(f"    URL: {finding.get('url', 'N/A')}")
                print(f"    Description: {finding.get('description', 'N/A')}")
                
                if finding.get('payload'):
                    print(f"    Payload: {finding['payload']}")
                
                if finding.get('evidence'):
                    print(f"    Evidence: {finding['evidence']}")
                
                print(f"    {Fore.GREEN}Remediation: {finding.get('remediation', 'N/A')}{Style.RESET_ALL}")
                print("    " + "─" * 60)
        
        else:
            print(f"\n{Fore.GREEN}🎉 No vulnerabilities found!{Style.RESET_ALL}")
        
        # Recommendations
        self._print_recommendations(results)

    def _print_recommendations(self, results):
        """Print security recommendations"""
        print(f"\n{Fore.WHITE + Style.BRIGHT}Security Recommendations:")
        print("═" * 80)
        
        recommendations = {
            'SQL Injection': 'Implement parameterized queries and input validation',
            'Cross-Site Scripting (XSS)': 'Use Content Security Policy and output encoding',
            'Missing Security Header': 'Configure appropriate security headers',
            'File Inclusion': 'Implement path traversal protection'
        }
        
        vuln_types = set(finding['type'] for finding in results['findings'])
        
        for vuln_type in vuln_types:
            if vuln_type in recommendations:
                print(f"  {Fore.YELLOW}• {vuln_type}:{Style.RESET_ALL}")
                print(f"    {recommendations[vuln_type]}")
        
        # General recommendations
        print(f"\n{Fore.GREEN}General Best Practices:{Style.RESET_ALL}")
        general_tips = [
            "Keep all software and dependencies updated",
            "Implement Web Application Firewall (WAF)",
            "Conduct regular security assessments",
            "Follow principle of least privilege",
            "Enable logging and monitoring"
        ]
        
        for tip in general_tips:
            print(f"  • {tip}")

    def generate_html_report(self, results, filename="vulnshield_report.html"):
        """Generate professional HTML report"""
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>VulnShield Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
                .summary {{ background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .finding {{ background: white; padding: 20px; border-radius: 8px; margin-bottom: 15px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                .risk-critical {{ border-left: 5px solid #dc3545; }}
                .risk-high {{ border-left: 5px solid #fd7e14; }}
                .risk-medium {{ border-left: 5px solid #ffc107; }}
                .risk-low {{ border-left: 5px solid #20c997; }}
                .risk-info {{ border-left: 5px solid #6c757d; }}
                .recommendation {{ background: #d4edda; padding: 15px; border-radius: 5px; margin: 10px 0; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔒 VulnShield Security Assessment Report</h1>
                <p>Generated on: {results['timestamp']}</p>
            </div>
            
            <div class="summary">
                <h2>Scan Summary</h2>
                <p><strong>Target:</strong> {results['target']}</p>
                <p><strong>Findings:</strong> {len(results['findings'])} vulnerabilities detected</p>
            </div>
        """
        
        # Add findings
        if results['findings']:
            html_content += '<h2>Vulnerability Findings</h2>'
            for i, finding in enumerate(results['findings'], 1):
                risk_class = f"risk-{finding.get('risk', 'info').lower()}"
                html_content += f"""
                <div class="finding {risk_class}">
                    <h3>{i}. {finding['type']} <span style="color: #dc3545;">[{finding.get('risk', 'INFO')}]</span></h3>
                    <p><strong>URL:</strong> {finding.get('url', 'N/A')}</p>
                    <p><strong>Description:</strong> {finding.get('description', 'N/A')}</p>
                    <p><strong>Remediation:</strong> {finding.get('remediation', 'N/A')}</p>
                </div>
                """
        else:
            html_content += '<div class="finding risk-info"><h3>🎉 No vulnerabilities detected!</h3></div>'
        
        html_content += """
            </body>
            </html>
        """
        
        try:
            with open(filename, 'w', encoding='utf-8') f:
                f.write(html_content)
            return True
        except Exception as e:
            print(f"Error generating HTML report: {e}")
            return False

    def generate(self, results, output_format="console", filename=None):
        """Main report generation function"""
        if output_format == "console":
            self.generate_console_report(results)
        elif output_format == "html":
            filename = filename or f"vulnshield_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            success = self.generate_html_report(results, filename)
            if success:
                print(f"\n{Fore.GREEN}[+] HTML report generated: {filename}{Style.RESET_ALL}")
            return success
        elif output_format == "json":
            filename = filename or f"vulnshield_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            try:
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                print(f"\n{Fore.GREEN}[+] JSON report generated: {filename}{Style.RESET_ALL}")
                return True
            except Exception as e:
                print(f"{Fore.RED}Error generating JSON report: {e}{Style.RESET_ALL}")
                return False
        
        return True