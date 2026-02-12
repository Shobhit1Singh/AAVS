"""
Report Generator Module
Generates detailed vulnerability reports
"""

import json
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path
from colorama import Fore, Style


class ReportGenerator:
    """
    Generates vulnerability reports in various formats
    """
    
    def __init__(self, output_dir: str = 'output/reports'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_json_report(
        self, 
        vulnerabilities: List[Dict], 
        stats: Dict,
        api_info: Dict
    ) -> str:
        """Generate JSON report"""
        
        report = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'api_name': api_info.get('title', 'Unknown API'),
                'api_version': api_info.get('version', '1.0.0'),
                'base_url': api_info.get('base_url', ''),
            },
            'summary': stats,
            'vulnerabilities': vulnerabilities,
        }
        
        filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"{Fore.GREEN}✓ JSON report saved: {filepath}{Style.RESET_ALL}")
        return str(filepath)
    
    def generate_text_report(
        self, 
        vulnerabilities: List[Dict], 
        stats: Dict,
        api_info: Dict
    ) -> str:
        """Generate human-readable text report"""
        
        lines = []
        lines.append("="*70)
        lines.append("API SECURITY VULNERABILITY REPORT")
        lines.append("="*70)
        lines.append("")
        lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"API: {api_info.get('title', 'Unknown')} v{api_info.get('version', '1.0.0')}")
        lines.append(f"Base URL: {api_info.get('base_url', 'N/A')}")
        lines.append("")
        lines.append("-"*70)
        lines.append("SUMMARY")
        lines.append("-"*70)
        lines.append(f"Total Vulnerabilities: {stats['total_vulnerabilities']}")
        lines.append("")
        lines.append("By Severity:")
        for severity, count in stats.get('by_severity', {}).items():
            lines.append(f"  {severity:10} : {count}")
        lines.append("")
        lines.append("-"*70)
        lines.append("DETAILED FINDINGS")
        lines.append("-"*70)
        lines.append("")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            lines.append(f"[{i}] {vuln['attack_type']} - {vuln['severity']}")
            lines.append(f"    Endpoint: {vuln['method']} {vuln['url']}")
            lines.append(f"    Parameter: {vuln['param_name']} ({vuln['param_location']})")
            lines.append(f"    Payload: {vuln['payload'][:100]}")
            lines.append(f"    Status Code: {vuln.get('status_code', 'N/A')}")
            
            if vuln.get('vulnerabilities'):
                lines.append("    Issues Detected:")
                for issue in vuln['vulnerabilities']:
                    lines.append(f"      • {issue['type']}: {issue['reason']}")
                    if issue.get('evidence'):
                        lines.append(f"        Evidence: {issue['evidence'][:100]}...")
            
            lines.append("")
        
        lines.append("="*70)
        lines.append("END OF REPORT")
        lines.append("="*70)
        
        filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        
        print(f"{Fore.GREEN}✓ Text report saved: {filepath}{Style.RESET_ALL}")
        return str(filepath)
    
    def generate_html_report(
        self, 
        vulnerabilities: List[Dict], 
        stats: Dict,
        api_info: Dict
    ) -> str:
        """Generate HTML report"""
        
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>API Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .vulnerability {{ background: #fff; border-left: 4px solid #e74c3c; padding: 15px; margin: 15px 0; }}
        .critical {{ border-left-color: #c0392b; }}
        .high {{ border-left-color: #e67e22; }}
        .medium {{ border-left-color: #f39c12; }}
        .low {{ border-left-color: #27ae60; }}
        .severity {{ display: inline-block; padding: 3px 8px; border-radius: 3px; color: white; font-size: 12px; }}
        .severity.critical {{ background: #c0392b; }}
        .severity.high {{ background: #e67e22; }}
        .severity.medium {{ background: #f39c12; }}
        .severity.low {{ background: #27ae60; }}
        code {{ background: #ecf0f1; padding: 2px 6px; border-radius: 3px; font-family: monospace; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #34495e; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 API Security Vulnerability Report</h1>
        
        <div class="summary">
            <p><strong>Scan Date:</strong> {scan_date}</p>
            <p><strong>API:</strong> {api_name} v{api_version}</p>
            <p><strong>Base URL:</strong> {base_url}</p>
            <p><strong>Total Vulnerabilities:</strong> <span style="color: #e74c3c; font-size: 24px; font-weight: bold;">{total_vulns}</span></p>
        </div>
        
        <h2>📊 Summary by Severity</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>Count</th>
            </tr>
            {severity_rows}
        </table>
        
        <h2>🔍 Detailed Findings</h2>
        {vulnerability_items}
        
        <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; text-align: center;">
            Generated by API Security Fuzzer | {scan_date}
        </footer>
    </div>
</body>
</html>
"""
        
        # Build severity rows
        severity_rows = ""
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = stats.get('by_severity', {}).get(severity, 0)
            if count > 0:
                severity_rows += f"<tr><td><span class='severity {severity.lower()}'>{severity}</span></td><td>{count}</td></tr>\n"
        
        # Build vulnerability items
        vulnerability_items = ""
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_class = vuln['severity'].lower()
            
            vuln_html = f"""
        <div class="vulnerability {severity_class}">
            <h3>[{i}] {vuln['attack_type']} <span class="severity {severity_class}">{vuln['severity']}</span></h3>
            <p><strong>Endpoint:</strong> <code>{vuln['method']} {vuln['url']}</code></p>
            <p><strong>Parameter:</strong> {vuln['param_name']} ({vuln['param_location']})</p>
            <p><strong>Payload:</strong> <code>{vuln['payload'][:150]}</code></p>
            <p><strong>Status Code:</strong> {vuln.get('status_code', 'N/A')}</p>
"""
            
            if vuln.get('vulnerabilities'):
                vuln_html += "<p><strong>Issues:</strong></p><ul>"
                for issue in vuln['vulnerabilities']:
                    vuln_html += f"<li><strong>{issue['type']}:</strong> {issue['reason']}</li>"
                vuln_html += "</ul>"
            
            vuln_html += "</div>\n"
            vulnerability_items += vuln_html
        
        # Fill template
        html = html_template.format(
            scan_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            api_name=api_info.get('title', 'Unknown API'),
            api_version=api_info.get('version', '1.0.0'),
            base_url=api_info.get('base_url', 'N/A'),
            total_vulns=stats['total_vulnerabilities'],
            severity_rows=severity_rows,
            vulnerability_items=vulnerability_items,
        )
        
        filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"{Fore.GREEN}✓ HTML report saved: {filepath}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Open in browser: file://{filepath.absolute()}{Style.RESET_ALL}")
        return str(filepath)