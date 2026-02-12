"""
Response Analyzer Module
Analyzes API responses to detect vulnerabilities
"""

import re
import logging
from typing import Dict, List, Any
from colorama import Fore, Style

logger = logging.getLogger(__name__)


class ResponseAnalyzer:
    """
    Analyzes API responses to detect security vulnerabilities
    """
    
    # Error patterns that indicate vulnerabilities
    ERROR_PATTERNS = {
        'sql_error': [
            r'SQL syntax',
            r'mysql_fetch',
            r'ORA-\d+',
            r'PostgreSQL.*ERROR',
            r'SQLite.*error',
            r'Microsoft SQL Server',
            r'ODBC.*Driver',
            r'syntax error at or near',
        ],
        'stack_trace': [
            r'Traceback \(most recent call last\)',
            r'at [A-Za-z0-9.]+\([A-Za-z0-9.]+\.java:\d+\)',
            r'File ".*", line \d+',
            r'Exception in thread',
            r'\.java:\d+\)',
        ],
        'path_disclosure': [
            r'[A-Z]:\\[\w\\]+',  # Windows paths
            r'/var/www/',
            r'/home/[\w/]+',
            r'/usr/[\w/]+',
            r'C:\\\\',
        ],
        'database_info': [
            r'Table \'[\w]+\' doesn\'t exist',
            r'Unknown column',
            r'Undeclared variable',
        ],
        'debug_info': [
            r'DEBUG:',
            r'var_dump',
            r'print_r\(',
            r'console\.log',
        ],
    }
    
    # Dangerous headers that shouldn't be exposed
    DANGEROUS_HEADERS = [
        'X-Powered-By',
        'Server',
        'X-AspNet-Version',
        'X-AspNetMvc-Version',
    ]
    
    def __init__(self):
        self.vulnerabilities = []
    
    def analyze_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a single test result for vulnerabilities
        
        Args:
            result: Test result from executor
            
        Returns:
            Analysis with vulnerability detection
        """
        if not result.get('success'):
            # Already marked as vulnerable (timeout/crash)
            if result.get('vulnerability_detected'):
                self.vulnerabilities.append(result)
            return result
        
        vulnerabilities_found = []
        
        # Check 1: Unexpected status codes
        status_code = result.get('status_code', 0)
        
        if status_code == 500:
            vulnerabilities_found.append({
                'type': 'Server Error',
                'severity': 'HIGH',
                'reason': 'Server returned 500 - payload caused internal error',
            })
        
        # Check 2: Response body analysis
        response_body = result.get('response_body', '')
        
        for error_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    vulnerabilities_found.append({
                        'type': f'Information Disclosure ({error_type})',
                        'severity': 'CRITICAL' if error_type == 'sql_error' else 'HIGH',
                        'reason': f'Response contains {error_type}: {pattern}',
                        'evidence': self._extract_evidence(response_body, pattern)
                    })
        
        # Check 3: Response timing anomalies
        response_time = result.get('response_time', 0)
        
        if response_time > 5.0:  # Suspiciously slow
            vulnerabilities_found.append({
                'type': 'Timing Anomaly',
                'severity': 'MEDIUM',
                'reason': f'Response took {response_time:.2f}s - possible time-based injection',
            })
        
        # Check 4: Dangerous headers
        response_headers = result.get('response_headers', {})
        
        for dangerous_header in self.DANGEROUS_HEADERS:
            if dangerous_header in response_headers:
                vulnerabilities_found.append({
                    'type': 'Information Disclosure (Headers)',
                    'severity': 'LOW',
                    'reason': f'Exposed header: {dangerous_header} = {response_headers[dangerous_header]}',
                })
        
        # Check 5: Unexpected success
        if status_code == 200 and result['attack_type'] in ['SQL Injection', 'Command Injection']:
            # Successful request with malicious payload is suspicious
            if "' OR '1'='1" in str(result.get('payload', '')):
                vulnerabilities_found.append({
                    'type': 'Possible SQL Injection',
                    'severity': 'CRITICAL',
                    'reason': 'Malicious SQL payload was accepted without error',
                })
        
        # Check 6: Missing required field accepted
        if result['attack_type'] == 'Missing Required Field' and status_code == 200:
            vulnerabilities_found.append({
                'type': 'Validation Bypass',
                'severity': 'MEDIUM',
                'reason': f'Required field "{result["param_name"]}" was not enforced',
            })
        
        # Check 7: Boundary violations accepted
        if result['attack_type'] == 'Boundary Violation' and status_code == 200:
            vulnerabilities_found.append({
                'type': 'Input Validation Failure',
                'severity': 'MEDIUM',
                'reason': 'Boundary constraint was not enforced',
            })
        
        # Update result with findings
        if vulnerabilities_found:
            result['vulnerability_detected'] = True
            result['vulnerabilities'] = vulnerabilities_found
            self.vulnerabilities.append(result)
            
            # Log findings
            logger.warning(
                f"{Fore.YELLOW}Vulnerability detected: {result['attack_type']} "
                f"on {result['param_name']} - {len(vulnerabilities_found)} issues{Style.RESET_ALL}"
            )
        else:
            result['vulnerability_detected'] = False
        
        return result
    
    def _extract_evidence(self, text: str, pattern: str, context_chars: int = 100) -> str:
        """Extract evidence snippet from response"""
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            start = max(0, match.start() - context_chars)
            end = min(len(text), match.end() + context_chars)
            return text[start:end]
        return ""
    
    def analyze_all_results(self, results: List[Dict]) -> List[Dict]:
        """Analyze all test results"""
        print(f"\n{Fore.CYAN}Analyzing {len(results)} test results...{Style.RESET_ALL}\n")
        
        analyzed = []
        for result in results:
            analyzed.append(self.analyze_result(result))
        
        vuln_count = len(self.vulnerabilities)
        
        if vuln_count > 0:
            print(f"{Fore.RED}⚠ Found {vuln_count} potential vulnerabilities{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.GREEN}✓ No vulnerabilities detected{Style.RESET_ALL}\n")
        
        return analyzed
    
    def get_vulnerabilities(self) -> List[Dict]:
        """Get all detected vulnerabilities"""
        return self.vulnerabilities
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics"""
        if not self.vulnerabilities:
            return {
                'total_vulnerabilities': 0,
                'by_severity': {},
                'by_type': {},
            }
        
        # Count by severity
        by_severity = {}
        by_type = {}
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            attack_type = vuln.get('attack_type', 'UNKNOWN')
            
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_type[attack_type] = by_type.get(attack_type, 0) + 1
        
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'by_severity': by_severity,
            'by_type': by_type,
        }
    
    def print_summary(self):
        """Print vulnerability summary"""
        stats = self.get_statistics()
        
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"VULNERABILITY ANALYSIS SUMMARY")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}Total Vulnerabilities Found:{Style.RESET_ALL} {stats['total_vulnerabilities']}\n")
        
        if stats['total_vulnerabilities'] == 0:
            print(f"{Fore.GREEN}No vulnerabilities detected. API appears secure against tested attacks.{Style.RESET_ALL}\n")
            return
        
        print(f"{Fore.RED}By Severity:{Style.RESET_ALL}")
        for severity, count in sorted(stats['by_severity'].items(), 
                                     key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].index(x[0]) if x[0] in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] else 999):
            color = {
                'CRITICAL': Fore.RED,
                'HIGH': Fore.YELLOW,
                'MEDIUM': Fore.BLUE,
                'LOW': Fore.GREEN,
            }.get(severity, Fore.WHITE)
            print(f"  {color}{severity:10}{Style.RESET_ALL} : {count}")
        
        print(f"\n{Fore.RED}By Attack Type:{Style.RESET_ALL}")
        for attack_type, count in sorted(stats['by_type'].items(), key=lambda x: -x[1])[:10]:
            print(f"  {attack_type:30} : {count}")
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")