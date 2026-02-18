"""
Attack Executor Module
Sends attack payloads to the API and captures responses
"""

import requests
import time
import logging
from typing import Dict, List, Any, Optional
from colorama import Fore, Style
from urllib.parse import urljoin
import json

logger = logging.getLogger(__name__)


class TestExecutor:
    """
    Executes attack test cases against a live API
    """
    
    def __init__(self, base_url: str, headers: Optional[Dict] = None, timeout: int = 10):
        """
        Initialize the executor
        
        Args:
            base_url: Base URL of the API (e.g., 'https://api.example.com/v1')
            headers: Optional default headers (auth tokens, etc.)
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.default_headers = headers or {}
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(self.default_headers)
        
        # Results storage
        self.results = []
        
    def execute_attack(
        self, 
        attack: Dict[str, Any], 
        endpoint_path: str, 
        method: str
    ) -> Dict[str, Any]:
        """
        Execute a single attack test case
        
        Args:
            attack: Attack test case from generator
            endpoint_path: API endpoint path (e.g., '/users')
            method: HTTP method (GET, POST, etc.)
            
        Returns:
            Test result with response data
        """
        # Build full URL
        url = self.base_url.rstrip("/") + "/" +  endpoint_path.lstrip("/")
        
        # Prepare request based on parameter location
        params = {}
        headers = self.default_headers.copy()
        body = None
        
        # Inject payload based on location
        param_location = attack.get('param_location', 'body')
        param_name = attack.get('param_name', '')
        payload = attack.get('payload', '')
        
        if param_location == 'query':
            params[param_name] = payload
        elif param_location == 'header':
            headers[param_name] = str(payload)
        elif param_location == 'path':
            # Replace path parameter
            url = url.replace(f'{{{param_name}}}', str(payload))
        elif param_location == 'body':
            # For body attacks, we need to build a complete valid body
            # with just this field being malicious
            body = {param_name: payload}
        
        # Execute request
        result = {
            'attack_type': attack['attack_type'],
            'severity': attack['severity'],
            'param_name': param_name,
            'param_location': param_location,
            'payload': str(payload)[:200],  # Truncate for logging
            'url': url,
            'method': method,
            'timestamp': time.time(),
        }
        
        try:
            # Measure response time
            start_time = time.time()
            
            # Send request
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                headers=headers,
                json=body if body else None,
                timeout=self.timeout,
                allow_redirects=False  # Don't follow redirects automatically
            )
            
            end_time = time.time()
            response_time = end_time - start_time
            
            # Capture response details
            result.update({
                'status_code': response.status_code,
                'response_time': response_time,
                'response_headers': dict(response.headers),
                'response_body': response.text[:5000],  # First 5000 chars
                'response_size': len(response.content),
                'success': True,
            })
            
            logger.debug(f"Attack executed: {attack['attack_type']} -> {response.status_code}")
            
        except requests.exceptions.Timeout:
            result.update({
                'status_code': 0,
                'error': 'Request timeout',
                'success': False,
                'vulnerability_detected': True,  # Timeout might indicate DoS
                'vulnerability_reason': 'Request timed out - possible DoS vulnerability'
            })
            logger.warning(f"{Fore.YELLOW}Timeout on {attack['attack_type']}{Style.RESET_ALL}")
            
        except requests.exceptions.ConnectionError as e:
            result.update({
                'status_code': 0,
                'error': f'Connection error: {str(e)}',
                'success': False,
                'vulnerability_detected': True,
                'vulnerability_reason': 'Server crashed or became unreachable'
            })
            logger.error(f"{Fore.RED}Connection error on {attack['attack_type']}{Style.RESET_ALL}")
            
        except Exception as e:
            result.update({
                'status_code': 0,
                'error': str(e),
                'success': False,
            })
            logger.error(f"{Fore.RED}Error executing attack: {e}{Style.RESET_ALL}")
        
        self.results.append(result)
        return result
    
    def execute_all_attacks(
        self, 
        attacks: List[Dict], 
        endpoint_path: str, 
        method: str,
        delay: float = 0.1
    ) -> List[Dict]:
        """
        Execute all attack test cases for an endpoint
        
        Args:
            attacks: List of attack test cases
            endpoint_path: API endpoint path
            method: HTTP method
            delay: Delay between requests (to avoid rate limiting)
            
        Returns:
            List of test results
        """
        print(f"\n{Fore.CYAN}Executing {len(attacks)} attacks against {method} {endpoint_path}...{Style.RESET_ALL}\n")
        
        results = []
        for i, attack in enumerate(attacks, 1):
            # Progress indicator
            print(f"[{i}/{len(attacks)}] {attack['attack_type']}...", end='\r')
            
            # Execute attack
            result = self.execute_attack(attack, endpoint_path, method)
            results.append(result)
            
            # Delay between requests
            time.sleep(delay)
        
        print(f"\n{Fore.GREEN}✓ Completed {len(attacks)} attacks{Style.RESET_ALL}\n")
        return results
    
    def get_results(self) -> List[Dict]:
        """Get all test results"""
        return self.results
    
    def clear_results(self):
        """Clear stored results"""
        self.results = []