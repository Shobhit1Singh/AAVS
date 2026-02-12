"""
Attack Generator Module
Generates attack test cases based on API schema
"""

from typing import Dict, List, Any, Optional
from faker import Faker
from attacks.payload import AttackPayloads
import random
import logging
from colorama import Fore, Style

logger = logging.getLogger(__name__)
fake = Faker()


class AttackGenerator:
    """
    Generates malicious test cases based on parameter types and constraints
    """
    
    def __init__(self):
        self.payloads = AttackPayloads()
        
    def generate_attacks_for_endpoint(
        self, 
        endpoint_details: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Generate all attack test cases for a specific endpoint
        
        Args:
            endpoint_details: Endpoint information from parser
            
        Returns:
            List of attack test cases
        """
        attacks = []
        
        # Attack query parameters
        for param in endpoint_details['parameters'].get('query', []):
            attacks.extend(self._generate_parameter_attacks(param, 'query'))
        
        # Attack path parameters
        for param in endpoint_details['parameters'].get('path', []):
            attacks.extend(self._generate_parameter_attacks(param, 'path'))
        
        # Attack headers
        for param in endpoint_details['parameters'].get('header', []):
            attacks.extend(self._generate_parameter_attacks(param, 'header'))
        
        # Attack request body
        if endpoint_details.get('request_body'):
            attacks.extend(self._generate_body_attacks(endpoint_details['request_body']))
        
        logger.info(f"Generated {len(attacks)} attack test cases")
        return attacks
    
    def _generate_parameter_attacks(
        self, 
        param: Dict[str, Any], 
        param_location: str
    ) -> List[Dict[str, Any]]:
        """Generate attacks for a single parameter"""
        attacks = []
        param_name = param['name']
        param_type = param.get('type', 'string')
        
        # String-based attacks
        if param_type == 'string':
            attacks.extend(self._string_attacks(param_name, param, param_location))
        
        # Integer-based attacks
        elif param_type == 'integer':
            attacks.extend(self._integer_attacks(param_name, param, param_location))
        
        # Boolean attacks
        elif param_type == 'boolean':
            attacks.extend(self._boolean_attacks(param_name, param, param_location))
        
        # Array attacks
        elif param_type == 'array':
            attacks.extend(self._array_attacks(param_name, param, param_location))
        
        # Type confusion attacks (send wrong type)
        attacks.extend(self._type_confusion_attacks(param_name, param_type, param_location))
        
        return attacks
    
    def _string_attacks(
        self, 
        param_name: str, 
        param: Dict, 
        location: str
    ) -> List[Dict]:
        """Generate string-based attacks"""
        attacks = []
        
        # SQL Injection
        for payload in self.payloads.SQL_INJECTION[:5]:  # Top 5
            attacks.append({
                'attack_type': 'SQL Injection',
                'severity': 'CRITICAL',
                'param_name': param_name,
                'param_location': location,
                'payload': payload,
                'expected_safe_behavior': 'Reject malicious SQL syntax',
            })
        
        # XSS
        for payload in self.payloads.XSS_PAYLOADS[:3]:
            attacks.append({
                'attack_type': 'XSS',
                'severity': 'HIGH',
                'param_name': param_name,
                'param_location': location,
                'payload': payload,
                'expected_safe_behavior': 'Sanitize or escape HTML',
            })
        
        # Command Injection
        for payload in self.payloads.COMMAND_INJECTION[:3]:
            attacks.append({
                'attack_type': 'Command Injection',
                'severity': 'CRITICAL',
                'param_name': param_name,
                'param_location': location,
                'payload': payload,
                'expected_safe_behavior': 'Reject shell metacharacters',
            })
        
        # Path Traversal
        for payload in self.payloads.PATH_TRAVERSAL[:3]:
            attacks.append({
                'attack_type': 'Path Traversal',
                'severity': 'HIGH',
                'param_name': param_name,
                'param_location': location,
                'payload': payload,
                'expected_safe_behavior': 'Block directory traversal',
            })
        
        # Length boundary attacks
        if param.get('max_length'):
            max_len = param['max_length']
            attacks.append({
                'attack_type': 'Buffer Overflow',
                'severity': 'MEDIUM',
                'param_name': param_name,
                'param_location': location,
                'payload': 'A' * (max_len * 2),
                'expected_safe_behavior': f'Reject strings longer than {max_len}',
            })
            attacks.append({
                'attack_type': 'Boundary Test',
                'severity': 'LOW',
                'param_name': param_name,
                'param_location': location,
                'payload': 'A' * (max_len + 1),
                'expected_safe_behavior': f'Reject at max_length + 1',
            })
        
        # Pattern violation (if pattern exists)
        if param.get('pattern'):
            attacks.append({
                'attack_type': 'Pattern Violation',
                'severity': 'MEDIUM',
                'param_name': param_name,
                'param_location': location,
                'payload': '!@#$%^&*()',
                'expected_safe_behavior': f'Reject pattern mismatch',
            })
        
        # Email-specific attacks
        if param.get('format') == 'email':
            for payload in self.payloads.EMAIL_ATTACKS[:2]:
                attacks.append({
                    'attack_type': 'Email Header Injection',
                    'severity': 'HIGH',
                    'param_name': param_name,
                    'param_location': location,
                    'payload': payload,
                    'expected_safe_behavior': 'Reject malformed emails',
                })
        
        return attacks
    
    def _integer_attacks(
        self, 
        param_name: str, 
        param: Dict, 
        location: str
    ) -> List[Dict]:
        """Generate integer-based attacks"""
        attacks = []
        
        # Integer overflow/underflow
        for payload in self.payloads.INTEGER_ATTACKS:
            attacks.append({
                'attack_type': 'Integer Overflow/Underflow',
                'severity': 'MEDIUM',
                'param_name': param_name,
                'param_location': location,
                'payload': payload,
                'expected_safe_behavior': 'Handle extreme integers safely',
            })
        
        # Boundary tests
        if param.get('minimum') is not None:
            attacks.append({
                'attack_type': 'Boundary Violation',
                'severity': 'MEDIUM',
                'param_name': param_name,
                'param_location': location,
                'payload': param['minimum'] - 1,
                'expected_safe_behavior': f'Reject values < {param["minimum"]}',
            })
        
        if param.get('maximum') is not None:
            attacks.append({
                'attack_type': 'Boundary Violation',
                'severity': 'MEDIUM',
                'param_name': param_name,
                'param_location': location,
                'payload': param['maximum'] + 1,
                'expected_safe_behavior': f'Reject values > {param["maximum"]}',
            })
        
        return attacks
    
    def _boolean_attacks(
        self, 
        param_name: str, 
        param: Dict, 
        location: str
    ) -> List[Dict]:
        """Generate boolean attacks"""
        attacks = []
        
        # Type confusion for booleans
        for payload in ['yes', 'no', '1', '0', 'TRUE', 'FALSE', None]:
            attacks.append({
                'attack_type': 'Type Confusion',
                'severity': 'LOW',
                'param_name': param_name,
                'param_location': location,
                'payload': payload,
                'expected_safe_behavior': 'Accept only true/false',
            })
        
        return attacks
    
    def _array_attacks(
        self, 
        param_name: str, 
        param: Dict, 
        location: str
    ) -> List[Dict]:
        """Generate array-based attacks"""
        attacks = []
        
        # Empty array
        attacks.append({
            'attack_type': 'Empty Array',
            'severity': 'LOW',
            'param_name': param_name,
            'param_location': location,
            'payload': [],
            'expected_safe_behavior': 'Handle empty arrays gracefully',
        })
        
        # Huge array (DoS)
        attacks.append({
            'attack_type': 'Resource Exhaustion',
            'severity': 'HIGH',
            'param_name': param_name,
            'param_location': location,
            'payload': list(range(100000)),
            'expected_safe_behavior': 'Limit array size',
        })
        
        return attacks
    
    def _type_confusion_attacks(
        self, 
        param_name: str, 
        expected_type: str, 
        location: str
    ) -> List[Dict]:
        """Send wrong types to confuse the API"""
        attacks = []
        
        wrong_types = {
            'string': [123, True, None, [], {}],
            'integer': ['not_a_number', True, None, [], {}],
            'boolean': ['yes', 1, 0, None],
            'array': ['not_an_array', 123, True],
            'object': ['not_an_object', 123, []],
        }
        
        for payload in wrong_types.get(expected_type, []):
            attacks.append({
                'attack_type': 'Type Confusion',
                'severity': 'MEDIUM',
                'param_name': param_name,
                'param_location': location,
                'payload': payload,
                'expected_safe_behavior': f'Reject non-{expected_type} values',
            })
        
        return attacks
    
    def _generate_body_attacks(self, request_body: Dict) -> List[Dict]:
        """Generate attacks for request body"""
        attacks = []
        
        # Get JSON schema
        json_schema = request_body.get('content', {}).get('application/json', {}).get('schema', {})
        
        if not json_schema:
            return attacks
        
        # Extract properties
        properties = json_schema.get('properties', {})
        required = json_schema.get('required', [])
        
        for prop_name, prop_details in properties.items():
            prop_type = prop_details.get('type', 'string')
            
            # Similar attacks as parameters
            if prop_type == 'string':
                attacks.extend(self._string_attacks(prop_name, prop_details, 'body'))
            elif prop_type == 'integer':
                attacks.extend(self._integer_attacks(prop_name, prop_details, 'body'))
        
        # Missing required fields
        for req_field in required:
            attacks.append({
                'attack_type': 'Missing Required Field',
                'severity': 'MEDIUM',
                'param_name': req_field,
                'param_location': 'body',
                'payload': '<MISSING>',
                'expected_safe_behavior': f'Reject request missing {req_field}',
            })
        
        return attacks
    
    def print_attack_summary(self, attacks: List[Dict]):
        """Print a nice summary of generated attacks"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"GENERATED ATTACK TEST CASES")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        # Count by type
        attack_types = {}
        for attack in attacks:
            atype = attack['attack_type']
            attack_types[atype] = attack_types.get(atype, 0) + 1
        
        print(f"{Fore.YELLOW}Total Attacks:{Style.RESET_ALL} {len(attacks)}\n")
        
        for atype, count in sorted(attack_types.items(), key=lambda x: -x[1]):
            print(f"  {atype:30} : {count}")
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")