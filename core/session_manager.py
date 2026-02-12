"""
Session Manager
Handles authentication flows and session persistence
"""

import requests
import jwt
import time
from typing import Dict, Optional, Any
from colorama import Fore, Style
import logging

logger = logging.getLogger(__name__)


class SessionManager:
    """
    Manages authentication sessions across multiple API requests
    """
    
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.auth_token = None
        self.auth_type = None  # 'bearer', 'api_key', 'basic', 'cookie'
        self.token_expiry = None
        
    def authenticate_basic(self, username: str, password: str) -> bool:
        """
        Authenticate using HTTP Basic Auth
        """
        try:
            self.session.auth = (username, password)
            self.auth_type = 'basic'
            logger.info(f"{Fore.GREEN}✓ Basic auth configured{Style.RESET_ALL}")
            return True
        except Exception as e:
            logger.error(f"{Fore.RED}Basic auth failed: {e}{Style.RESET_ALL}")
            return False
    
    def authenticate_bearer(self, token: str) -> bool:
        """
        Authenticate using Bearer token (JWT)
        """
        try:
            self.auth_token = token
            self.session.headers.update({'Authorization': f'Bearer {token}'})
            self.auth_type = 'bearer'
            
            # Try to decode JWT to get expiry
            try:
                decoded = jwt.decode(token, options={"verify_signature": False})
                if 'exp' in decoded:
                    self.token_expiry = decoded['exp']
                    logger.info(f"{Fore.GREEN}✓ Bearer token configured (expires: {time.ctime(self.token_expiry)}){Style.RESET_ALL}")
                else:
                    logger.info(f"{Fore.GREEN}✓ Bearer token configured (no expiry){Style.RESET_ALL}")
            except:
                logger.info(f"{Fore.GREEN}✓ Bearer token configured{Style.RESET_ALL}")
            
            return True
        except Exception as e:
            logger.error(f"{Fore.RED}Bearer auth failed: {e}{Style.RESET_ALL}")
            return False
    
    def authenticate_api_key(self, api_key: str, header_name: str = 'X-API-Key') -> bool:
        """
        Authenticate using API Key
        """
        try:
            self.session.headers.update({header_name: api_key})
            self.auth_type = 'api_key'
            logger.info(f"{Fore.GREEN}✓ API key configured ({header_name}){Style.RESET_ALL}")
            return True
        except Exception as e:
            logger.error(f"{Fore.RED}API key auth failed: {e}{Style.RESET_ALL}")
            return False
    
    def authenticate_login(self, login_url: str, credentials: Dict[str, str]) -> bool:
        """
        Authenticate via login endpoint (POST username/password, get token)
        """
        try:
            full_url = f"{self.base_url}{login_url}"
            response = self.session.post(full_url, json=credentials)
            
            if response.status_code == 200:
                data = response.json()
                
                # Try to find token in response
                token = data.get('token') or data.get('access_token') or data.get('jwt')
                
                if token:
                    return self.authenticate_bearer(token)
                else:
                    # Maybe cookies were set
                    if self.session.cookies:
                        self.auth_type = 'cookie'
                        logger.info(f"{Fore.GREEN}✓ Cookie-based auth configured{Style.RESET_ALL}")
                        return True
                    
                logger.error(f"{Fore.RED}Login succeeded but no token found{Style.RESET_ALL}")
                return False
            else:
                logger.error(f"{Fore.RED}Login failed: {response.status_code}{Style.RESET_ALL}")
                return False
                
        except Exception as e:
            logger.error(f"{Fore.RED}Login auth failed: {e}{Style.RESET_ALL}")
            return False
    
    def is_token_expired(self) -> bool:
        """Check if current token is expired"""
        if not self.token_expiry:
            return False
        
        return time.time() > self.token_expiry
    
    def refresh_token_if_needed(self, refresh_url: str = None) -> bool:
        """
        Refresh token if expired
        (Placeholder - implement based on your API's refresh mechanism)
        """
        if not self.is_token_expired():
            return True
        
        logger.warning(f"{Fore.YELLOW}Token expired, refresh needed{Style.RESET_ALL}")
        
        # TODO: Implement refresh logic based on API
        # This would typically involve calling a /refresh endpoint
        # with a refresh_token
        
        return False
    
    def get_authenticated_session(self) -> requests.Session:
        """Get the configured session object"""
        return self.session
    
    def clear_auth(self):
        """Clear all authentication"""
        self.session = requests.Session()
        self.auth_token = None
        self.auth_type = None
        self.token_expiry = None
        logger.info(f"{Fore.YELLOW}Authentication cleared{Style.RESET_ALL}")