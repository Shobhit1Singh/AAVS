"""
Rate Limiter
Detects and handles API rate limiting
"""

import time
from collections import deque
from typing import Optional, Dict
from colorama import Fore, Style
import logging

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Smart rate limiting with adaptive delays
    """
    
    def __init__(self, max_requests_per_second: float = 10):
        self.max_rps = max_requests_per_second
        self.min_delay = 1.0 / max_requests_per_second
        
        # Track request timestamps
        self.request_history = deque(maxlen=100)
        
        # Track rate limit responses
        self.rate_limit_hits = 0
        self.backoff_multiplier = 1.0
        
        # Adaptive settings
        self.current_delay = self.min_delay
        
    def wait_if_needed(self):
        """
        Wait before next request to respect rate limits
        """
        now = time.time()
        
        # Clean old requests (older than 1 second)
        while self.request_history and now - self.request_history[0] > 1.0:
            self.request_history.popleft()
        
        # Check if we're over the limit
        if len(self.request_history) >= self.max_rps:
            sleep_time = 1.0 - (now - self.request_history[0])
            if sleep_time > 0:
                logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
                time.sleep(sleep_time)
        
        # Apply current adaptive delay
        if self.current_delay > self.min_delay:
            time.sleep(self.current_delay)
        
        # Record this request
        self.request_history.append(time.time())
    
    def handle_rate_limit_response(self, response_headers: Dict):
        """
        Detect and handle rate limit responses
        
        Common headers:
        - X-RateLimit-Remaining
        - X-RateLimit-Reset
        - Retry-After
        """
        self.rate_limit_hits += 1
        
        # Increase backoff
        self.backoff_multiplier = min(self.backoff_multiplier * 2, 16.0)
        self.current_delay = self.min_delay * self.backoff_multiplier
        
        logger.warning(
            f"{Fore.YELLOW}Rate limit hit #{self.rate_limit_hits}. "
            f"Increasing delay to {self.current_delay:.2f}s{Style.RESET_ALL}"
        )
        
        # Check for Retry-After header
        retry_after = response_headers.get('Retry-After')
        if retry_after:
            try:
                wait_time = int(retry_after)
                logger.warning(
                    f"{Fore.YELLOW}Retry-After: {wait_time}s. Waiting...{Style.RESET_ALL}"
                )
                time.sleep(wait_time)
                return wait_time
            except:
                pass
        
        # Check for X-RateLimit-Reset
        rate_limit_reset = response_headers.get('X-RateLimit-Reset')
        if rate_limit_reset:
            try:
                reset_time = int(rate_limit_reset)
                wait_time = max(0, reset_time - time.time())
                if wait_time > 0:
                    logger.warning(
                        f"{Fore.YELLOW}Rate limit resets in {wait_time:.0f}s. Waiting...{Style.RESET_ALL}"
                    )
                    time.sleep(wait_time)
                    return wait_time
            except:
                pass
        
        # Default backoff
        backoff_time = self.current_delay * 2
        time.sleep(backoff_time)
        return backoff_time
    
    def reset_backoff(self):
        """Reset backoff when requests succeed"""
        if self.backoff_multiplier > 1.0:
            self.backoff_multiplier = max(1.0, self.backoff_multiplier * 0.5)
            self.current_delay = self.min_delay * self.backoff_multiplier
            logger.debug(f"Reduced backoff to {self.current_delay:.2f}s")
    
    def get_stats(self) -> Dict:
        """Get rate limiter statistics"""
        return {
            'rate_limit_hits': self.rate_limit_hits,
            'current_delay': self.current_delay,
            'backoff_multiplier': self.backoff_multiplier,
            'requests_in_last_second': len(self.request_history),
        }