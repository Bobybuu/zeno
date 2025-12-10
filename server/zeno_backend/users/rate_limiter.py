from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)

class OTPRateLimiter:
    def __init__(self):
        self.limit = 3  # Max 3 requests per hour
        self.window = 3600  # 1 hour in seconds
    
    def _get_cache_key(self, phone_number):
        """Generate cache key for rate limiting"""
        return f"otp_rate_limit:{phone_number}"
    
    def is_rate_limited(self, phone_number):
        """
        Check if phone number has exceeded rate limit
        Returns: (is_limited, retry_after_seconds)
        """
        cache_key = self._get_cache_key(phone_number)
        requests_data = cache.get(cache_key, [])
        
        # Remove expired timestamps (older than 1 hour)
        now = timezone.now()
        cutoff_time = now - timedelta(seconds=self.window)
        valid_requests = [ts for ts in requests_data if ts > cutoff_time]
        
        # Check if limit exceeded
        if len(valid_requests) >= self.limit:
            # Calculate when the oldest request will expire
            if valid_requests:
                oldest_request = min(valid_requests)
                retry_after = int((oldest_request + timedelta(seconds=self.window) - now).total_seconds())
                return True, max(0, retry_after)
            return True, self.window
        
        return False, 0
    
    def record_request(self, phone_number):
        """Record an OTP request for rate limiting"""
        cache_key = self._get_cache_key(phone_number)
        requests_data = cache.get(cache_key, [])
        
        now = timezone.now()
        requests_data.append(now)
        
        # Keep only requests from the last hour
        cutoff_time = now - timedelta(seconds=self.window)
        valid_requests = [ts for ts in requests_data if ts > cutoff_time]
        
        # Store in cache with expiration
        cache.set(cache_key, valid_requests, self.window)
        
        logger.info(f"OTP request recorded for {phone_number}. {len(valid_requests)}/{self.limit} requests in last hour.")
    
    def get_remaining_attempts(self, phone_number):
        """Get remaining OTP attempts for phone number"""
        cache_key = self._get_cache_key(phone_number)
        requests_data = cache.get(cache_key, [])
        
        # Remove expired timestamps
        now = timezone.now()
        cutoff_time = now - timedelta(seconds=self.window)
        valid_requests = [ts for ts in requests_data if ts > cutoff_time]
        
        remaining = self.limit - len(valid_requests)
        return max(0, remaining)

# Global instance
otp_rate_limiter = OTPRateLimiter()