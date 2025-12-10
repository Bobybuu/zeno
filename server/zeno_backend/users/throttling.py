"""
Custom throttling for Zeno Application
"""

from rest_framework.throttling import UserRateThrottle, AnonRateThrottle, ScopedRateThrottle


class BurstRateThrottle(UserRateThrottle):
    """
    Throttle for burst requests (per user)
    """
    scope = 'burst'
    rate = '100/hour'


class SustainedRateThrottle(UserRateThrottle):
    """
    Throttle for sustained requests (per user)
    """
    scope = 'sustained'
    rate = '1000/day'


class RegistrationThrottle(AnonRateThrottle):
    """
    Throttle for registration attempts
    """
    scope = 'registration'
    rate = '10/hour'


class LoginThrottle(AnonRateThrottle):
    """
    Throttle for login attempts
    """
    scope = 'login'
    rate = '20/hour'


class PasswordResetThrottle(AnonRateThrottle):
    """
    Throttle for password reset attempts
    """
    scope = 'password_reset'
    rate = '5/hour'


class FileUploadThrottle(UserRateThrottle):
    """
    Throttle for file uploads
    """
    scope = 'file_upload'
    rate = '50/day'


class AdminThrottle(UserRateThrottle):
    """
    Throttle for admin endpoints
    """
    scope = 'admin'
    rate = '1000/hour'


class HighTrafficThrottle(AnonRateThrottle):
    """
    Throttle for high-traffic endpoints
    """
    scope = 'high_traffic'
    rate = '1000/minute'