"""
models.py for Zeno Application
Robust implementation with best practices for authentication, authorization, and data modeling
"""

import uuid
import hashlib
import logging
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from django.core.validators import MinLengthValidator, RegexValidator
from django.core.exceptions import ValidationError
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.contrib.postgres.fields import ArrayField
from django.db.models import JSONField

# Local imports
from .validators import validate_phone_number, validate_coordinates
from .managers import UserManager, VendorManager, ServiceManager

logger = logging.getLogger(__name__)


class TimestampMixin(models.Model):
    """Abstract base model for timestamp tracking"""
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True, db_index=True)
    
    class Meta:
        abstract = True


class SoftDeleteMixin(models.Model):
    """Abstract base model for soft deletion"""
    is_deleted = models.BooleanField(default=False, db_index=True)
    deleted_at = models.DateTimeField(null=True, blank=True)
    
    def soft_delete(self):
        """Soft delete the instance"""
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save()
    
    def restore(self):
        """Restore a soft-deleted instance"""
        self.is_deleted = False
        self.deleted_at = None
        self.save()
    
    class Meta:
        abstract = True


class AddressMixin(models.Model):
    """Abstract base model for address information"""
    address_line1 = models.CharField(max_length=255, blank=True)
    address_line2 = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=100, blank=True)
    country = models.CharField(max_length=100, default='Kenya')
    postal_code = models.CharField(max_length=20, blank=True)
    latitude = models.DecimalField(
        max_digits=10, 
        decimal_places=8, 
        null=True, 
        blank=True,
        validators=[validate_coordinates]
    )
    longitude = models.DecimalField(
        max_digits=11, 
        decimal_places=8, 
        null=True, 
        blank=True,
        validators=[validate_coordinates]
    )
    
    @property
    def full_address(self):
        """Return formatted full address"""
        parts = [self.address_line1]
        if self.address_line2:
            parts.append(self.address_line2)
        parts.extend([self.city, self.state, self.country])
        return ', '.join(filter(None, parts))
    
    class Meta:
        abstract = True


class User(AbstractUser, TimestampMixin, SoftDeleteMixin):
    """
    Enhanced User model with robust authentication and authorization
    Supports JWT + Session + Secure HttpOnly Cookies
    """
    
    class UserType(models.TextChoices):
        CUSTOMER = 'customer', _('Customer')
        VENDOR = 'vendor', _('Vendor')
        MECHANIC = 'mechanic', _('Mechanic')
        ADMIN = 'admin', _('Admin')
        SUPER_ADMIN = 'super_admin', _('Super Admin')
    
    # Core identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(
        _('email address'),
        unique=True,
        db_index=True,
        error_messages={
            'unique': _("A user with that email already exists."),
        }
    )
    username = models.CharField(
        _('username'),
        max_length=150,
        blank=True,
        null=True,
        help_text=_('Optional username for display purposes')
    )
    
    # Replace phone verification with AWS Cognito email verification
    cognito_user_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        unique=True,
        db_index=True,
        help_text=_('AWS Cognito User ID')
    )
    email_verified = models.BooleanField(
        default=False,
        help_text=_('Designates whether this user has verified their email via AWS Cognito')
    )
    
    # User type and profile
    user_type = models.CharField(
        max_length=20,
        choices=UserType.choices,
        default=UserType.CUSTOMER,
        db_index=True
    )
    phone_number = models.CharField(
        max_length=15,
        blank=True,
        validators=[validate_phone_number],
        help_text=_('Format: +254XXXXXXXXX')
    )
    
    # Location and profile
    location = models.CharField(max_length=255, blank=True)
    profile_picture = models.ImageField(
        upload_to='profile_pictures/%Y/%m/%d/',
        null=True,
        blank=True,
        max_length=500
    )
    
    # Security and authentication
    mfa_enabled = models.BooleanField(default=False)
    mfa_secret = models.CharField(max_length=100, blank=True, null=True, editable=False)
    failed_login_attempts = models.IntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    current_login_ip = models.GenericIPAddressField(null=True, blank=True)
    
    # Session management
    session_key = models.CharField(max_length=40, blank=True, null=True)
    session_expiry = models.DateTimeField(null=True, blank=True)
    
    # JWT token tracking
    jwt_refresh_token = models.CharField(max_length=500, blank=True, null=True, editable=False)
    jwt_refresh_token_expiry = models.DateTimeField(null=True, blank=True)
    
    # Preferences and settings
    preferences = JSONField(
        default=dict,
        blank=True,
        help_text=_('User preferences and settings')
    )
    notification_settings = JSONField(
        default=dict,
        blank=True,
        help_text=_('Notification preferences')
    )
    
    # Audit fields
    created_by_ip = models.GenericIPAddressField(null=True, blank=True)
    last_accessed_ip = models.GenericIPAddressField(null=True, blank=True)
    last_password_change = models.DateTimeField(default=timezone.now)
    
    # Custom manager
    objects = UserManager()
    
    # Set email as the username field
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')
        db_table = 'users'
        indexes = [
            models.Index(fields=['email', 'is_active']),
            models.Index(fields=['user_type', 'is_active']),
            models.Index(fields=['created_at']),
            models.Index(fields=['is_deleted']),
        ]
        ordering = ['-created_at']
        permissions = [
            ('can_manage_vendors', 'Can manage vendors'),
            ('can_manage_services', 'Can manage services'),
            ('can_view_analytics', 'Can view analytics'),
        ]
    
    def __str__(self):
        return f"{self.email} ({self.get_user_type_display()})"
    
    def clean(self):
        """Custom model validation"""
        # Call parent clean method
        super().clean()
        
        # Normalize email using the User manager
        if self.email:
            self.email = self.__class__.objects.normalize_email(self.email)
        
        # Validate phone number if provided
        if self.phone_number:
            try:
                validate_phone_number(self.phone_number)
            except ValidationError as e:
                raise ValidationError({'phone_number': str(e)})
        
        # Only check uniqueness for existing users
        if self.pk is not None:
            try:
                original = User.objects.get(pk=self.pk)
                
                # Check if email is being changed
                if original.email.lower() != self.email.lower():
                    if User.objects.filter(email__iexact=self.email).exclude(pk=self.pk).exists():
                        raise ValidationError({
                            'email': 'A user with this email already exists.'
                        })
                
                # Check if username is being changed
                if self.username and original.username != self.username:
                    if User.objects.filter(username=self.username).exclude(pk=self.pk).exists():
                        raise ValidationError({
                            'username': 'A user with this username already exists.'
                        })
                
                # Check if phone number is being changed
                if self.phone_number and original.phone_number != self.phone_number:
                    if User.objects.filter(phone_number=self.phone_number).exclude(pk=self.pk).exists():
                        raise ValidationError({
                            'phone_number': 'A user with this phone number already exists.'
                        })
                        
            except User.DoesNotExist:
                # This shouldn't happen for existing users, but handle gracefully
                pass
        else:
            # For new users, check if email/username/phone already exist
            if self.email and User.objects.filter(email__iexact=self.email).exists():
                raise ValidationError({
                    'email': 'A user with this email already exists.'
                })
            
            if self.username and User.objects.filter(username=self.username).exists():
                raise ValidationError({
                    'username': 'A user with this username already exists.'
                })
            
            if self.phone_number and User.objects.filter(phone_number=self.phone_number).exists():
                raise ValidationError({
                    'phone_number': 'A user with this phone number already exists.'
            })
    
    def save(self, *args, **kwargs):
        """Override save to handle special cases"""
        self.clean()
        super().save(*args, **kwargs)
    
    def get_full_name(self):
        """Return the user's full name"""
        full_name = f'{self.first_name} {self.last_name}'.strip()
        return full_name or self.email
    
    def get_short_name(self):
        """Return the user's short name"""
        return self.first_name or self.email.split('@')[0]
    
    def is_account_locked(self):
        """Check if account is locked due to too many failed attempts"""
        if not self.account_locked_until:
            return False
        
        if timezone.now() < self.account_locked_until:
            return True
        
        # Reset if lock time has passed
        self.account_locked_until = None
        self.failed_login_attempts = 0
        self.save(update_fields=['account_locked_until', 'failed_login_attempts'])
        return False
    
    def record_failed_login(self, ip_address: Optional[str] = None):
        """Record failed login attempt"""
        self.failed_login_attempts += 1
        
        # Lock account after 5 failed attempts for 30 minutes
        if self.failed_login_attempts >= 5:
            self.account_locked_until = timezone.now() + timedelta(minutes=30)
            logger.warning(f'Account {self.email} locked due to failed login attempts')
        
        self.last_accessed_ip = ip_address
        self.save(
            update_fields=[
                'failed_login_attempts',
                'account_locked_until',
                'last_accessed_ip'
            ]
        )
    
    def reset_failed_logins(self):
        """Reset failed login attempts"""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.save(update_fields=['failed_login_attempts', 'account_locked_until'])
    
    def update_session(self, session_key: str, expiry: datetime, ip_address: str):
        """Update user session information"""
        self.session_key = session_key
        self.session_expiry = expiry
        self.current_login_ip = ip_address
        self.last_login = timezone.now()
        self.save(
            update_fields=[
                'session_key',
                'session_expiry',
                'current_login_ip',
                'last_login'
            ]
        )
    
    def invalidate_session(self):
        """Invalidate current session"""
        self.session_key = None
        self.session_expiry = None
        self.save(update_fields=['session_key', 'session_expiry'])
    
    def update_jwt_refresh_token(self, refresh_token: str, expiry: datetime):
        """Update JWT refresh token"""
        self.jwt_refresh_token = refresh_token
        self.jwt_refresh_token_expiry = expiry
        self.save(update_fields=['jwt_refresh_token', 'jwt_refresh_token_expiry'])
    
    def is_jwt_refresh_token_valid(self, token: str) -> bool:
        """Validate JWT refresh token"""
        if not self.jwt_refresh_token or not self.jwt_refresh_token_expiry:
            return False
        
        if token != self.jwt_refresh_token:
            return False
        
        if timezone.now() > self.jwt_refresh_token_expiry:
            self.jwt_refresh_token = None
            self.jwt_refresh_token_expiry = None
            self.save(update_fields=['jwt_refresh_token', 'jwt_refresh_token_expiry'])
            return False
        
        return True
    
    def set_cognito_user_id(self, cognito_id: str):
        """Set AWS Cognito user ID"""
        self.cognito_user_id = cognito_id
        self.save(update_fields=['cognito_user_id'])
    
    def mark_email_verified(self):
        """Mark email as verified via AWS Cognito"""
        self.email_verified = True
        self.save(update_fields=['email_verified'])


class UserProfile(TimestampMixin):
    """Extended user profile information"""
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='profile',
        primary_key=True
    )
    
    # Contact information
    alternative_phone = models.CharField(max_length=15, blank=True, validators=[validate_phone_number])
    emergency_contact_name = models.CharField(max_length=100, blank=True)
    emergency_contact_phone = models.CharField(max_length=15, blank=True, validators=[validate_phone_number])
    
    # Address information
    address_line1 = models.CharField(max_length=255, blank=True)
    address_line2 = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=100, blank=True)
    country = models.CharField(max_length=100, default='Kenya')
    postal_code = models.CharField(max_length=20, blank=True)
    
    # Business information (for vendors/mechanics)
    business_name = models.CharField(max_length=255, blank=True)
    business_registration_number = models.CharField(max_length=100, blank=True)
    tax_id = models.CharField(max_length=100, blank=True)
    business_description = models.TextField(blank=True)
    
    # Ratings and statistics
    average_rating = models.DecimalField(max_digits=3, decimal_places=2, default=0.0)
    total_ratings = models.IntegerField(default=0)
    completed_orders = models.IntegerField(default=0)
    
    # Preferences
    preferred_language = models.CharField(max_length=10, default='en')
    currency = models.CharField(max_length=3, default='KES')
    
    # Metadata
    date_of_birth = models.DateField(null=True, blank=True)
    gender = models.CharField(
        max_length=20,
        choices=[
            ('male', 'Male'),
            ('female', 'Female'),
            ('other', 'Other'),
            ('prefer_not_to_say', 'Prefer not to say'),
        ],
        blank=True
    )
    
    class Meta:
        verbose_name = _('User Profile')
        verbose_name_plural = _('User Profiles')
        db_table = 'user_profiles'
    
    def __str__(self):
        return f"Profile: {self.user.email}"


class Vendor(TimestampMixin, SoftDeleteMixin, AddressMixin):
    """Vendor model for gas stations and service providers"""
    
    class VendorType(models.TextChoices):
        GAS_STATION = 'gas_station', _('Gas Station')
        HOSPITAL = 'hospital', _('Hospital')
        MECHANICAL_SERVICE = 'mechanical_service', _('Mechanical Service')
        TOWING_SERVICE = 'towing_service', _('Towing Service')
        FUEL_DELIVERY = 'fuel_delivery', _('Fuel Delivery')
    
    class VerificationStatus(models.TextChoices):
        PENDING = 'pending', _('Pending Verification')
        VERIFIED = 'verified', _('Verified')
        REJECTED = 'rejected', _('Rejected')
        SUSPENDED = 'suspended', _('Suspended')
    
    # Core identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='vendor_profile',
        limit_choices_to={'user_type__in': [User.UserType.VENDOR, User.UserType.MECHANIC]}
    )
    vendor_name = models.CharField(max_length=255, db_index=True)
    vendor_type = models.CharField(
        max_length=50,
        choices=VendorType.choices,
        db_index=True
    )
    
    # Contact information
    contact_person = models.CharField(max_length=100, blank=True)
    contact_email = models.EmailField(blank=True)
    contact_phone = models.CharField(max_length=15, validators=[validate_phone_number])
    website = models.URLField(blank=True)
    
    # Business information
    business_registration_number = models.CharField(max_length=100, blank=True)
    tax_id = models.CharField(max_length=100, blank=True)
    license_number = models.CharField(max_length=100, blank=True)
    license_expiry = models.DateField(null=True, blank=True)
    
    # Verification and status
    verification_status = models.CharField(
        max_length=20,
        choices=VerificationStatus.choices,
        default=VerificationStatus.PENDING,
        db_index=True
    )
    verification_documents = JSONField(
        default=dict,
        blank=True,
        help_text=_('Stores document URLs and metadata')
    )
    verified_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='verified_vendors',
        limit_choices_to={'user_type__in': [User.UserType.ADMIN, User.UserType.SUPER_ADMIN]}
    )
    verified_at = models.DateTimeField(null=True, blank=True)
    
    # Operational information
    opening_hours = JSONField(
        default=dict,
        blank=True,
        help_text=_('Structured opening hours')
    )
    is_24_hours = models.BooleanField(default=False)
    accepts_emergency_calls = models.BooleanField(default=False)
    
    # Ratings and statistics
    average_rating = models.DecimalField(max_digits=3, decimal_places=2, default=0.0)
    total_ratings = models.IntegerField(default=0)
    total_orders = models.IntegerField(default=0)
    total_revenue = models.DecimalField(max_digits=12, decimal_places=2, default=0.0)
    
    # Media and branding
    logo = models.ImageField(
        upload_to='vendor_logos/%Y/%m/%d/',
        null=True,
        blank=True,
        max_length=500
    )
    banner_image = models.ImageField(
        upload_to='vendor_banners/%Y/%m/%d/',
        null=True,
        blank=True,
        max_length=500
    )
    gallery_images = ArrayField(
        models.CharField(max_length=500),
        blank=True,
        default=list,
        help_text=_('Array of image URLs')
    )
    
    # Additional information
    description = models.TextField(blank=True)
    tags = ArrayField(
        models.CharField(max_length=50),
        blank=True,
        default=list,
        help_text=_('Search tags for the vendor')
    )
    amenities = JSONField(
        default=dict,
        blank=True,
        help_text=_('Available amenities and facilities')
    )
    
    # Custom manager
    objects = VendorManager()
    
    class Meta:
        verbose_name = _('Vendor')
        verbose_name_plural = _('Vendors')
        db_table = 'vendors'
        indexes = [
            models.Index(fields=['vendor_name', 'vendor_type']),
            models.Index(fields=['latitude', 'longitude']),
            models.Index(fields=['verification_status', 'is_deleted']),
            models.Index(fields=['average_rating', 'total_orders']),
        ]
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.vendor_name} ({self.get_vendor_type_display()})"
    
    def clean(self):
        """Custom validation"""
        super().clean()
        
        # Validate coordinates if provided
        if self.latitude and self.longitude:
            if not (-90 <= self.latitude <= 90):
                raise ValidationError({'latitude': 'Latitude must be between -90 and 90'})
            if not (-180 <= self.longitude <= 180):
                raise ValidationError({'longitude': 'Longitude must be between -180 and 180'})
    
    def is_open_now(self) -> bool:
        """Check if vendor is currently open"""
        if self.is_24_hours:
            return True
        
        if not self.opening_hours:
            return False
        
        now = timezone.now()
        current_weekday = now.strftime('%A').lower()
        current_time = now.time()
        
        # Check opening hours for current weekday
        hours = self.opening_hours.get(current_weekday)
        if not hours or not hours.get('open'):
            return False
        
        open_time = datetime.strptime(hours['open_time'], '%H:%M').time()
        close_time = datetime.strptime(hours['close_time'], '%H:%M').time()
        
        return open_time <= current_time <= close_time
    
    def update_rating(self, new_rating: float):
        """Update average rating with new rating"""
        total_score = self.average_rating * self.total_ratings
        self.total_ratings += 1
        self.average_rating = (total_score + new_rating) / self.total_ratings
        self.save(update_fields=['average_rating', 'total_ratings'])
    
    def verify_vendor(self, verified_by: User, documents: Dict[str, Any] = None):
        """Verify vendor"""
        self.verification_status = self.VerificationStatus.VERIFIED
        self.verified_by = verified_by
        self.verified_at = timezone.now()
        if documents:
            self.verification_documents = documents
        self.save()
    
    def suspend_vendor(self, reason: str):
        """Suspend vendor"""
        self.verification_status = self.VerificationStatus.SUSPENDED
        if 'suspension_history' not in self.verification_documents:
            self.verification_documents['suspension_history'] = []
        self.verification_documents['suspension_history'].append({
            'reason': reason,
            'suspended_at': timezone.now().isoformat()
        })
        self.save()


class Service(TimestampMixin, SoftDeleteMixin):
    """Service model for different service offerings"""
    
    class ServiceType(models.TextChoices):
        GAS_DELIVERY = 'gas_delivery', _('Gas Delivery')
        GAS_REFILL = 'gas_refill', _('Gas Refill')
        OXYGEN_REFILL = 'oxygen_refill', _('Oxygen Refill')
        MECHANICAL_REPAIR = 'mechanical_repair', _('Mechanical Repair')
        FUEL_DELIVERY = 'fuel_delivery', _('Fuel Delivery')
        TOWING = 'towing', _('Towing Service')
        BATTERY_JUMPSTART = 'battery_jumpstart', _('Battery Jumpstart')
        TIRE_CHANGE = 'tire_change', _('Tire Change')
        LOCKOUT_SERVICE = 'lockout_service', _('Lockout Service')
    
    class ServiceStatus(models.TextChoices):
        ACTIVE = 'active', _('Active')
        INACTIVE = 'inactive', _('Inactive')
        DISCONTINUED = 'discontinued', _('Discontinued')
    
    # Core identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    service_name = models.CharField(max_length=255, db_index=True)
    service_type = models.CharField(
        max_length=50,
        choices=ServiceType.choices,
        db_index=True
    )
    service_code = models.CharField(
        max_length=20,
        unique=True,
        db_index=True,
        help_text=_('Unique code for service identification')
    )
    
    # Vendor relationship
    vendor = models.ForeignKey(
        Vendor,
        on_delete=models.CASCADE,
        related_name='services',
        db_index=True
    )
    
    # Service details
    description = models.TextField(blank=True)
    detailed_description = models.TextField(blank=True)
    
    # Pricing
    price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        help_text=_('Base price in KES')
    )
    currency = models.CharField(max_length=3, default='KES')
    is_price_negotiable = models.BooleanField(default=False)
    minimum_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Minimum negotiable price')
    )
    
    # Service attributes
    estimated_duration_minutes = models.IntegerField(
        null=True,
        blank=True,
        help_text=_('Estimated service duration in minutes')
    )
    service_radius_km = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Maximum service radius in kilometers')
    )
    
    # Status and availability
    status = models.CharField(
        max_length=20,
        choices=ServiceStatus.choices,
        default=ServiceStatus.ACTIVE,
        db_index=True
    )
    is_available = models.BooleanField(default=True, db_index=True)
    available_from = models.TimeField(null=True, blank=True)
    available_to = models.TimeField(null=True, blank=True)
    available_days = ArrayField(
        models.IntegerField(
            choices=[
                (0, 'Monday'),
                (1, 'Tuesday'),
                (2, 'Wednesday'),
                (3, 'Thursday'),
                (4, 'Friday'),
                (5, 'Saturday'),
                (6, 'Sunday'),
            ]
        ),
        blank=True,
        default=list
    )
    
    # Requirements and constraints
    requirements = JSONField(
        default=dict,
        blank=True,
        help_text=_('Customer requirements for this service')
    )
    constraints = JSONField(
        default=dict,
        blank=True,
        help_text=_('Service constraints and limitations')
    )
    
    # Media
    service_images = ArrayField(
        models.CharField(max_length=500),
        blank=True,
        default=list,
        help_text=_('Array of service image URLs')
    )
    
    # Statistics
    total_bookings = models.IntegerField(default=0)
    average_rating = models.DecimalField(max_digits=3, decimal_places=2, default=0.0)
    
    # Custom manager
    objects = ServiceManager()
    
    class Meta:
        verbose_name = _('Service')
        verbose_name_plural = _('Services')
        db_table = 'services'
        indexes = [
            models.Index(fields=['service_type', 'is_available']),
            models.Index(fields=['vendor', 'status']),
            models.Index(fields=['price', 'service_type']),
            models.Index(fields=['is_deleted']),
        ]
        ordering = ['service_name']
        constraints = [
            models.CheckConstraint(
                check=models.Q(price__gte=0),
                name='price_non_negative'
            ),
            models.CheckConstraint(
                check=models.Q(estimated_duration_minutes__gt=0) | models.Q(estimated_duration_minutes__isnull=True),
                name='positive_estimated_duration'
            ),
        ]
    
    def __str__(self):
        return f"{self.service_name} - {self.vendor.vendor_name}"
    
    def clean(self):
        """Custom validation"""
        super().clean()
        
        # Validate price
        if self.price < 0:
            raise ValidationError({'price': 'Price cannot be negative'})
        
        # Validate minimum price if negotiable
        if self.is_price_negotiable and self.minimum_price:
            if self.minimum_price > self.price:
                raise ValidationError({
                    'minimum_price': 'Minimum price cannot be greater than base price'
                })
    
    def is_available_now(self) -> bool:
        """Check if service is currently available"""
        if not self.is_available:
            return False
        
        if self.status != self.ServiceStatus.ACTIVE:
            return False
        
        # Check time availability
        now = timezone.now()
        current_time = now.time()
        current_day = now.weekday()
        
        if self.available_days and current_day not in self.available_days:
            return False
        
        if self.available_from and self.available_to:
            return self.available_from <= current_time <= self.available_to
        
        return True
    
    def calculate_distance_price(self, customer_lat: float, customer_lng: float) -> float:
        """Calculate additional price based on distance"""
        if not self.service_radius_km or not customer_lat or not customer_lng:
            return float(self.price)
        
        # Calculate distance using Haversine formula
        from math import radians, sin, cos, sqrt, atan2
        
        R = 6371  # Earth's radius in km
        
        lat1 = radians(float(self.vendor.latitude))
        lon1 = radians(float(self.vendor.longitude))
        lat2 = radians(customer_lat)
        lon2 = radians(customer_lng)
        
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        distance_km = R * c
        
        # Check if within service radius
        if distance_km > float(self.service_radius_km):
            return None  # Service not available for this distance
        
        # Add distance-based pricing (example: 50 KES per km after 5km)
        base_distance = 5.0
        per_km_rate = 50.0
        
        if distance_km <= base_distance:
            additional_cost = 0
        else:
            additional_cost = (distance_km - base_distance) * per_km_rate
        
        return float(self.price) + additional_cost


class ServiceAddon(TimestampMixin, SoftDeleteMixin):
    """Add-on services or extras"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    service = models.ForeignKey(
        Service,
        on_delete=models.CASCADE,
        related_name='addons',
        db_index=True
    )
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    is_available = models.BooleanField(default=True)
    sort_order = models.IntegerField(default=0)
    
    class Meta:
        verbose_name = _('Service Add-on')
        verbose_name_plural = _('Service Add-ons')
        db_table = 'service_addons'
        ordering = ['sort_order', 'name']
    
    def __str__(self):
        return f"{self.name} (+{self.price} KES)"


class GasCylinder(TimestampMixin):
    """Gas cylinder inventory model"""
    
    class GasType(models.TextChoices):
        LPG = 'lpg', _('Liquefied Petroleum Gas')
        OXYGEN = 'oxygen', _('Medical Oxygen')
        NITROGEN = 'nitrogen', _('Nitrogen')
        ARGON = 'argon', _('Argon')
        ACETYLENE = 'acetylene', _('Acetylene')
    
    class CylinderSize(models.TextChoices):
        SMALL_3KG = '3kg', _('3kg Cylinder')
        MEDIUM_6KG = '6kg', _('6kg Cylinder')
        LARGE_13KG = '13kg', _('13kg Cylinder')
        COMMERCIAL_50KG = '50kg', _('50kg Cylinder')
        MEDICAL_10L = '10l', _('10L Medical Cylinder')
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vendor = models.ForeignKey(
        Vendor,
        on_delete=models.CASCADE,
        related_name='gas_cylinders',
        db_index=True,
        limit_choices_to={'vendor_type': Vendor.VendorType.GAS_STATION}
    )
    gas_type = models.CharField(max_length=20, choices=GasType.choices, db_index=True)
    cylinder_size = models.CharField(max_length=10, choices=CylinderSize.choices, db_index=True)
    
    # Inventory
    sku = models.CharField(max_length=50, unique=True, db_index=True)
    stock_quantity = models.IntegerField(default=0)
    reserved_quantity = models.IntegerField(default=0)
    minimum_stock_level = models.IntegerField(default=5)
    maximum_stock_level = models.IntegerField(default=100)
    
    # Pricing
    price_per_unit = models.DecimalField(max_digits=10, decimal_places=2)
    deposit_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00,
        help_text=_('Cylinder deposit amount')
    )
    refill_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Price for refilling existing cylinder')
    )
    
    # Details
    brand = models.CharField(max_length=100, blank=True)
    weight_kg = models.DecimalField(max_digits=6, decimal_places=2)
    volume_liters = models.DecimalField(max_digits=6, decimal_places=2)
    
    # Safety and compliance
    last_inspection_date = models.DateField(null=True, blank=True)
    next_inspection_date = models.DateField(null=True, blank=True)
    certification_number = models.CharField(max_length=100, blank=True)
    
    # Status
    is_available = models.BooleanField(default=True, db_index=True)
    
    class Meta:
        verbose_name = _('Gas Cylinder')
        verbose_name_plural = _('Gas Cylinders')
        db_table = 'gas_cylinders'
        indexes = [
            models.Index(fields=['vendor', 'gas_type', 'is_available']),
            models.Index(fields=['stock_quantity']),
        ]
        ordering = ['gas_type', 'cylinder_size']
        unique_together = ['vendor', 'gas_type', 'cylinder_size', 'brand']
    
    def __str__(self):
        return f"{self.get_gas_type_display()} - {self.get_cylinder_size_display()} ({self.vendor.vendor_name})"
    
    @property
    def available_quantity(self):
        """Get available quantity (stock - reserved)"""
        return self.stock_quantity - self.reserved_quantity
    
    def reserve(self, quantity: int) -> bool:
        """Reserve cylinders if available"""
        if quantity <= self.available_quantity:
            self.reserved_quantity += quantity
            self.save(update_fields=['reserved_quantity'])
            return True
        return False
    
    def release(self, quantity: int):
        """Release reserved cylinders"""
        self.reserved_quantity = max(0, self.reserved_quantity - quantity)
        self.save(update_fields=['reserved_quantity'])
    
    def consume(self, quantity: int):
        """Consume cylinders from stock"""
        self.stock_quantity = max(0, self.stock_quantity - quantity)
        self.reserved_quantity = max(0, self.reserved_quantity - quantity)
        self.save(update_fields=['stock_quantity', 'reserved_quantity'])
    
    def restock(self, quantity: int):
        """Add to stock"""
        self.stock_quantity += quantity
        self.save(update_fields=['stock_quantity'])
    
    def needs_restocking(self) -> bool:
        """Check if needs restocking"""
        return self.stock_quantity <= self.minimum_stock_level


class ServiceArea(TimestampMixin):
    """Service area for vendors"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vendor = models.ForeignKey(
        Vendor,
        on_delete=models.CASCADE,
        related_name='service_areas',
        db_index=True
    )
    area_name = models.CharField(max_length=100)
    polygon_coordinates = JSONField(
        help_text=_('GeoJSON polygon coordinates for service area')
    )
    is_active = models.BooleanField(default=True)
    
    class Meta:
        verbose_name = _('Service Area')
        verbose_name_plural = _('Service Areas')
        db_table = 'service_areas'
        indexes = [
            models.Index(fields=['vendor', 'is_active']),
        ]
    
    def __str__(self):
        return f"{self.area_name} - {self.vendor.vendor_name}"


class UserSession(TimestampMixin):
    """Track user sessions for security and analytics"""
    
    class SessionStatus(models.TextChoices):
        ACTIVE = 'active', _('Active')
        EXPIRED = 'expired', _('Expired')
        REVOKED = 'revoked', _('Revoked')
        SUSPICIOUS = 'suspicious', _('Suspicious')
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='sessions',
        db_index=True
    )
    session_key = models.CharField(max_length=255, unique=True, db_index=True)
    refresh_token_hash = models.CharField(max_length=255, db_index=True)
    
    # Device and location info
    user_agent = models.TextField(blank=True)
    device_info = JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField()
    location_info = JSONField(default=dict, blank=True)
    
    # Timing
    login_at = models.DateTimeField()
    last_activity_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    
    # Status
    status = models.CharField(
        max_length=20,
        choices=SessionStatus.choices,
        default=SessionStatus.ACTIVE,
        db_index=True
    )
    revocation_reason = models.CharField(max_length=100, blank=True)
    
    # Security
    is_mobile = models.BooleanField(default=False)
    is_tablet = models.BooleanField(default=False)
    is_desktop = models.BooleanField(default=False)
    
    class Meta:
        verbose_name = _('User Session')
        verbose_name_plural = _('User Sessions')
        db_table = 'user_sessions'
        indexes = [
            models.Index(fields=['user', 'status', 'expires_at']),
            models.Index(fields=['session_key', 'status']),
            models.Index(fields=['expires_at']),
        ]
        ordering = ['-login_at']
    
    def __str__(self):
        return f"Session {self.session_key[:10]}... for {self.user.email}"
    
    @property
    def is_valid(self):
        """Check if session is valid"""
        now = timezone.now()
        return (
            self.status == self.SessionStatus.ACTIVE and
            now < self.expires_at
        )
    
    def revoke(self, reason: str = ''):
        """Revoke session"""
        self.status = self.SessionStatus.REVOKED
        self.revocation_reason = reason
        self.revoked_at = timezone.now()
        self.save()
    
    def mark_suspicious(self):
        """Mark session as suspicious"""
        self.status = self.SessionStatus.SUSPICIOUS
        self.save()
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity_at = timezone.now()
        self.save(update_fields=['last_activity_at'])


class AuditLog(TimestampMixin):
    """Comprehensive audit logging"""
    
    class ActionType(models.TextChoices):
        LOGIN = 'login', _('Login')
        LOGOUT = 'logout', _('Logout')
        CREATE = 'create', _('Create')
        UPDATE = 'update', _('Update')
        DELETE = 'delete', _('Delete')
        VIEW = 'view', _('View')
        VERIFY = 'verify', _('Verify')
        PAYMENT = 'payment', _('Payment')
        BOOKING = 'booking', _('Booking')
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs',
        db_index=True
    )
    user_session = models.ForeignKey(
        UserSession,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs',
        db_index=True
    )
    
    # Action details
    action = models.CharField(max_length=50, choices=ActionType.choices, db_index=True)
    resource_type = models.CharField(max_length=100, db_index=True)
    resource_id = models.UUIDField(null=True, blank=True, db_index=True)
    
    # Data
    old_data = JSONField(null=True, blank=True)
    new_data = JSONField(null=True, blank=True)
    changes = JSONField(null=True, blank=True)
    
    # Context
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    request_path = models.CharField(max_length=500, blank=True)
    request_method = models.CharField(max_length=10, blank=True)
    
    # Metadata
    status_code = models.IntegerField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    duration_ms = models.FloatField(null=True, blank=True)
    
    class Meta:
        verbose_name = _('Audit Log')
        verbose_name_plural = _('Audit Logs')
        db_table = 'audit_logs'
        indexes = [
            models.Index(fields=['resource_type', 'resource_id', 'created_at']),
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['action', 'created_at']),
            models.Index(fields=['created_at']),
        ]
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.action} {self.resource_type} by {self.user.email if self.user else 'System'}"

