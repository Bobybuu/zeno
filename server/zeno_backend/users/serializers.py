"""
Serializers for Zeno Application
Robust implementation with validation, nested relationships, and business logic
"""

import re
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from decimal import Decimal

from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate
from django.db import transaction
from django.conf import settings

from .models import (
    User, UserProfile, Vendor, Service, ServiceAddon,
    GasCylinder, ServiceArea, UserSession, AuditLog
)
from .validators import (
    validate_phone_number, validate_password, validate_kenyan_id,
    validate_business_reg, validate_postal_code, validate_coordinates,
    validate_opening_hours, validate_image_file
)

logger = logging.getLogger(__name__)


# ============ UTILITY SERIALIZERS ============

class TimestampSerializer(serializers.Serializer):
    """Serializer mixin for timestamp fields"""
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)


class SoftDeleteSerializer(serializers.Serializer):
    """Serializer mixin for soft delete fields"""
    is_deleted = serializers.BooleanField(read_only=True)
    deleted_at = serializers.DateTimeField(read_only=True, allow_null=True)


class AddressSerializer(serializers.Serializer):
    """Serializer mixin for address fields"""
    address_line1 = serializers.CharField(
        max_length=255,
        required=False,
        allow_blank=True,
        trim_whitespace=True
    )
    address_line2 = serializers.CharField(
        max_length=255,
        required=False,
        allow_blank=True,
        trim_whitespace=True
    )
    city = serializers.CharField(
        max_length=100,
        required=False,
        allow_blank=True,
        trim_whitespace=True
    )
    state = serializers.CharField(
        max_length=100,
        required=False,
        allow_blank=True,
        trim_whitespace=True
    )
    country = serializers.CharField(
        max_length=100,
        required=False,
        default='Kenya',
        trim_whitespace=True
    )
    postal_code = serializers.CharField(
        max_length=20,
        required=False,
        allow_blank=True,
        validators=[validate_postal_code],
        trim_whitespace=True
    )
    latitude = serializers.DecimalField(
        max_digits=10,
        decimal_places=8,
        required=False,
        allow_null=True,
        min_value=-90,
        max_value=90,
        validators=[validate_coordinates.validate_latitude]
    )
    longitude = serializers.DecimalField(
        max_digits=11,
        decimal_places=8,
        required=False,
        allow_null=True,
        min_value=-180,
        max_value=180,
        validators=[validate_coordinates.validate_longitude]
    )
    
    def validate(self, attrs):
        """Validate address coordinates"""
        latitude = attrs.get('latitude')
        longitude = attrs.get('longitude')
        
        # Both or neither should be provided
        if (latitude is not None and longitude is None) or \
           (latitude is None and longitude is not None):
            raise serializers.ValidationError({
                'coordinates': 'Both latitude and longitude must be provided together'
            })
        
        return attrs


# ============ AUTHENTICATION SERIALIZERS ============

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom JWT token serializer with additional user data
    """
    
    def validate(self, attrs):
        """Custom validation with account locking check"""
        email = attrs.get('email', attrs.get('username'))
        password = attrs.get('password')
        
        if not email or not password:
            raise serializers.ValidationError({
                'detail': 'Email and password are required'
            })
        
        # Get user by email
        try:
            user = User.objects.get(email=email.lower())
        except User.DoesNotExist:
            raise serializers.ValidationError({
                'detail': 'Invalid credentials'
            })
        
        # Check if account is locked
        if user.is_account_locked():
            raise serializers.ValidationError({
                'detail': 'Account is temporarily locked. Please try again later.',
                'locked_until': user.account_locked_until,
                'locked': True
            })
        
        # Check if account is active
        if not user.is_active:
            raise serializers.ValidationError({
                'detail': 'Account is inactive',
                'inactive': True
            })
        
        # Check if email is verified
        if not user.email_verified:
            raise serializers.ValidationError({
                'detail': 'Email not verified',
                'email_verified': False
            })
        
        # Authenticate user
        authenticated_user = authenticate(
            request=self.context.get('request'),
            username=email,
            password=password
        )
        
        if not authenticated_user:
            # Record failed login attempt
            ip_address = self.context.get('request').META.get('REMOTE_ADDR')
            user.record_failed_login(ip_address)
            
            attempts_left = 5 - user.failed_login_attempts
            raise serializers.ValidationError({
                'detail': f'Invalid credentials. {attempts_left} attempts left.',
                'attempts_left': attempts_left,
                'failed_attempts': user.failed_login_attempts
            })
        
        # Reset failed login attempts on successful login
        user.reset_failed_logins()
        
        # Update session info
        request = self.context.get('request')
        if request:
            ip_address = request.META.get('REMOTE_ADDR')
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            
            # Create or update user session
            session_key = request.session.session_key
            expiry = request.session.get_expiry_date()
            user.update_session(session_key, expiry, ip_address)
            
            # Create UserSession record
            UserSession.objects.create(
                user=user,
                session_key=session_key,
                refresh_token_hash='',  # Will be set when JWT is created
                user_agent=user_agent,
                ip_address=ip_address,
                login_at=timezone.now(),
                expires_at=expiry,
                device_info=self._get_device_info(request)
            )
        
        # Generate tokens
        refresh = self.get_token(user)
        access_token = refresh.access_token
        
        # Set custom claims
        access_token['user_type'] = user.user_type
        access_token['email_verified'] = user.email_verified
        
        # Update JWT refresh token in user model
        user.update_jwt_refresh_token(
            str(refresh),
            timezone.now() + timedelta(days=7)
        )
        
        return {
            'access': str(access_token),
            'refresh': str(refresh),
            'user': {
                'id': str(user.id),
                'email': user.email,
                'user_type': user.user_type,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email_verified': user.email_verified,
                'phone_number': user.phone_number,
                'has_profile': hasattr(user, 'profile')
            }
        }
    
    def _get_device_info(self, request) -> Dict[str, Any]:
        """Extract device information from request"""
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Simple device detection
        device_info = {
            'user_agent': user_agent,
            'is_mobile': any(x in user_agent.lower() for x in ['mobile', 'android', 'iphone']),
            'is_tablet': any(x in user_agent.lower() for x in ['tablet', 'ipad']),
            'is_desktop': not any(x in user_agent.lower() for x in ['mobile', 'android', 'iphone', 'tablet', 'ipad']),
        }
        
        return device_info


class RegisterSerializer(serializers.ModelSerializer):
    """Serializer for user registration with AWS Cognito integration"""
    
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    phone_number = serializers.CharField(
        required=False,
        allow_blank=True,
        validators=[validate_phone_number]
    )
    
    class Meta:
        model = User
        fields = [
            'email', 'password', 'password_confirm', 'first_name', 'last_name',
            'phone_number', 'user_type', 'location'
        ]
        extra_kwargs = {
            'email': {
                'required': True,
                'validators': [UniqueValidator(queryset=User.objects.all())]
            },
            'first_name': {'required': False, 'allow_blank': True},
            'last_name': {'required': False, 'allow_blank': True},
            'user_type': {'default': 'customer'},
        }
    
    def validate(self, attrs):
        """Validate registration data"""
        # Check password confirmation
        password = attrs.get('password')
        password_confirm = attrs.get('password_confirm')
        
        if password != password_confirm:
            raise serializers.ValidationError({
                'password_confirm': 'Passwords do not match'
            })
        
        # Remove password_confirm from validated data
        attrs.pop('password_confirm', None)
        
        # Validate user type
        user_type = attrs.get('user_type', 'customer')
        if user_type not in dict(User.UserType.choices):
            raise serializers.ValidationError({
                'user_type': f'Invalid user type. Must be one of: {", ".join(dict(User.UserType.choices).keys())}'
            })
        
        # Ensure email is lowercase
        if 'email' in attrs:
            attrs['email'] = attrs['email'].lower()
        
        return attrs
    
    def create(self, validated_data):
        """Create user with AWS Cognito integration"""
        from .cognito_client import cognito_client
        
        with transaction.atomic():
            # Extract password before creating user
            password = validated_data.pop('password')
            email = validated_data['email'].lower()
            
            # Create user in Django
            user = User.objects.create_user(
                **validated_data,
                password=password  # Django will hash this
            )
            
            try:
                # Register in AWS Cognito
                cognito_response = cognito_client.register_user(
                    email=email,
                    password=password,  # Plain password for Cognito
                    first_name=user.first_name,
                    last_name=user.last_name,
                    phone_number=user.phone_number
                )
                
                # Update user with Cognito ID
                user.cognito_user_id = cognito_response['user_id']
                user.save(update_fields=['cognito_user_id'])
                
                logger.info(f"User {email} registered successfully in Cognito")
                
            except Exception as e:
                # If Cognito registration fails, delete Django user
                user.delete()
                logger.error(f"Cognito registration failed: {str(e)}")
                raise serializers.ValidationError({
                    'detail': f'Registration failed: {str(e)}'
                })
            
            return user
    
    def to_representation(self, instance):
        """Custom representation after registration"""
        return {
            'id': str(instance.id),
            'email': instance.email,
            'user_type': instance.user_type,
            'message': 'Registration successful. Please check your email for verification.',
            'requires_email_verification': True
        }


class PasswordResetSerializer(serializers.Serializer):
    """Serializer for password reset request"""
    
    email = serializers.EmailField(required=True)
    
    def validate_email(self, value):
        """Validate email exists"""
        try:
            user = User.objects.get(email=value.lower())
            if not user.is_active:
                raise serializers.ValidationError('Account is inactive')
            return value
        except User.DoesNotExist:
            # Don't reveal if user exists for security
            return value
    
    def create(self, validated_data):
        """Initiate password reset process"""
        from .cognito_client import cognito_client
        
        email = validated_data['email'].lower()
        
        try:
            # Send password reset via AWS Cognito
            result = cognito_client.initiate_password_reset(email)
            
            # Log the action
            AuditLog.objects.create(
                action='password_reset_request',
                resource_type='user',
                resource_id=None,
                details={'email': email},
                ip_address=self.context.get('request').META.get('REMOTE_ADDR'),
                user_agent=self.context.get('request').META.get('HTTP_USER_AGENT', '')
            )
            
            return {
                'success': True,
                'message': 'If your email is registered, you will receive reset instructions',
                'detail': result.get('message', 'Password reset initiated')
            }
            
        except Exception as e:
            logger.error(f"Password reset failed for {email}: {str(e)}")
            # Still return success for security reasons
            return {
                'success': True,
                'message': 'If your email is registered, you will receive reset instructions'
            }


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Serializer for password reset confirmation"""
    
    email = serializers.EmailField(required=True)
    verification_code = serializers.CharField(required=True, max_length=6)
    new_password = serializers.CharField(
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    
    def validate(self, attrs):
        """Validate password reset data"""
        email = attrs['email'].lower()
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({
                'email': 'Invalid email'
            })
        
        if not user.is_active:
            raise serializers.ValidationError({
                'email': 'Account is inactive'
            })
        
        attrs['user'] = user
        return attrs
    
    def create(self, validated_data):
        """Confirm password reset"""
        from .cognito_client import cognito_client
        
        user = validated_data['user']
        verification_code = validated_data['verification_code']
        new_password = validated_data['new_password']
        
        try:
            # Confirm password reset via AWS Cognito
            result = cognito_client.confirm_password_reset(
                email=user.email,
                verification_code=verification_code,
                new_password=new_password
            )
            
            # Update password in Django (optional, if you sync passwords)
            user.set_password(new_password)
            user.save(update_fields=['password', 'last_password_change'])
            
            # Log the action
            AuditLog.objects.create(
                user=user,
                action='password_reset_complete',
                resource_type='user',
                resource_id=user.id,
                ip_address=self.context.get('request').META.get('REMOTE_ADDR'),
                user_agent=self.context.get('request').META.get('HTTP_USER_AGENT', '')
            )
            
            return {
                'success': True,
                'message': 'Password reset successfully',
                'detail': result.get('message', 'Password reset completed')
            }
            
        except Exception as e:
            logger.error(f"Password reset confirmation failed: {str(e)}")
            raise serializers.ValidationError({
                'detail': f'Invalid verification code or password reset failed: {str(e)}'
            })


class VerifyEmailSerializer(serializers.Serializer):
    """Serializer for email verification"""
    
    email = serializers.EmailField(required=True)
    verification_code = serializers.CharField(required=True, max_length=6)
    
    def validate(self, attrs):
        """Validate verification data"""
        email = attrs['email'].lower()
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({
                'email': 'Invalid email'
            })
        
        if user.email_verified:
            raise serializers.ValidationError({
                'email': 'Email already verified'
            })
        
        attrs['user'] = user
        return attrs
    
    def create(self, validated_data):
        """Verify email via AWS Cognito"""
        from .cognito_client import cognito_client
        
        user = validated_data['user']
        verification_code = validated_data['verification_code']
        
        try:
            # Verify email via AWS Cognito
            result = cognito_client.verify_email(
                email=user.email,
                verification_code=verification_code
            )
            
            # Mark email as verified in Django
            user.mark_email_verified()
            
            # Log the action
            AuditLog.objects.create(
                user=user,
                action='email_verified',
                resource_type='user',
                resource_id=user.id,
                ip_address=self.context.get('request').META.get('REMOTE_ADDR'),
                user_agent=self.context.get('request').META.get('HTTP_USER_AGENT', '')
            )
            
            return {
                'success': True,
                'message': 'Email verified successfully',
                'detail': result.get('message', 'Email verification completed')
            }
            
        except Exception as e:
            logger.error(f"Email verification failed: {str(e)}")
            raise serializers.ValidationError({
                'detail': f'Invalid verification code: {str(e)}'
            })


class ResendVerificationSerializer(serializers.Serializer):
    """Serializer for resending verification email"""
    
    email = serializers.EmailField(required=True)
    
    def validate_email(self, value):
        """Validate email exists and not verified"""
        try:
            user = User.objects.get(email=value.lower())
            if user.email_verified:
                raise serializers.ValidationError('Email already verified')
            if not user.is_active:
                raise serializers.ValidationError('Account is inactive')
            return value
        except User.DoesNotExist:
            raise serializers.ValidationError('User not found')
    
    def create(self, validated_data):
        """Resend verification email"""
        from .cognito_client import cognito_client
        
        email = validated_data['email'].lower()
        
        try:
            # Resend verification via AWS Cognito
            result = cognito_client.resend_verification_email(email)
            
            # Log the action
            AuditLog.objects.create(
                action='resend_verification',
                resource_type='user',
                resource_id=None,
                details={'email': email},
                ip_address=self.context.get('request').META.get('REMOTE_ADDR'),
                user_agent=self.context.get('request').META.get('HTTP_USER_AGENT', '')
            )
            
            return {
                'success': True,
                'message': 'Verification email sent',
                'detail': result.get('message', 'Verification email resent')
            }
            
        except Exception as e:
            logger.error(f"Failed to resend verification email to {email}: {str(e)}")
            raise serializers.ValidationError({
                'detail': f'Failed to resend verification email: {str(e)}'
            })


class CognitoLoginSerializer(serializers.Serializer):
    """Serializer for Cognito authentication"""
    
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        required=True,
        style={'input_type': 'password'},
        write_only=True
    )
    
    def validate(self, attrs):
        """Validate login credentials"""
        email = attrs['email'].lower()
        password = attrs['password']
        
        # Get user by email
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({
                'detail': 'Invalid credentials'
            })
        
        # Check if account is locked
        if user.is_account_locked():
            raise serializers.ValidationError({
                'detail': 'Account is temporarily locked. Please try again later.',
                'locked_until': user.account_locked_until,
                'locked': True
            })
        
        # Check if account is active
        if not user.is_active:
            raise serializers.ValidationError({
                'detail': 'Account is inactive',
                'inactive': True
            })
        
        attrs['user'] = user
        return attrs
    
    def create(self, validated_data):
        """Authenticate user via Cognito"""
        from .cognito_client import cognito_client
        
        user = validated_data['user']
        password = validated_data['password']
        
        try:
            # Authenticate user via AWS Cognito
            auth_result = cognito_client.authenticate_user(
                email=user.email,
                password=password
            )
            
            # Reset failed login attempts on successful login
            user.reset_failed_logins()
            
            # Update session info
            request = self.context.get('request')
            if request:
                ip_address = request.META.get('REMOTE_ADDR')
                user_agent = request.META.get('HTTP_USER_AGENT', '')
                
                # Create UserSession record
                session_key = request.session.session_key if hasattr(request.session, 'session_key') else None
                expiry = request.session.get_expiry_date() if hasattr(request.session, 'get_expiry_date') else None
                
                UserSession.objects.create(
                    user=user,
                    session_key=session_key,
                    refresh_token_hash=auth_result.get('refresh_token', '')[:64],
                    user_agent=user_agent,
                    ip_address=ip_address,
                    login_at=timezone.now(),
                    expires_at=expiry,
                    device_info=self._get_device_info(request)
                )
            
            # Update last login time
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
            
            # Log the action
            AuditLog.objects.create(
                user=user,
                action='login',
                resource_type='user',
                resource_id=user.id,
                ip_address=self.context.get('request').META.get('REMOTE_ADDR'),
                user_agent=self.context.get('request').META.get('HTTP_USER_AGENT', '')
            )
            
            return {
                'success': True,
                'access_token': auth_result.get('access_token'),
                'refresh_token': auth_result.get('refresh_token'),
                'id_token': auth_result.get('id_token'),
                'expires_in': auth_result.get('expires_in'),
                'token_type': auth_result.get('token_type'),
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'user_type': user.user_type,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'email_verified': user.email_verified,
                    'phone_number': user.phone_number,
                    'has_profile': hasattr(user, 'profile')
                }
            }
            
        except Exception as e:
            # Record failed login attempt
            ip_address = self.context.get('request').META.get('REMOTE_ADDR')
            user.record_failed_login(ip_address)
            
            attempts_left = 5 - user.failed_login_attempts
            logger.error(f"Authentication failed for {user.email}: {str(e)}")
            
            if user.is_account_locked():
                raise serializers.ValidationError({
                    'detail': 'Account is temporarily locked. Please try again later.',
                    'locked_until': user.account_locked_until,
                    'locked': True
                })
            else:
                raise serializers.ValidationError({
                    'detail': f'Invalid credentials. {attempts_left} attempts left.',
                    'attempts_left': attempts_left,
                    'failed_attempts': user.failed_login_attempts
                })
    
    def _get_device_info(self, request) -> Dict[str, Any]:
        """Extract device information from request"""
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Simple device detection
        device_info = {
            'user_agent': user_agent,
            'is_mobile': any(x in user_agent.lower() for x in ['mobile', 'android', 'iphone']),
            'is_tablet': any(x in user_agent.lower() for x in ['tablet', 'ipad']),
            'is_desktop': not any(x in user_agent.lower() for x in ['mobile', 'android', 'iphone', 'tablet', 'ipad']),
        }
        
        return device_info


class CognitoRefreshTokenSerializer(serializers.Serializer):
    """Serializer for refreshing Cognito tokens"""
    
    refresh_token = serializers.CharField(required=True)
    
    def create(self, validated_data):
        """Refresh access token"""
        from .cognito_client import cognito_client
        
        refresh_token = validated_data['refresh_token']
        
        try:
            # Refresh token via AWS Cognito
            result = cognito_client.refresh_token(refresh_token)
            
            return {
                'success': True,
                'access_token': result.get('access_token'),
                'id_token': result.get('id_token'),
                'expires_in': result.get('expires_in'),
                'token_type': result.get('token_type')
            }
            
        except Exception as e:
            logger.error(f"Token refresh failed: {str(e)}")
            raise serializers.ValidationError({
                'detail': f'Token refresh failed: {str(e)}'
            })


class ChangePasswordSerializer(serializers.Serializer):
    """Serializer for changing password"""
    
    current_password = serializers.CharField(
        required=True,
        style={'input_type': 'password'},
        write_only=True
    )
    new_password = serializers.CharField(
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'},
        write_only=True
    )
    
    def validate(self, attrs):
        """Validate password change data"""
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            raise serializers.ValidationError({
                'detail': 'Authentication required'
            })
        
        # Verify current password
        user = request.user
        if not user.check_password(attrs['current_password']):
            raise serializers.ValidationError({
                'current_password': 'Current password is incorrect'
            })
        
        # Check if new password is different
        if attrs['current_password'] == attrs['new_password']:
            raise serializers.ValidationError({
                'new_password': 'New password must be different from current password'
            })
        
        return attrs
    
    def create(self, validated_data):
        """Change password via Cognito"""
        from .cognito_client import cognito_client
        
        request = self.context.get('request')
        user = request.user
        new_password = validated_data['new_password']
        
        # Check if user has Cognito ID
        if not user.cognito_user_id:
            raise serializers.ValidationError({
                'detail': 'User not registered in Cognito'
            })
        
        # Get access token (you need to have this stored from login)
        # This is a simplified example - in reality you'd need to handle token storage
        try:
            # This assumes you have a way to get the current access token
            # You might need to store it in the session or a secure location
            access_token = request.session.get('cognito_access_token')
            
            if not access_token:
                # Try to authenticate first to get a fresh token
                auth_result = cognito_client.authenticate_user(
                    email=user.email,
                    password=validated_data['current_password']
                )
                access_token = auth_result.get('access_token')
            
            # Change password via AWS Cognito
            result = cognito_client.change_password(
                access_token=access_token,
                previous_password=validated_data['current_password'],
                proposed_password=new_password
            )
            
            # Update password in Django
            user.set_password(new_password)
            user.save(update_fields=['password', 'last_password_change'])
            
            # Log the action
            AuditLog.objects.create(
                user=user,
                action='password_change',
                resource_type='user',
                resource_id=user.id,
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            return {
                'success': True,
                'message': 'Password changed successfully',
                'detail': result.get('message', 'Password change completed')
            }
            
        except Exception as e:
            logger.error(f"Password change failed for user {user.email}: {str(e)}")
            raise serializers.ValidationError({
                'detail': f'Password change failed: {str(e)}'
            })


# ============ USER SERIALIZERS ============

class UserProfileSerializer(serializers.ModelSerializer, TimestampSerializer):
    """Serializer for UserProfile"""
    
    full_address = serializers.SerializerMethodField(read_only=True)
    
    class Meta:
        model = UserProfile
        fields = [
            # Contact
            'alternative_phone', 'emergency_contact_name', 'emergency_contact_phone',
            # Address
            'address_line1', 'address_line2', 'city', 'state', 'country',
            'postal_code', 'full_address',
            # Business
            'business_name', 'business_registration_number', 'tax_id',
            'business_description',
            # Statistics
            'average_rating', 'total_ratings', 'completed_orders',
            # Preferences
            'preferred_language', 'currency',
            # Personal
            'date_of_birth', 'gender',
            # Timestamps
            'created_at', 'updated_at'
        ]
        extra_kwargs = {
            'alternative_phone': {'validators': [validate_phone_number]},
            'emergency_contact_phone': {'validators': [validate_phone_number]},
            'business_registration_number': {'validators': [validate_business_reg]},
            'postal_code': {'validators': [validate_postal_code]},
        }
    
    def get_full_address(self, obj):
        return obj.full_address
    
    def validate(self, attrs):
        """Validate business information based on user type"""
        request = self.context.get('request')
        if request and request.user:
            user = request.user
            if user.user_type in ['customer']:
                # Customers shouldn't have business info
                business_fields = ['business_name', 'business_registration_number', 
                                 'tax_id', 'business_description']
                for field in business_fields:
                    if field in attrs and attrs[field]:
                        raise serializers.ValidationError({
                            field: f'{field.replace("_", " ").title()} is not applicable for customers'
                        })
        
        return attrs


class UserSerializer(serializers.ModelSerializer, TimestampSerializer, SoftDeleteSerializer):
    """Serializer for User model"""
    
    profile = UserProfileSerializer(read_only=True)
    full_name = serializers.SerializerMethodField(read_only=True)
    is_account_locked = serializers.SerializerMethodField(read_only=True)
    account_status = serializers.SerializerMethodField(read_only=True)
    
    class Meta:
        model = User
        fields = [
            # Core
            'id', 'email', 'username', 'first_name', 'last_name', 'full_name',
            # Type & Verification
            'user_type', 'cognito_user_id', 'email_verified',
            # Contact
            'phone_number', 'location',
            # Profile
            'profile_picture', 'profile',
            # Security
            'mfa_enabled', 'failed_login_attempts', 'account_locked_until',
            'is_account_locked', 'account_status',
            # Session
            'last_login_ip', 'current_login_ip',
            # Preferences
            'preferences', 'notification_settings',
            # Status
            'is_active', 'is_staff', 'is_superuser',
            # Timestamps
            'last_login', 'date_joined', 'created_at', 'updated_at',
            'last_password_change',
            # Soft delete
            'is_deleted', 'deleted_at'
        ]
        read_only_fields = [
            'id', 'cognito_user_id', 'email_verified', 'failed_login_attempts',
            'account_locked_until', 'last_login_ip', 'current_login_ip',
            'is_staff', 'is_superuser', 'last_login', 'date_joined',
            'created_at', 'updated_at', 'last_password_change',
            'is_deleted', 'deleted_at'
        ]
        extra_kwargs = {
            'email': {
                'validators': [UniqueValidator(queryset=User.objects.all())]
            },
            'phone_number': {'validators': [validate_phone_number]},
            'profile_picture': {'validators': [validate_image_file]},
        }
    
    def get_full_name(self, obj):
        return obj.get_full_name()
    
    def get_is_account_locked(self, obj):
        return obj.is_account_locked()
    
    def get_account_status(self, obj):
        if obj.is_account_locked():
            return 'locked'
        elif not obj.is_active:
            return 'inactive'
        elif not obj.email_verified:
            return 'unverified'
        return 'active'
    
    def validate_email(self, value):
        """Ensure email is lowercase"""
        return value.lower() if value else value
    
    def validate(self, attrs):
        """Custom validation"""
        request = self.context.get('request')
        
        # Prevent changing user_type to admin/super_admin unless superuser
        if request and 'user_type' in attrs:
            if attrs['user_type'] in ['admin', 'super_admin'] and not request.user.is_superuser:
                raise serializers.ValidationError({
                    'user_type': 'You cannot change to admin or super_admin role'
                })
        
        return attrs
    
    def update(self, instance, validated_data):
        """Handle user update"""
        # Handle profile picture upload
        profile_picture = validated_data.pop('profile_picture', None)
        if profile_picture:
            # Delete old picture if exists
            if instance.profile_picture:
                instance.profile_picture.delete(save=False)
            instance.profile_picture = profile_picture
        
        # Update user
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        instance.save()
        return instance


class UserUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user profile (excluding sensitive fields)"""
    
    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'phone_number', 'location',
            'profile_picture', 'preferences', 'notification_settings'
        ]
        extra_kwargs = {
            'phone_number': {'validators': [validate_phone_number]},
            'profile_picture': {'validators': [validate_image_file]},
        }
    
    def update(self, instance, validated_data):
        """Update user with audit logging"""
        old_data = {
            'first_name': instance.first_name,
            'last_name': instance.last_name,
            'phone_number': instance.phone_number,
        }
        
        # Update user
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        instance.save()
        
        # Create audit log for significant changes
        changes = {}
        for field in ['first_name', 'last_name', 'phone_number']:
            if field in validated_data and getattr(instance, field) != old_data[field]:
                changes[field] = {
                    'from': old_data[field],
                    'to': getattr(instance, field)
                }
        
        if changes:
            AuditLog.objects.create(
                user=instance,
                action='update',
                resource_type='user',
                resource_id=instance.id,
                old_data=old_data,
                new_data={k: validated_data.get(k, getattr(instance, k)) 
                         for k in ['first_name', 'last_name', 'phone_number']},
                changes=changes,
                ip_address=self.context.get('request').META.get('REMOTE_ADDR'),
                user_agent=self.context.get('request').META.get('HTTP_USER_AGENT', ''),
                request_path=self.context.get('request').path,
                request_method=self.context.get('request').method
            )
        
        return instance


class UserProfileUpdateSerializer(UserProfileSerializer):
    """Serializer for updating user profile"""
    
    class Meta(UserProfileSerializer.Meta):
        read_only_fields = ['average_rating', 'total_ratings', 'completed_orders']
    
    def update(self, instance, validated_data):
        """Update user profile with validation"""
        # Validate business fields based on user type
        user = instance.user
        if user.user_type == 'customer':
            business_fields = ['business_name', 'business_registration_number', 
                             'tax_id', 'business_description']
            for field in business_fields:
                if field in validated_data:
                    validated_data.pop(field)
        
        return super().update(instance, validated_data)


# ============ VENDOR SERIALIZERS ============

class VendorSerializer(serializers.ModelSerializer, TimestampSerializer, 
                       SoftDeleteSerializer, AddressSerializer):
    """Serializer for Vendor model"""
    
    user = UserSerializer(read_only=True)
    full_address = serializers.SerializerMethodField(read_only=True)
    is_open_now = serializers.SerializerMethodField(read_only=True)
    verification_status_display = serializers.CharField(
        source='get_verification_status_display',
        read_only=True
    )
    vendor_type_display = serializers.CharField(
        source='get_vendor_type_display',
        read_only=True
    )
    
    class Meta:
        model = Vendor
        fields = [
            # Core
            'id', 'vendor_name', 'vendor_type', 'vendor_type_display', 'user',
            # Contact
            'contact_person', 'contact_email', 'contact_phone', 'website',
            # Address
            'address_line1', 'address_line2', 'city', 'state', 'country',
            'postal_code', 'latitude', 'longitude', 'full_address',
            # Business
            'business_registration_number', 'tax_id', 'license_number',
            'license_expiry',
            # Verification
            'verification_status', 'verification_status_display',
            'verification_documents', 'verified_by', 'verified_at',
            # Operational
            'opening_hours', 'is_24_hours', 'accepts_emergency_calls',
            'is_open_now',
            # Statistics
            'average_rating', 'total_ratings', 'total_orders', 'total_revenue',
            # Media
            'logo', 'banner_image', 'gallery_images',
            # Additional
            'description', 'tags', 'amenities',
            # Timestamps
            'created_at', 'updated_at',
            # Soft delete
            'is_deleted', 'deleted_at'
        ]
        read_only_fields = [
            'id', 'user', 'verified_by', 'verified_at', 'average_rating',
            'total_ratings', 'total_orders', 'total_revenue', 'created_at',
            'updated_at', 'is_deleted', 'deleted_at'
        ]
        extra_kwargs = {
            'contact_phone': {'validators': [validate_phone_number]},
            'contact_email': {'required': True},
            'business_registration_number': {'validators': [validate_business_reg]},
            'opening_hours': {'validators': [validate_opening_hours]},
            'logo': {'validators': [validate_image_file]},
            'banner_image': {'validators': [validate_image_file]},
        }
    
    def get_full_address(self, obj):
        return obj.full_address
    
    def get_is_open_now(self, obj):
        return obj.is_open_now()
    
    def validate(self, attrs):
        """Validate vendor data"""
        request = self.context.get('request')
        
        # Validate opening hours structure
        opening_hours = attrs.get('opening_hours')
        if opening_hours:
            try:
                validate_opening_hours(opening_hours)
            except ValidationError as e:
                raise serializers.ValidationError({
                    'opening_hours': str(e)
                })
        
        # Validate coordinates
        latitude = attrs.get('latitude')
        longitude = attrs.get('longitude')
        if latitude is not None and longitude is not None:
            try:
                validate_coordinates.validate_latitude(latitude)
                validate_coordinates.validate_longitude(longitude)
            except ValidationError as e:
                raise serializers.ValidationError({
                    'coordinates': str(e)
                })
        
        # Validate business registration for certain vendor types
        vendor_type = attrs.get('vendor_type')
        business_reg = attrs.get('business_registration_number')
        
        if vendor_type in ['gas_station', 'hospital'] and not business_reg:
            raise serializers.ValidationError({
                'business_registration_number': 'Business registration number is required for this vendor type'
            })
        
        return attrs
    
    def create(self, validated_data):
        """Create vendor with user association"""
        request = self.context.get('request')
        user = request.user if request else None
        
        if not user:
            raise serializers.ValidationError({
                'detail': 'Authentication required'
            })
        
        # Check if user already has a vendor profile
        if hasattr(user, 'vendor_profile'):
            raise serializers.ValidationError({
                'detail': 'User already has a vendor profile'
            })
        
        # Check user type
        if user.user_type not in ['vendor', 'mechanic']:
            raise serializers.ValidationError({
                'detail': 'User must be registered as vendor or mechanic'
            })
        
        with transaction.atomic():
            # Create vendor
            vendor = Vendor.objects.create(
                user=user,
                **validated_data
            )
            
            # Create audit log
            AuditLog.objects.create(
                user=user,
                action='create',
                resource_type='vendor',
                resource_id=vendor.id,
                new_data={
                    'vendor_name': vendor.vendor_name,
                    'vendor_type': vendor.vendor_type,
                    'verification_status': vendor.verification_status
                },
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                request_path=request.path,
                request_method=request.method
            )
            
            return vendor


class VendorUpdateSerializer(VendorSerializer):
    """Serializer for updating vendor (excluding some fields)"""
    
    class Meta(VendorSerializer.Meta):
        read_only_fields = VendorSerializer.Meta.read_only_fields + [
            'vendor_type', 'user', 'verification_status'
        ]
    
    def update(self, instance, validated_data):
        """Update vendor with audit logging"""
        old_data = {
            'vendor_name': instance.vendor_name,
            'contact_person': instance.contact_person,
            'contact_email': instance.contact_email,
            'contact_phone': instance.contact_phone,
            'description': instance.description,
        }
        
        # Update vendor
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        instance.save()
        
        # Create audit log for significant changes
        changes = {}
        for field in ['vendor_name', 'contact_person', 'contact_email', 
                     'contact_phone', 'description']:
            if field in validated_data and getattr(instance, field) != old_data[field]:
                changes[field] = {
                    'from': old_data[field],
                    'to': getattr(instance, field)
                }
        
        if changes:
            request = self.context.get('request')
            AuditLog.objects.create(
                user=instance.user,
                action='update',
                resource_type='vendor',
                resource_id=instance.id,
                old_data=old_data,
                new_data={k: validated_data.get(k, getattr(instance, k)) 
                         for k in old_data.keys()},
                changes=changes,
                ip_address=request.META.get('REMOTE_ADDR') if request else None,
                user_agent=request.META.get('HTTP_USER_AGENT', '') if request else None,
                request_path=request.path if request else '',
                request_method=request.method if request else ''
            )
        
        return instance


class VendorVerificationSerializer(serializers.ModelSerializer):
    """Serializer for vendor verification"""
    
    class Meta:
        model = Vendor
        fields = ['verification_status', 'verification_documents', 'verified_by', 'verified_at']
        read_only_fields = ['verified_by', 'verified_at']
    
    def validate(self, attrs):
        """Validate verification data"""
        request = self.context.get('request')
        user = request.user if request else None
        
        if not user or user.user_type not in ['admin', 'super_admin']:
            raise serializers.ValidationError({
                'detail': 'Only admins can verify vendors'
            })
        
        verification_status = attrs.get('verification_status')
        if verification_status not in ['verified', 'rejected', 'suspended']:
            raise serializers.ValidationError({
                'verification_status': 'Invalid verification status'
            })
        
        attrs['verified_by'] = user
        attrs['verified_at'] = timezone.now()
        
        return attrs
    
    def update(self, instance, validated_data):
        """Update verification status"""
        old_status = instance.verification_status
        new_status = validated_data.get('verification_status')
        
        instance.verification_status = new_status
        instance.verified_by = validated_data.get('verified_by')
        instance.verified_at = validated_data.get('verified_at')
        
        if 'verification_documents' in validated_data:
            instance.verification_documents = validated_data['verification_documents']
        
        instance.save()
        
        # Create audit log
        request = self.context.get('request')
        AuditLog.objects.create(
            user=validated_data.get('verified_by'),
            action='verify' if new_status == 'verified' else 'update',
            resource_type='vendor',
            resource_id=instance.id,
            old_data={'verification_status': old_status},
            new_data={'verification_status': new_status},
            changes={'verification_status': {'from': old_status, 'to': new_status}},
            ip_address=request.META.get('REMOTE_ADDR') if request else None,
            user_agent=request.META.get('HTTP_USER_AGENT', '') if request else None,
            request_path=request.path if request else '',
            request_method=request.method if request else ''
        )
        
        return instance


# ============ SERVICE SERIALIZERS ============

class ServiceAddonSerializer(serializers.ModelSerializer, TimestampSerializer, SoftDeleteSerializer):
    """Serializer for ServiceAddon"""
    
    class Meta:
        model = ServiceAddon
        fields = [
            'id', 'service', 'name', 'description', 'price',
            'is_available', 'sort_order', 'created_at', 'updated_at',
            'is_deleted', 'deleted_at'
        ]
        read_only_fields = ['id', 'service', 'created_at', 'updated_at', 'is_deleted', 'deleted_at']
    
    def validate_price(self, value):
        """Validate price is non-negative"""
        if value < 0:
            raise serializers.ValidationError('Price cannot be negative')
        return value


class ServiceSerializer(serializers.ModelSerializer, TimestampSerializer, SoftDeleteSerializer):
    """Serializer for Service model"""
    
    vendor_details = serializers.SerializerMethodField(read_only=True)
    addons = ServiceAddonSerializer(many=True, read_only=True)
    is_available_now = serializers.SerializerMethodField(read_only=True)
    service_type_display = serializers.CharField(
        source='get_service_type_display',
        read_only=True
    )
    status_display = serializers.CharField(
        source='get_status_display',
        read_only=True
    )
    
    class Meta:
        model = Service
        fields = [
            # Core
            'id', 'service_name', 'service_type', 'service_type_display',
            'service_code', 'vendor', 'vendor_details',
            # Details
            'description', 'detailed_description',
            # Pricing
            'price', 'currency', 'is_price_negotiable', 'minimum_price',
            # Attributes
            'estimated_duration_minutes', 'service_radius_km',
            # Availability
            'status', 'status_display', 'is_available', 'is_available_now',
            'available_from', 'available_to', 'available_days',
            # Requirements
            'requirements', 'constraints',
            # Media
            'service_images',
            # Statistics
            'total_bookings', 'average_rating',
            # Addons
            'addons',
            # Timestamps
            'created_at', 'updated_at',
            # Soft delete
            'is_deleted', 'deleted_at'
        ]
        read_only_fields = [
            'id', 'service_code', 'vendor_details', 'total_bookings',
            'average_rating', 'created_at', 'updated_at', 'is_deleted', 'deleted_at'
        ]
        extra_kwargs = {
            'vendor': {'write_only': True},
        }
    
    def get_vendor_details(self, obj):
        """Get minimal vendor details"""
        return {
            'id': str(obj.vendor.id),
            'vendor_name': obj.vendor.vendor_name,
            'vendor_type': obj.vendor.vendor_type,
            'average_rating': float(obj.vendor.average_rating),
            'is_verified': obj.vendor.verification_status == 'verified'
        }
    
    def get_is_available_now(self, obj):
        return obj.is_available_now()
    
    def validate(self, attrs):
        """Validate service data"""
        # Validate price
        price = attrs.get('price')
        if price is not None and price < 0:
            raise serializers.ValidationError({
                'price': 'Price cannot be negative'
            })
        
        # Validate minimum price if negotiable
        is_price_negotiable = attrs.get('is_price_negotiable', False)
        minimum_price = attrs.get('minimum_price')
        
        if is_price_negotiable and minimum_price is not None:
            if minimum_price > price:
                raise serializers.ValidationError({
                    'minimum_price': 'Minimum price cannot be greater than base price'
                })
        
        # Validate time ranges
        available_from = attrs.get('available_from')
        available_to = attrs.get('available_to')
        
        if available_from and available_to and available_from >= available_to:
            raise serializers.ValidationError({
                'available_to': 'Available to time must be after available from time'
            })
        
        # Validate service radius
        service_radius_km = attrs.get('service_radius_km')
        if service_radius_km is not None and service_radius_km <= 0:
            raise serializers.ValidationError({
                'service_radius_km': 'Service radius must be greater than 0'
            })
        
        return attrs
    
    def create(self, validated_data):
        """Create service with validation"""
        request = self.context.get('request')
        user = request.user if request else None
        
        if not user:
            raise serializers.ValidationError({
                'detail': 'Authentication required'
            })
        
        vendor = validated_data.get('vendor')
        
        # Check if user owns the vendor
        if vendor.user != user and not user.is_superuser:
            raise serializers.ValidationError({
                'detail': 'You can only create services for your own vendor'
            })
        
        # Check if vendor is verified
        if vendor.verification_status != 'verified':
            raise serializers.ValidationError({
                'detail': 'Vendor must be verified to create services'
            })
        
        with transaction.atomic():
            service = Service.objects.create(**validated_data)
            
            # Create audit log
            AuditLog.objects.create(
                user=user,
                action='create',
                resource_type='service',
                resource_id=service.id,
                new_data={
                    'service_name': service.service_name,
                    'service_type': service.service_type,
                    'price': str(service.price),
                    'vendor': str(vendor.id)
                },
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                request_path=request.path,
                request_method=request.method
            )
            
            return service


class ServiceUpdateSerializer(ServiceSerializer):
    """Serializer for updating service"""
    
    class Meta(ServiceSerializer.Meta):
        read_only_fields = ServiceSerializer.Meta.read_only_fields + [
            'vendor', 'service_type', 'service_code'
        ]


class ServiceSearchSerializer(serializers.Serializer):
    """Serializer for service search"""
    
    query = serializers.CharField(required=False, allow_blank=True)
    service_type = serializers.CharField(required=False)
    min_price = serializers.DecimalField(
        max_digits=10, decimal_places=2, required=False, min_value=0
    )
    max_price = serializers.DecimalField(
        max_digits=10, decimal_places=2, required=False, min_value=0
    )
    latitude = serializers.DecimalField(
        max_digits=10, decimal_places=8, required=False, 
        min_value=-90, max_value=90
    )
    longitude = serializers.DecimalField(
        max_digits=11, decimal_places=8, required=False,
        min_value=-180, max_value=180
    )
    radius_km = serializers.DecimalField(
        max_digits=5, decimal_places=2, required=False, min_value=0.1, max_value=100
    )
    available_now = serializers.BooleanField(required=False, default=False)
    vendor_type = serializers.CharField(required=False)
    
    def validate(self, attrs):
        """Validate search parameters"""
        latitude = attrs.get('latitude')
        longitude = attrs.get('longitude')
        radius_km = attrs.get('radius_km')
        
        # Validate location parameters
        if (latitude is not None and longitude is None) or \
           (latitude is None and longitude is not None):
            raise serializers.ValidationError({
                'detail': 'Both latitude and longitude must be provided for location-based search'
            })
        
        if latitude is not None and longitude is not None and radius_km is None:
            attrs['radius_km'] = 10  # Default radius
        
        # Validate price range
        min_price = attrs.get('min_price')
        max_price = attrs.get('max_price')
        
        if min_price is not None and max_price is not None and min_price > max_price:
            raise serializers.ValidationError({
                'min_price': 'Minimum price cannot be greater than maximum price'
            })
        
        return attrs


# ============ GAS CYLINDER SERIALIZERS ============

class GasCylinderSerializer(serializers.ModelSerializer, TimestampSerializer):
    """Serializer for GasCylinder model"""
    
    vendor_details = serializers.SerializerMethodField(read_only=True)
    available_quantity = serializers.IntegerField(read_only=True)
    gas_type_display = serializers.CharField(
        source='get_gas_type_display',
        read_only=True
    )
    cylinder_size_display = serializers.CharField(
        source='get_cylinder_size_display',
        read_only=True
    )
    needs_restocking = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = GasCylinder
        fields = [
            # Core
            'id', 'vendor', 'vendor_details', 'gas_type', 'gas_type_display',
            'cylinder_size', 'cylinder_size_display', 'sku',
            # Inventory
            'stock_quantity', 'reserved_quantity', 'available_quantity',
            'minimum_stock_level', 'maximum_stock_level', 'needs_restocking',
            # Pricing
            'price_per_unit', 'deposit_amount', 'refill_price',
            # Details
            'brand', 'weight_kg', 'volume_liters',
            # Safety
            'last_inspection_date', 'next_inspection_date', 'certification_number',
            # Status
            'is_available',
            # Timestamps
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'vendor_details', 'available_quantity', 'needs_restocking',
            'created_at', 'updated_at'
        ]
        extra_kwargs = {
            'vendor': {'write_only': True},
            'sku': {'read_only': True},
        }
    
    def get_vendor_details(self, obj):
        """Get minimal vendor details"""
        return {
            'id': str(obj.vendor.id),
            'vendor_name': obj.vendor.vendor_name,
            'is_verified': obj.vendor.verification_status == 'verified'
        }
    
    def validate(self, attrs):
        """Validate gas cylinder data"""
        # Validate stock levels
        stock_quantity = attrs.get('stock_quantity', 0)
        minimum_stock_level = attrs.get('minimum_stock_level')
        maximum_stock_level = attrs.get('maximum_stock_level')
        
        if minimum_stock_level is not None and maximum_stock_level is not None:
            if minimum_stock_level >= maximum_stock_level:
                raise serializers.ValidationError({
                    'minimum_stock_level': 'Minimum stock level must be less than maximum stock level'
                })
        
        # Validate dates
        last_inspection_date = attrs.get('last_inspection_date')
        next_inspection_date = attrs.get('next_inspection_date')
        
        if last_inspection_date and last_inspection_date > timezone.now().date():
            raise serializers.ValidationError({
                'last_inspection_date': 'Last inspection date cannot be in the future'
            })
        
        if next_inspection_date and next_inspection_date <= timezone.now().date():
            raise serializers.ValidationError({
                'next_inspection_date': 'Next inspection date must be in the future'
            })
        
        # Validate prices
        price_per_unit = attrs.get('price_per_unit', 0)
        deposit_amount = attrs.get('deposit_amount', 0)
        refill_price = attrs.get('refill_price')
        
        if price_per_unit < 0:
            raise serializers.ValidationError({
                'price_per_unit': 'Price cannot be negative'
            })
        
        if deposit_amount < 0:
            raise serializers.ValidationError({
                'deposit_amount': 'Deposit amount cannot be negative'
            })
        
        if refill_price is not None and refill_price < 0:
            raise serializers.ValidationError({
                'refill_price': 'Refill price cannot be negative'
            })
        
        return attrs
    
    def create(self, validated_data):
        """Create gas cylinder"""
        request = self.context.get('request')
        user = request.user if request else None
        
        if not user:
            raise serializers.ValidationError({
                'detail': 'Authentication required'
            })
        
        vendor = validated_data.get('vendor')
        
        # Check if user owns the vendor
        if vendor.user != user and not user.is_superuser:
            raise serializers.ValidationError({
                'detail': 'You can only add gas cylinders to your own vendor'
            })
        
        # Check if vendor is a gas station
        if vendor.vendor_type != 'gas_station':
            raise serializers.ValidationError({
                'detail': 'Only gas stations can add gas cylinders'
            })
        
        with transaction.atomic():
            gas_cylinder = GasCylinder.objects.create(**validated_data)
            
            # Create audit log
            AuditLog.objects.create(
                user=user,
                action='create',
                resource_type='gas_cylinder',
                resource_id=gas_cylinder.id,
                new_data={
                    'gas_type': gas_cylinder.gas_type,
                    'cylinder_size': gas_cylinder.cylinder_size,
                    'vendor': str(vendor.id)
                },
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                request_path=request.path,
                request_method=request.method
            )
            
            return gas_cylinder


class GasCylinderInventorySerializer(serializers.Serializer):
    """Serializer for inventory operations"""
    
    quantity = serializers.IntegerField(min_value=1, max_value=1000)
    action = serializers.ChoiceField(choices=['restock', 'reserve', 'release', 'consume'])
    notes = serializers.CharField(required=False, allow_blank=True)
    
    def validate(self, attrs):
        """Validate inventory operation"""
        quantity = attrs['quantity']
        action = attrs['action']
        instance = self.context.get('instance')
        
        if not instance:
            raise serializers.ValidationError({
                'detail': 'Gas cylinder instance required'
            })
        
        # Validate based on action
        if action == 'restock':
            # Restocking is always allowed
            pass
        elif action == 'reserve':
            if quantity > instance.available_quantity:
                raise serializers.ValidationError({
                    'quantity': f'Only {instance.available_quantity} cylinders available'
                })
        elif action == 'release':
            if quantity > instance.reserved_quantity:
                raise serializers.ValidationError({
                    'quantity': f'Only {instance.reserved_quantity} cylinders reserved'
                })
        elif action == 'consume':
            if quantity > instance.available_quantity:
                raise serializers.ValidationError({
                    'quantity': f'Only {instance.available_quantity} cylinders available'
                })
        
        return attrs
    
    def create(self, validated_data):
        """Perform inventory operation"""
        instance = self.context.get('instance')
        action = validated_data['action']
        quantity = validated_data['quantity']
        notes = validated_data.get('notes', '')
        
        request = self.context.get('request')
        user = request.user if request else None
        
        # Perform action
        success = False
        if action == 'restock':
            instance.restock(quantity)
            success = True
        elif action == 'reserve':
            success = instance.reserve(quantity)
        elif action == 'release':
            instance.release(quantity)
            success = True
        elif action == 'consume':
            instance.consume(quantity)
            success = True
        
        # Create audit log
        if success and user:
            AuditLog.objects.create(
                user=user,
                action='update',
                resource_type='gas_cylinder',
                resource_id=instance.id,
                old_data={
                    'stock_quantity': instance.stock_quantity - (quantity if action == 'restock' else 0),
                    'reserved_quantity': instance.reserved_quantity,
                },
                new_data={
                    'stock_quantity': instance.stock_quantity,
                    'reserved_quantity': instance.reserved_quantity,
                },
                changes={
                    'action': action,
                    'quantity': quantity,
                    'notes': notes
                },
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                request_path=request.path,
                request_method=request.method
            )
        
        return {
            'success': success,
            'action': action,
            'quantity': quantity,
            'new_stock': instance.stock_quantity,
            'new_reserved': instance.reserved_quantity,
            'available': instance.available_quantity
        }


# ============ SERVICE AREA SERIALIZERS ============

class ServiceAreaSerializer(serializers.ModelSerializer, TimestampSerializer):
    """Serializer for ServiceArea"""
    
    class Meta:
        model = ServiceArea
        fields = ['id', 'vendor', 'area_name', 'polygon_coordinates', 'is_active', 
                 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def validate_polygon_coordinates(self, value):
        """Validate polygon coordinates"""
        if not isinstance(value, list) or len(value) < 3:
            raise serializers.ValidationError('Polygon must have at least 3 coordinates')
        
        for coord in value:
            if not isinstance(coord, list) or len(coord) != 2:
                raise serializers.ValidationError('Each coordinate must be [longitude, latitude]')
            
            lon, lat = coord
            if not (-180 <= lon <= 180):
                raise serializers.ValidationError('Longitude must be between -180 and 180')
            if not (-90 <= lat <= 90):
                raise serializers.ValidationError('Latitude must be between -90 and 90')
        
        return value


# ============ AUDIT LOG SERIALIZERS ============

class AuditLogSerializer(serializers.ModelSerializer, TimestampSerializer):
    """Serializer for AuditLog"""
    
    user_email = serializers.EmailField(source='user.email', read_only=True, allow_null=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)
    
    class Meta:
        model = AuditLog
        fields = [
            'id', 'user', 'user_email', 'user_session', 'action', 'action_display',
            'resource_type', 'resource_id', 'old_data', 'new_data', 'changes',
            'ip_address', 'user_agent', 'request_path', 'request_method',
            'status_code', 'error_message', 'duration_ms', 'timestamp',
            'created_at', 'updated_at'
        ]
        read_only_fields = fields


# ============ USER SESSION SERIALIZERS ============

class UserSessionSerializer(serializers.ModelSerializer, TimestampSerializer):
    """Serializer for UserSession"""
    
    user_email = serializers.EmailField(source='user.email', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    device_type = serializers.SerializerMethodField(read_only=True)
    is_valid = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = UserSession
        fields = [
            'id', 'user', 'user_email', 'session_key', 'status', 'status_display',
            'user_agent', 'device_info', 'ip_address', 'location_info',
            'login_at', 'last_activity_at', 'expires_at', 'revoked_at',
            'revocation_reason', 'is_mobile', 'is_tablet', 'is_desktop',
            'device_type', 'is_valid', 'created_at', 'updated_at'
        ]
        read_only_fields = fields
    
    def get_device_type(self, obj):
        if obj.is_mobile:
            return 'mobile'
        elif obj.is_tablet:
            return 'tablet'
        elif obj.is_desktop:
            return 'desktop'
        return 'unknown'


# ============ COMPREHENSIVE RESPONSE SERIALIZERS ============

class UserDetailSerializer(UserSerializer):
    """Detailed user serializer with all related data"""
    
    vendor_profile = VendorSerializer(read_only=True)
    sessions = UserSessionSerializer(many=True, read_only=True)
    audit_logs = AuditLogSerializer(many=True, read_only=True)
    
    class Meta(UserSerializer.Meta):
        fields = UserSerializer.Meta.fields + [
            'vendor_profile', 'sessions', 'audit_logs'
        ]


class VendorDetailSerializer(VendorSerializer):
    """Detailed vendor serializer with all related data"""
    
    services = ServiceSerializer(many=True, read_only=True)
    gas_cylinders = GasCylinderSerializer(many=True, read_only=True)
    service_areas = ServiceAreaSerializer(many=True, read_only=True)
    
    class Meta(VendorSerializer.Meta):
        fields = VendorSerializer.Meta.fields + [
            'services', 'gas_cylinders', 'service_areas'
        ]


class ServiceDetailSerializer(ServiceSerializer):
    """Detailed service serializer with all related data"""
    
    vendor_full = VendorSerializer(source='vendor', read_only=True)
    
    class Meta(ServiceSerializer.Meta):
        fields = ServiceSerializer.Meta.fields + ['vendor_full']


# ============ STATISTICS SERIALIZERS ============

class UserStatsSerializer(serializers.Serializer):
    """Serializer for user statistics"""
    
    total_users = serializers.IntegerField()
    verified_users = serializers.IntegerField()
    customer_count = serializers.IntegerField()
    vendor_count = serializers.IntegerField()
    mechanic_count = serializers.IntegerField()
    admin_count = serializers.IntegerField()
    super_admin_count = serializers.IntegerField()
    mfa_enabled_count = serializers.IntegerField()
    locked_accounts = serializers.IntegerField()


class VendorStatsSerializer(serializers.Serializer):
    """Serializer for vendor statistics"""
    
    total_vendors = serializers.IntegerField()
    total_revenue = serializers.DecimalField(max_digits=12, decimal_places=2)
    total_orders = serializers.IntegerField()
    avg_rating = serializers.DecimalField(max_digits=3, decimal_places=2)
    open_now = serializers.IntegerField()


class ServiceStatsSerializer(serializers.Serializer):
    """Serializer for service statistics"""
    
    total_services = serializers.IntegerField()
    total_bookings = serializers.IntegerField()
    avg_price = serializers.DecimalField(max_digits=10, decimal_places=2)
    avg_rating = serializers.DecimalField(max_digits=3, decimal_places=2)
    available_now = serializers.IntegerField()


class DashboardStatsSerializer(serializers.Serializer):
    """Serializer for dashboard statistics"""
    
    users = UserStatsSerializer()
    vendors = VendorStatsSerializer()
    services = ServiceStatsSerializer()
    recent_activity = AuditLogSerializer(many=True)


# ============ FILE UPLOAD SERIALIZERS ============

class FileUploadSerializer(serializers.Serializer):
    """Serializer for file uploads"""
    
    file = serializers.FileField(required=True)
    file_type = serializers.ChoiceField(
        choices=['profile_picture', 'vendor_logo', 'vendor_banner', 'document']
    )
    description = serializers.CharField(required=False, allow_blank=True)
    
    def validate_file(self, value):
        """Validate uploaded file"""
        max_size = 5 * 1024 * 1024  # 5MB
        allowed_types = {
            'profile_picture': ['image/jpeg', 'image/png', 'image/gif'],
            'vendor_logo': ['image/jpeg', 'image/png', 'image/svg+xml'],
            'vendor_banner': ['image/jpeg', 'image/png'],
            'document': ['application/pdf', 'image/jpeg', 'image/png']
        }
        
        file_type = self.initial_data.get('file_type', 'document')
        
        # Check file size
        if value.size > max_size:
            raise serializers.ValidationError(f'File size cannot exceed 5MB')
        
        # Check file type
        if value.content_type not in allowed_types.get(file_type, []):
            raise serializers.ValidationError(
                f'Invalid file type for {file_type}. Allowed: {", ".join(allowed_types[file_type])}'
            )
        
        return value


# ============ VALIDATION ERROR SERIALIZER ============

class ValidationErrorSerializer(serializers.Serializer):
    """Serializer for validation errors"""
    
    detail = serializers.CharField()
    code = serializers.CharField(required=False)
    field = serializers.CharField(required=False)
    
    class Meta:
        fields = ['detail', 'code', 'field']


# ============ PAGINATION SERIALIZERS ============

class PaginatedResponseSerializer(serializers.Serializer):
    """Serializer for paginated responses"""
    
    count = serializers.IntegerField()
    next = serializers.URLField(allow_null=True)
    previous = serializers.URLField(allow_null=True)
    results = serializers.ListField()


# ============ SERIALIZER FACTORY ============

class SerializerFactory:
    """Factory class for creating serializers based on model"""
    
    @staticmethod
    def get_serializer(model_name, action='default'):
        """
        Get appropriate serializer based on model and action
        
        Args:
            model_name: Name of the model
            action: Serializer action (default, create, update, list, detail)
        
        Returns:
            Appropriate serializer class
        """
        serializers_map = {
            'User': {
                'default': UserSerializer,
                'create': RegisterSerializer,
                'update': UserUpdateSerializer,
                'detail': UserDetailSerializer,
                'list': UserSerializer,
            },
            'UserProfile': {
                'default': UserProfileSerializer,
                'update': UserProfileUpdateSerializer,
            },
            'Vendor': {
                'default': VendorSerializer,
                'create': VendorSerializer,
                'update': VendorUpdateSerializer,
                'detail': VendorDetailSerializer,
                'verify': VendorVerificationSerializer,
            },
            'Service': {
                'default': ServiceSerializer,
                'create': ServiceSerializer,
                'update': ServiceUpdateSerializer,
                'detail': ServiceDetailSerializer,
            },
            'ServiceAddon': {
                'default': ServiceAddonSerializer,
            },
            'GasCylinder': {
                'default': GasCylinderSerializer,
                'inventory': GasCylinderInventorySerializer,
            },
            'ServiceArea': {
                'default': ServiceAreaSerializer,
            },
            'UserSession': {
                'default': UserSessionSerializer,
            },
            'AuditLog': {
                'default': AuditLogSerializer,
            },
        }
        
        model_serializers = serializers_map.get(model_name, {})
        return model_serializers.get(action, model_serializers.get('default'))