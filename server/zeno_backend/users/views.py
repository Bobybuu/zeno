"""
Views for Zeno User Application
Robust implementation with authentication, authorization, and business logic
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from django.utils import timezone
from django.db import transaction
from django.db.models import Q, Count, Sum, Avg
from django.shortcuts import get_object_or_404
from django.core.cache import cache
from django.contrib.auth import logout
from django.http import HttpRequest

from rest_framework import viewsets, status, permissions, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle

from .models import User, UserProfile, UserSession, AuditLog
from .serializers import (
    # Authentication
    CustomTokenObtainPairSerializer, RegisterSerializer,
    PasswordResetSerializer, PasswordResetConfirmSerializer,
    VerifyEmailSerializer,
    
    # User Management
    UserSerializer, UserUpdateSerializer, UserDetailSerializer,
    UserProfileSerializer, UserProfileUpdateSerializer,
    
    # Session & Audit
    UserSessionSerializer, AuditLogSerializer,
    
    # Statistics
    UserStatsSerializer, DashboardStatsSerializer,
    
    # File Upload
    FileUploadSerializer,
    
    # Search & Filter
    ValidationErrorSerializer,
    
    # Factory
    SerializerFactory
)
from .permissions import (
    IsOwnerOrReadOnly, IsAdminOrReadOnly,
    IsSuperAdmin, IsVendorOwner, IsCustomer,
    IsVendorOrMechanic, HasUserType
)
from .throttling import (
    BurstRateThrottle, SustainedRateThrottle,
    RegistrationThrottle, LoginThrottle
)
from .filters import UserFilter, AuditLogFilter
from .cognito_client import CognitoClient

logger = logging.getLogger(__name__)


# ============ CUSTOM PAGINATION ============

class StandardResultsSetPagination(PageNumberPagination):
    """Standard pagination for list views"""
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100
    
    def get_paginated_response(self, data):
        return Response({
            'count': self.page.paginator.count,
            'next': self.get_next_link(),
            'previous': self.get_previous_link(),
            'results': data,
            'page': self.page.number,
            'page_size': self.get_page_size(self.request),
            'total_pages': self.page.paginator.num_pages,
        })


class LargeResultsSetPagination(PageNumberPagination):
    """Large pagination for admin views"""
    page_size = 50
    page_size_query_param = 'page_size'
    max_page_size = 200


# ============ BASE VIEWSETS ============

class BaseViewSet(viewsets.ModelViewSet):
    """
    Base ViewSet with common functionality
    """
    
    pagination_class = StandardResultsSetPagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    ordering_fields = ['created_at', 'updated_at', 'email', 'last_login']
    ordering = ['-created_at']
    
    def get_serializer_class(self):
        """
        Dynamically select serializer based on action
        """
        if hasattr(self, 'serializer_class_map'):
            return self.serializer_class_map.get(
                self.action,
                self.serializer_class_map.get('default')
            )
        return super().get_serializer_class()
    
    def get_queryset(self):
        """
        Apply filters and annotations to queryset
        """
        queryset = super().get_queryset()
        
        # Apply model-specific filtering
        if hasattr(self, 'filter_class'):
            filter_class = self.filter_class
            queryset = filter_class(self.request.GET, queryset=queryset).qs
        
        # Apply search
        if self.request.GET.get('search'):
            search_term = self.request.GET['search']
            if hasattr(self, 'search_fields'):
                query = Q()
                for field in self.search_fields:
                    query |= Q(**{f'{field}__icontains': search_term})
                queryset = queryset.filter(query)
        
        # Apply annotations for statistics
        if self.action == 'list':
            # Add annotations for list view if needed
            pass
        
        return queryset.select_related('profile')
    
    def perform_create(self, serializer):
        """
        Perform creation with audit logging
        """
        instance = serializer.save()
        
        # Create audit log
        AuditLog.objects.create(
            user=self.request.user if self.request.user.is_authenticated else None,
            action='create',
            resource_type=self.get_resource_type(),
            resource_id=instance.id,
            new_data=serializer.data,
            ip_address=self.get_client_ip(),
            user_agent=self.get_user_agent(),
            request_path=self.request.path,
            request_method=self.request.method
        )
        
        logger.info(f"{self.get_resource_type()} created: {instance}")
    
    def perform_update(self, serializer):
        """
        Perform update with audit logging
        """
        old_data = self.get_serializer(instance=self.get_object()).data
        instance = serializer.save()
        
        # Calculate changes
        changes = {}
        for key, new_value in serializer.data.items():
            old_value = old_data.get(key)
            if old_value != new_value:
                changes[key] = {'from': old_value, 'to': new_value}
        
        # Create audit log if changes exist
        if changes:
            AuditLog.objects.create(
                user=self.request.user,
                action='update',
                resource_type=self.get_resource_type(),
                resource_id=instance.id,
                old_data=old_data,
                new_data=serializer.data,
                changes=changes,
                ip_address=self.get_client_ip(),
                user_agent=self.get_user_agent(),
                request_path=self.request.path,
                request_method=self.request.method
            )
            
            logger.info(f"{self.get_resource_type()} updated: {instance}")
    
    def perform_destroy(self, instance):
        """
        Perform deletion with audit logging
        """
        old_data = self.get_serializer(instance=instance).data
        
        # Create audit log
        AuditLog.objects.create(
            user=self.request.user,
            action='delete',
            resource_type=self.get_resource_type(),
            resource_id=instance.id,
            old_data=old_data,
            ip_address=self.get_client_ip(),
            user_agent=self.get_user_agent(),
            request_path=self.request.path,
            request_method=self.request.method
        )
        
        logger.info(f"{self.get_resource_type()} deleted: {instance}")
        instance.delete()
    
    def get_resource_type(self):
        """
        Get resource type for audit logging
        """
        return self.queryset.model.__name__
    
    def get_client_ip(self):
        """
        Get client IP address from request
        """
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip
    
    def get_user_agent(self):
        """
        Get user agent from request
        """
        return self.request.META.get('HTTP_USER_AGENT', '')
    
    def handle_exception(self, exc):
        """
        Custom exception handling with logging
        """
        logger.error(f"Error in {self.__class__.__name__}.{self.action}: {str(exc)}")
        
        # Create audit log for errors
        if self.request.user.is_authenticated:
            AuditLog.objects.create(
                user=self.request.user,
                action='error',
                resource_type=self.get_resource_type(),
                details={'error': str(exc), 'action': self.action},
                ip_address=self.get_client_ip(),
                user_agent=self.get_user_agent(),
                request_path=self.request.path,
                request_method=self.request.method,
                error_message=str(exc)
            )
        
        return super().handle_exception(exc)


# ============ AUTHENTICATION VIEWS ============

class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom JWT token obtain view with rate limiting
    """
    
    serializer_class = CustomTokenObtainPairSerializer
    throttle_classes = [LoginThrottle]
    
    def post(self, request, *args, **kwargs):
        """
        Handle login with additional security checks
        """
        try:
            response = super().post(request, *args, **kwargs)
            
            # Set secure cookies for session management
            if response.status_code == 200:
                self.set_session_cookies(request, response)
            
            return response
            
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return Response(
                {'detail': 'Authentication failed'},
                status=status.HTTP_401_UNAUTHORIZED
            )
    
    def set_session_cookies(self, request, response):
        """
        Set secure HTTP-only cookies for session management
        """
        # Set session cookie
        if request.session.session_key:
            response.set_cookie(
                key='sessionid',
                value=request.session.session_key,
                httponly=True,
                secure=not settings.DEBUG,
                samesite='Lax',
                max_age=settings.SESSION_COOKIE_AGE
            )
        
        # Set CSRF token cookie
        response.set_cookie(
            key='csrftoken',
            value=request.META.get('CSRF_COOKIE', ''),
            httponly=False,  # JavaScript needs to read this
            secure=not settings.DEBUG,
            samesite='Lax'
        )


class CustomTokenRefreshView(TokenRefreshView):
    """
    Custom JWT token refresh view
    """
    
    throttle_classes = [BurstRateThrottle]
    
    def post(self, request, *args, **kwargs):
        """
        Handle token refresh with validation
        """
        try:
            response = super().post(request, *args, **kwargs)
            
            # Validate refresh token against user record
            if response.status_code == 200:
                refresh_token = request.data.get('refresh')
                if refresh_token:
                    # Get user from refresh token
                    from rest_framework_simplejwt.tokens import RefreshToken
                    try:
                        token = RefreshToken(refresh_token)
                        user_id = token['user_id']
                        user = User.objects.get(id=user_id)
                        
                        # Check if refresh token matches stored token
                        if not user.is_jwt_refresh_token_valid(refresh_token):
                            return Response(
                                {'detail': 'Invalid refresh token'},
                                status=status.HTTP_401_UNAUTHORIZED
                            )
                    except Exception as e:
                        logger.error(f"Refresh token validation error: {str(e)}")
                        # Continue anyway - the token will be validated by JWT itself
            
            return response
            
        except Exception as e:
            logger.error(f"Token refresh error: {str(e)}")
            return Response(
                {'detail': 'Token refresh failed'},
                status=status.HTTP_401_UNAUTHORIZED
            )


class LogoutView(APIView):
    """
    Handle user logout with session cleanup
    """
    
    permission_classes = [IsAuthenticated]
    throttle_classes = [BurstRateThrottle]
    
    def post(self, request):
        """
        Logout user and invalidate tokens
        """
        try:
            user = request.user
            
            # Invalidate JWT refresh token
            user.jwt_refresh_token = None
            user.jwt_refresh_token_expiry = None
            user.session_key = None
            user.session_expiry = None
            user.save(
                update_fields=[
                    'jwt_refresh_token',
                    'jwt_refresh_token_expiry',
                    'session_key',
                    'session_expiry'
                ]
            )
            
            # Revoke active sessions
            active_sessions = UserSession.objects.filter(
                user=user,
                status='active',
                expires_at__gt=timezone.now()
            )
            
            revoked_count = active_sessions.update(
                status='revoked',
                revoked_at=timezone.now(),
                revocation_reason='logout'
            )
            
            # Clear session data
            logout(request)
            
            # Clear cookies
            response = Response({'detail': 'Logout successful'})
            response.delete_cookie('sessionid')
            response.delete_cookie('csrftoken')
            
            # Create audit log
            AuditLog.objects.create(
                user=user,
                action='logout',
                resource_type='user',
                resource_id=user.id,
                ip_address=self.get_client_ip(request),
                user_agent=self.get_user_agent(request),
                request_path=request.path,
                request_method=request.method
            )
            
            logger.info(f"User {user.email} logged out. Revoked {revoked_count} sessions.")
            
            return response
            
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
            return Response(
                {'detail': 'Logout failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def get_user_agent(self, request):
        """Get user agent"""
        return request.META.get('HTTP_USER_AGENT', '')


class LogoutAllView(APIView):
    """
    Logout user from all devices
    """
    
    permission_classes = [IsAuthenticated]
    throttle_classes = [BurstRateThrottle]
    
    def post(self, request):
        """
        Logout user from all sessions
        """
        try:
            user = request.user
            
            # Revoke all active sessions
            revoked_count = UserSession.objects.revoke_all_user_sessions(user.id, 'logout_all')
            
            # Clear all session data
            user.invalidate_session()
            user.jwt_refresh_token = None
            user.jwt_refresh_token_expiry = None
            user.save(
                update_fields=[
                    'session_key',
                    'session_expiry',
                    'jwt_refresh_token',
                    'jwt_refresh_token_expiry'
                ]
            )
            
            # Clear current session
            logout(request)
            
            # Clear cookies
            response = Response({
                'detail': 'Logged out from all devices',
                'sessions_revoked': revoked_count
            })
            response.delete_cookie('sessionid')
            response.delete_cookie('csrftoken')
            
            # Create audit log
            AuditLog.objects.create(
                user=user,
                action='logout_all',
                resource_type='user',
                resource_id=user.id,
                ip_address=self.get_client_ip(request),
                user_agent=self.get_user_agent(request),
                request_path=request.path,
                request_method=request.method,
                details={'sessions_revoked': revoked_count}
            )
            
            logger.info(f"User {user.email} logged out from all devices. Revoked {revoked_count} sessions.")
            
            return response
            
        except Exception as e:
            logger.error(f"Logout all error: {str(e)}")
            return Response(
                {'detail': 'Logout failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def get_user_agent(self, request):
        """Get user agent"""
        return request.META.get('HTTP_USER_AGENT', '')


# ============ REGISTRATION & VERIFICATION VIEWS ============

class RegisterView(APIView):
    """
    Handle user registration with AWS Cognito integration
    """
    
    throttle_classes = [RegistrationThrottle]
    
    def post(self, request):
        """
        Register new user
        """
        serializer = RegisterSerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            try:
                with transaction.atomic():
                    user = serializer.save()
                    
                    # Create audit log
                    AuditLog.objects.create(
                        action='register',
                        resource_type='user',
                        resource_id=user.id,
                        new_data={'email': user.email, 'user_type': user.user_type},
                        ip_address=self.get_client_ip(request),
                        user_agent=self.get_user_agent(request),
                        request_path=request.path,
                        request_method=request.method
                    )
                    
                    logger.info(f"New user registered: {user.email} ({user.user_type})")
                    
                    return Response(
                        serializer.data,
                        status=status.HTTP_201_CREATED
                    )
                    
            except Exception as e:
                logger.error(f"Registration failed: {str(e)}")
                return Response(
                    {'detail': 'Registration failed. Please try again.'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def get_user_agent(self, request):
        """Get user agent"""
        return request.META.get('HTTP_USER_AGENT', '')


class VerifyEmailView(APIView):
    """
    Handle email verification via AWS Cognito
    """
    
    throttle_classes = [BurstRateThrottle]
    
    def post(self, request):
        """
        Verify user email
        """
        serializer = VerifyEmailSerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            try:
                result = serializer.save()
                return Response(result, status=status.HTTP_200_OK)
                
            except Exception as e:
                logger.error(f"Email verification failed: {str(e)}")
                return Response(
                    {'detail': 'Email verification failed'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResendVerificationEmailView(APIView):
    """
    Resend email verification code
    """
    
    throttle_classes = [BurstRateThrottle]
    
    def post(self, request):
        """
        Resend verification email
        """
        email = request.data.get('email', '').lower()
        
        if not email:
            return Response(
                {'email': 'Email is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = User.objects.get(email=email)
            
            if user.email_verified:
                return Response(
                    {'detail': 'Email already verified'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Resend verification via AWS Cognito
            cognito_client = CognitoClient()
            cognito_client.resend_verification_email(email)
            
            # Create audit log
            AuditLog.objects.create(
                user=user,
                action='resend_verification',
                resource_type='user',
                resource_id=user.id,
                ip_address=self.get_client_ip(request),
                user_agent=self.get_user_agent(request),
                request_path=request.path,
                request_method=request.method
            )
            
            logger.info(f"Verification email resent to: {email}")
            
            return Response({
                'detail': 'Verification email sent successfully',
                'email': email
            })
            
        except User.DoesNotExist:
            # Don't reveal if user exists for security
            return Response({
                'detail': 'If your email is registered, you will receive a verification code'
            })
        
        except Exception as e:
            logger.error(f"Failed to resend verification email: {str(e)}")
            return Response(
                {'detail': 'Failed to resend verification email'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def get_user_agent(self, request):
        """Get user agent"""
        return request.META.get('HTTP_USER_AGENT', '')


# ============ PASSWORD MANAGEMENT VIEWS ============

class PasswordResetView(APIView):
    """
    Handle password reset requests
    """
    
    throttle_classes = [BurstRateThrottle]
    
    def post(self, request):
        """
        Initiate password reset
        """
        serializer = PasswordResetSerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            try:
                serializer.save()
                
                # Always return success for security
                return Response({
                    'detail': 'If your email is registered, you will receive password reset instructions',
                    'email': serializer.data['email']
                })
                
            except Exception as e:
                logger.error(f"Password reset request failed: {str(e)}")
                # Still return success for security
                return Response({
                    'detail': 'If your email is registered, you will receive password reset instructions'
                })
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmView(APIView):
    """
    Confirm password reset
    """
    
    throttle_classes = [BurstRateThrottle]
    
    def post(self, request):
        """
        Confirm password reset with verification code
        """
        serializer = PasswordResetConfirmSerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            try:
                result = serializer.save()
                return Response(result, status=status.HTTP_200_OK)
                
            except Exception as e:
                logger.error(f"Password reset confirmation failed: {str(e)}")
                return Response(
                    {'detail': 'Password reset failed. Invalid verification code or expired.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):
    """
    Change password for authenticated users
    """
    
    permission_classes = [IsAuthenticated]
    throttle_classes = [BurstRateThrottle]
    
    def post(self, request):
        """
        Change user password
        """
        user = request.user
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')
        
        if not current_password or not new_password:
            return Response(
                {'detail': 'Current password and new password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate new password
        from .validators import validate_password
        try:
            validate_password(new_password)
        except Exception as e:
            return Response(
                {'new_password': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check current password
        if not user.check_password(current_password):
            return Response(
                {'current_password': 'Current password is incorrect'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Change password in AWS Cognito
            cognito_client = CognitoClient()
            cognito_client.change_password(
                email=user.email,
                current_password=current_password,
                new_password=new_password
            )
            
            # Update password in Django
            user.set_password(new_password)
            user.save(update_fields=['password', 'last_password_change'])
            
            # Create audit log
            AuditLog.objects.create(
                user=user,
                action='change_password',
                resource_type='user',
                resource_id=user.id,
                ip_address=self.get_client_ip(request),
                user_agent=self.get_user_agent(request),
                request_path=request.path,
                request_method=request.method
            )
            
            logger.info(f"Password changed for user: {user.email}")
            
            return Response({
                'detail': 'Password changed successfully'
            })
            
        except Exception as e:
            logger.error(f"Password change failed: {str(e)}")
            return Response(
                {'detail': 'Password change failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def get_user_agent(self, request):
        """Get user agent"""
        return request.META.get('HTTP_USER_AGENT', '')


# ============ USER VIEWSET ============

class UserViewSet(BaseViewSet):
    """
    ViewSet for User model management
    """
    
    queryset = User.objects.filter(is_deleted=False).select_related('profile')
    serializer_class = UserSerializer
    filter_class = UserFilter
    
    # Different serializers for different actions
    serializer_class_map = {
        'default': UserSerializer,
        'create': RegisterSerializer,
        'update': UserUpdateSerializer,
        'partial_update': UserUpdateSerializer,
        'retrieve': UserDetailSerializer,
        'list': UserSerializer,
        'profile': UserProfileSerializer,
        'sessions': UserSessionSerializer,
        'audit_logs': AuditLogSerializer,
    }
    
    # Search fields
    search_fields = ['email', 'first_name', 'last_name', 'phone_number', 'username']
    
    # Permissions
    def get_permissions(self):
        """
        Instantiate and return the list of permissions that this view requires.
        """
        if self.action in ['create', 'verify_email', 'resend_verification']:
            permission_classes = [permissions.AllowAny]
        elif self.action in ['list', 'retrieve']:
            permission_classes = [IsAuthenticated]
        elif self.action in ['update', 'partial_update', 'destroy', 'profile']:
            permission_classes = [IsOwnerOrReadOnly]
        elif self.action in ['admin_list', 'admin_retrieve', 'stats', 'dashboard']:
            permission_classes = [IsAdminUser]
        elif self.action in ['sessions', 'audit_logs']:
            permission_classes = [IsOwnerOrReadOnly]
        else:
            permission_classes = [IsAuthenticated]
        
        return [permission() for permission in permission_classes]
    
    # Throttling
    throttle_classes = [UserRateThrottle]
    
    # Custom actions
    @action(detail=False, methods=['get'])
    def me(self, request):
        """
        Get current user profile
        """
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)
    
    @action(detail=False, methods=['put', 'patch'])
    def update_me(self, request):
        """
        Update current user profile
        """
        serializer = UserUpdateSerializer(
            request.user,
            data=request.data,
            partial=True,
            context={'request': request}
        )
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['get'])
    def profile(self, request):
        """
        Get current user's profile
        """
        user = request.user
        profile = getattr(user, 'profile', None)
        
        if not profile:
            return Response(
                {'detail': 'Profile not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = UserProfileSerializer(profile, context={'request': request})
        return Response(serializer.data)
    
    @action(detail=False, methods=['put', 'patch'])
    def update_profile(self, request):
        """
        Update current user's profile
        """
        user = request.user
        profile = getattr(user, 'profile', None)
        
        if not profile:
            return Response(
                {'detail': 'Profile not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = UserProfileUpdateSerializer(
            profile,
            data=request.data,
            partial=True,
            context={'request': request}
        )
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['get'])
    def sessions(self, request, pk=None):
        """
        Get user's active sessions
        """
        user = self.get_object()
        
        # Check permission
        if user != request.user and not request.user.is_staff:
            return Response(
                {'detail': 'You do not have permission to view these sessions'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        sessions = UserSession.objects.filter(user=user).order_by('-login_at')
        page = self.paginate_queryset(sessions)
        
        if page is not None:
            serializer = UserSessionSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = UserSessionSerializer(sessions, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def audit_logs(self, request, pk=None):
        """
        Get user's audit logs
        """
        user = self.get_object()
        
        # Check permission
        if user != request.user and not request.user.is_staff:
            return Response(
                {'detail': 'You do not have permission to view these logs'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        audit_logs = AuditLog.objects.filter(user=user).order_by('-created_at')
        page = self.paginate_queryset(audit_logs)
        
        if page is not None:
            serializer = AuditLogSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = AuditLogSerializer(audit_logs, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """
        Get user statistics (admin only)
        """
        cache_key = 'user_stats'
        cached_data = cache.get(cache_key)
        
        if cached_data:
            return Response(cached_data)
        
        stats = User.objects.get_user_stats()
        serializer = UserStatsSerializer(stats)
        
        # Cache for 5 minutes
        cache.set(cache_key, serializer.data, 300)
        
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def dashboard(self, request):
        """
        Get dashboard statistics (admin only)
        """
        cache_key = f'dashboard_stats_{request.user.id}'
        cached_data = cache.get(cache_key)
        
        if cached_data:
            return Response(cached_data)
        
        # Get user stats
        user_stats = User.objects.get_user_stats()
        
        # Get recent activity (last 24 hours)
        recent_activity = AuditLog.objects.filter(
            created_at__gte=timezone.now() - timedelta(hours=24)
        ).order_by('-created_at')[:20]
        
        dashboard_data = {
            'users': user_stats,
            'recent_activity': AuditLogSerializer(recent_activity, many=True).data
        }
        
        serializer = DashboardStatsSerializer(dashboard_data)
        
        # Cache for 1 minute
        cache.set(cache_key, serializer.data, 60)
        
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def activate(self, request, pk=None):
        """
        Activate user account (admin only)
        """
        if not request.user.is_staff:
            return Response(
                {'detail': 'Only staff members can activate accounts'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        user = self.get_object()
        
        if user.is_active:
            return Response(
                {'detail': 'User is already active'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user.is_active = True
        user.save(update_fields=['is_active'])
        
        # Create audit log
        AuditLog.objects.create(
            user=request.user,
            action='activate',
            resource_type='user',
            resource_id=user.id,
            ip_address=self.get_client_ip(),
            user_agent=self.get_user_agent(),
            request_path=request.path,
            request_method=request.method,
            details={'activated_by': request.user.email}
        )
        
        logger.info(f"User {user.email} activated by {request.user.email}")
        
        return Response({
            'detail': 'User activated successfully',
            'user': {
                'id': str(user.id),
                'email': user.email,
                'is_active': user.is_active
            }
        })
    
    @action(detail=True, methods=['post'])
    def deactivate(self, request, pk=None):
        """
        Deactivate user account (admin only)
        """
        if not request.user.is_staff:
            return Response(
                {'detail': 'Only staff members can deactivate accounts'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        user = self.get_object()
        
        if not user.is_active:
            return Response(
                {'detail': 'User is already inactive'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Cannot deactivate yourself
        if user == request.user:
            return Response(
                {'detail': 'You cannot deactivate your own account'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user.is_active = False
        user.save(update_fields=['is_active'])
        
        # Create audit log
        AuditLog.objects.create(
            user=request.user,
            action='deactivate',
            resource_type='user',
            resource_id=user.id,
            ip_address=self.get_client_ip(),
            user_agent=self.get_user_agent(),
            request_path=request.path,
            request_method=request.method,
            details={'deactivated_by': request.user.email}
        )
        
        logger.info(f"User {user.email} deactivated by {request.user.email}")
        
        return Response({
            'detail': 'User deactivated successfully',
            'user': {
                'id': str(user.id),
                'email': user.email,
                'is_active': user.is_active
            }
        })
    
    @action(detail=True, methods=['post'])
    def lock(self, request, pk=None):
        """
        Lock user account (admin only)
        """
        if not request.user.is_staff:
            return Response(
                {'detail': 'Only staff members can lock accounts'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        user = self.get_object()
        duration_minutes = request.data.get('duration_minutes', 30)
        
        if user.is_account_locked():
            return Response(
                {'detail': 'User account is already locked'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user.account_locked_until = timezone.now() + timedelta(minutes=duration_minutes)
        user.save(update_fields=['account_locked_until'])
        
        # Create audit log
        AuditLog.objects.create(
            user=request.user,
            action='lock_account',
            resource_type='user',
            resource_id=user.id,
            ip_address=self.get_client_ip(),
            user_agent=self.get_user_agent(),
            request_path=request.path,
            request_method=request.method,
            details={
                'locked_by': request.user.email,
                'duration_minutes': duration_minutes,
                'locked_until': user.account_locked_until.isoformat()
            }
        )
        
        logger.info(f"User {user.email} locked by {request.user.email} for {duration_minutes} minutes")
        
        return Response({
            'detail': f'User account locked for {duration_minutes} minutes',
            'user': {
                'id': str(user.id),
                'email': user.email,
                'account_locked_until': user.account_locked_until
            }
        })
    
    @action(detail=True, methods=['post'])
    def unlock(self, request, pk=None):
        """
        Unlock user account (admin only)
        """
        if not request.user.is_staff:
            return Response(
                {'detail': 'Only staff members can unlock accounts'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        user = self.get_object()
        
        if not user.is_account_locked():
            return Response(
                {'detail': 'User account is not locked'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user.account_locked_until = None
        user.failed_login_attempts = 0
        user.save(update_fields=['account_locked_until', 'failed_login_attempts'])
        
        # Create audit log
        AuditLog.objects.create(
            user=request.user,
            action='unlock_account',
            resource_type='user',
            resource_id=user.id,
            ip_address=self.get_client_ip(),
            user_agent=self.get_user_agent(),
            request_path=request.path,
            request_method=request.method,
            details={'unlocked_by': request.user.email}
        )
        
        logger.info(f"User {user.email} unlocked by {request.user.email}")
        
        return Response({
            'detail': 'User account unlocked successfully',
            'user': {
                'id': str(user.id),
                'email': user.email,
                'account_locked_until': user.account_locked_until,
                'failed_login_attempts': user.failed_login_attempts
            }
        })
    
    @action(detail=False, methods=['get'], url_path='search')
    def search_users(self, request):
        """
        Search users by various criteria
        """
        query = request.query_params.get('q', '')
        user_type = request.query_params.get('user_type')
        email_verified = request.query_params.get('email_verified')
        is_active = request.query_params.get('is_active')
        
        queryset = User.objects.filter(is_deleted=False)
        
        # Apply search
        if query:
            queryset = queryset.search_users(query)
        
        # Apply filters
        if user_type:
            queryset = queryset.filter(user_type=user_type)
        
        if email_verified is not None:
            queryset = queryset.filter(email_verified=email_verified.lower() == 'true')
        
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        
        # Paginate results
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = UserSerializer(page, many=True, context={'request': request})
            return self.get_paginated_response(serializer.data)
        
        serializer = UserSerializer(queryset, many=True, context={'request': request})
        return Response(serializer.data)
    
    def list(self, request):
        """
        List users with filters (admin only for full list)
        """
        # Non-admin users can only see limited information
        if not request.user.is_staff:
            # Regular users can only see themselves
            queryset = User.objects.filter(id=request.user.id)
        else:
            queryset = self.filter_queryset(self.get_queryset())
        
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    
    def retrieve(self, request, pk=None):
        """
        Retrieve user details
        """
        user = self.get_object()
        
        # Non-admin users can only see their own details
        if not request.user.is_staff and user != request.user:
            return Response(
                {'detail': 'You do not have permission to view this user'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = self.get_serializer(user)
        return Response(serializer.data)
    
    def update(self, request, pk=None):
        """
        Update user
        """
        user = self.get_object()
        
        # Check permissions
        if not request.user.is_staff and user != request.user:
            return Response(
                {'detail': 'You can only update your own profile'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Prevent users from changing certain fields
        if not request.user.is_staff:
            restricted_fields = ['user_type', 'is_staff', 'is_superuser', 'is_active']
            for field in restricted_fields:
                if field in request.data:
                    return Response(
                        {field: 'You cannot change this field'},
                        status=status.HTTP_403_FORBIDDEN
                    )
        
        serializer = self.get_serializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def destroy(self, request, pk=None):
        """
        Delete user (soft delete)
        """
        user = self.get_object()
        
        # Check permissions
        if not request.user.is_staff and user != request.user:
            return Response(
                {'detail': 'You can only delete your own account'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Cannot delete yourself if you're an admin
        if request.user.is_staff and user == request.user:
            return Response(
                {'detail': 'Admin users cannot delete their own accounts'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Soft delete
        user.soft_delete()
        
        # Create audit log
        AuditLog.objects.create(
            user=request.user,
            action='delete',
            resource_type='user',
            resource_id=user.id,
            ip_address=self.get_client_ip(),
            user_agent=self.get_user_agent(),
            request_path=request.path,
            request_method=request.method,
            details={'deleted_by': request.user.email}
        )
        
        logger.info(f"User {user.email} deleted by {request.user.email}")
        
        return Response(
            {'detail': 'User deleted successfully'},
            status=status.HTTP_204_NO_CONTENT
        )


# ============ USER PROFILE VIEWSET ============

class UserProfileViewSet(viewsets.ModelViewSet):
    """
    ViewSet for UserProfile management
    """
    
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated, IsOwnerOrReadOnly]
    throttle_classes = [UserRateThrottle]
    
    def get_queryset(self):
        """
        Users can only see their own profile unless they're staff
        """
        user = self.request.user
        if user.is_staff:
            return UserProfile.objects.all()
        return UserProfile.objects.filter(user=user)
    
    def get_object(self):
        """
        Get profile by user ID or profile ID
        """
        # If using user ID in URL
        if 'user_pk' in self.kwargs:
            user_id = self.kwargs['user_pk']
            user = get_object_or_404(User, id=user_id)
            return get_object_or_404(UserProfile, user=user)
        
        # Default behavior
        return super().get_object()
    
    def perform_create(self, serializer):
        """
        Create user profile
        """
        user = self.request.user
        
        # Check if profile already exists
        if hasattr(user, 'profile'):
            raise serializers.ValidationError({
                'detail': 'User already has a profile'
            })
        
        profile = serializer.save(user=user)
        
        # Create audit log
        AuditLog.objects.create(
            user=user,
            action='create',
            resource_type='user_profile',
            resource_id=profile.user_id,
            ip_address=self.get_client_ip(),
            user_agent=self.get_user_agent(),
            request_path=self.request.path,
            request_method=self.request.method
        )
        
        logger.info(f"Profile created for user: {user.email}")
    
    def perform_update(self, serializer):
        """
        Update user profile with audit logging
        """
        profile = self.get_object()
        old_data = UserProfileSerializer(profile).data
        
        updated_profile = serializer.save()
        
        # Calculate changes
        changes = {}
        for key, new_value in serializer.data.items():
            old_value = old_data.get(key)
            if old_value != new_value:
                changes[key] = {'from': old_value, 'to': new_value}
        
        # Create audit log if changes exist
        if changes:
            AuditLog.objects.create(
                user=self.request.user,
                action='update',
                resource_type='user_profile',
                resource_id=profile.user_id,
                old_data=old_data,
                new_data=serializer.data,
                changes=changes,
                ip_address=self.get_client_ip(),
                user_agent=self.get_user_agent(),
                request_path=self.request.path,
                request_method=self.request.method
            )
            
            logger.info(f"Profile updated for user: {profile.user.email}")
    
    def get_client_ip(self):
        """Get client IP address"""
        request = self.request
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def get_user_agent(self):
        """Get user agent"""
        return self.request.META.get('HTTP_USER_AGENT', '')


# ============ USER SESSION VIEWSET ============

class UserSessionViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for UserSession management (read-only)
    """
    
    queryset = UserSession.objects.all()
    serializer_class = UserSessionSerializer
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    pagination_class = StandardResultsSetPagination
    
    def get_queryset(self):
        """
        Users can only see their own sessions unless they're staff
        """
        user = self.request.user
        if user.is_staff:
            return UserSession.objects.all()
        return UserSession.objects.filter(user=user)
    
    @action(detail=True, methods=['post'])
    def revoke(self, request, pk=None):
        """
        Revoke a specific session
        """
        session = self.get_object()
        
        # Check permissions
        if not request.user.is_staff and session.user != request.user:
            return Response(
                {'detail': 'You can only revoke your own sessions'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        session.revoke('manual_revocation')
        
        # Create audit log
        AuditLog.objects.create(
            user=request.user,
            action='revoke_session',
            resource_type='user_session',
            resource_id=session.id,
            ip_address=self.get_client_ip(request),
            user_agent=self.get_user_agent(request),
            request_path=request.path,
            request_method=request.method,
            details={'session_user': session.user.email}
        )
        
        logger.info(f"Session revoked: {session.session_key[:10]}... for user {session.user.email}")
        
        return Response({'detail': 'Session revoked successfully'})
    
    @action(detail=False, methods=['get'])
    def active(self, request):
        """
        Get active sessions for current user
        """
        sessions = UserSession.objects.filter(
            user=request.user,
            status='active',
            expires_at__gt=timezone.now()
        ).order_by('-login_at')
        
        page = self.paginate_queryset(sessions)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(sessions, many=True)
        return Response(serializer.data)
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def get_user_agent(self, request):
        """Get user agent"""
        return request.META.get('HTTP_USER_AGENT', '')


# ============ AUDIT LOG VIEWSET ============

class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for AuditLog management (read-only, admin only)
    """
    
    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = [IsAdminUser]
    throttle_classes = [UserRateThrottle]
    filter_class = AuditLogFilter
    pagination_class = LargeResultsSetPagination
    ordering_fields = ['created_at', 'timestamp']
    ordering = ['-created_at']
    
    @action(detail=False, methods=['get'])
    def recent(self, request):
        """
        Get recent audit logs (last 24 hours)
        """
        recent_logs = AuditLog.objects.filter(
            created_at__gte=timezone.now() - timedelta(hours=24)
        ).order_by('-created_at')
        
        page = self.paginate_queryset(recent_logs)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(recent_logs, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def user_activity(self, request):
        """
        Get activity for a specific user
        """
        user_id = request.query_params.get('user_id')
        email = request.query_params.get('email')
        
        if not user_id and not email:
            return Response(
                {'detail': 'user_id or email parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if user_id:
            user = get_object_or_404(User, id=user_id)
        else:
            user = get_object_or_404(User, email=email.lower())
        
        logs = AuditLog.objects.filter(user=user).order_by('-created_at')
        
        page = self.paginate_queryset(logs)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(logs, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['delete'])
    def cleanup(self, request):
        """
        Cleanup old audit logs (older than 90 days)
        """
        days = int(request.query_params.get('days', 90))
        
        if days < 30:
            return Response(
                {'detail': 'Minimum cleanup period is 30 days'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        deleted_count = AuditLog.objects.cleanup_old_logs(days)
        
        # Create audit log for cleanup
        AuditLog.objects.create(
            user=request.user,
            action='cleanup_audit_logs',
            resource_type='system',
            details={'days': days, 'deleted_count': deleted_count},
            ip_address=self.get_client_ip(request),
            user_agent=self.get_user_agent(request),
            request_path=request.path,
            request_method=request.method
        )
        
        logger.info(f"Audit logs cleaned up: {deleted_count} logs older than {days} days deleted")
        
        return Response({
            'detail': f'Cleaned up {deleted_count} audit logs older than {days} days'
        })
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def get_user_agent(self, request):
        """Get user agent"""
        return request.META.get('HTTP_USER_AGENT', '')


# ============ FILE UPLOAD VIEW ============

class FileUploadView(APIView):
    """
    Handle file uploads for user profiles and vendor documents
    """
    
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    
    def post(self, request):
        """
        Upload file and return URL
        """
        serializer = FileUploadSerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            try:
                file = serializer.validated_data['file']
                file_type = serializer.validated_data['file_type']
                description = serializer.validated_data.get('description', '')
                
                # Generate unique filename
                import uuid
                import os
                
                ext = os.path.splitext(file.name)[1]
                filename = f"{uuid.uuid4()}{ext}"
                
                # Determine upload path based on file type
                if file_type == 'profile_picture':
                    upload_path = f'profile_pictures/{request.user.id}/{filename}'
                elif file_type == 'vendor_logo':
                    upload_path = f'vendor_logos/{request.user.id}/{filename}'
                elif file_type == 'vendor_banner':
                    upload_path = f'vendor_banners/{request.user.id}/{filename}'
                else:  # document
                    upload_path = f'documents/{request.user.id}/{filename}'
                
                # Save file (using Django's FileSystemStorage or S3)
                from django.core.files.storage import default_storage
                saved_path = default_storage.save(upload_path, file)
                
                # Get URL
                file_url = default_storage.url(saved_path)
                
                # Create audit log
                AuditLog.objects.create(
                    user=request.user,
                    action='upload_file',
                    resource_type='file',
                    details={
                        'file_type': file_type,
                        'filename': filename,
                        'description': description,
                        'url': file_url
                    },
                    ip_address=self.get_client_ip(request),
                    user_agent=self.get_user_agent(request),
                    request_path=request.path,
                    request_method=request.method
                )
                
                logger.info(f"File uploaded by {request.user.email}: {filename} ({file_type})")
                
                return Response({
                    'url': file_url,
                    'filename': filename,
                    'file_type': file_type,
                    'description': description,
                    'uploaded_at': timezone.now().isoformat()
                })
                
            except Exception as e:
                logger.error(f"File upload failed: {str(e)}")
                return Response(
                    {'detail': 'File upload failed'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def get_user_agent(self, request):
        """Get user agent"""
        return request.META.get('HTTP_USER_AGENT', '')


# ============ HEALTH CHECK VIEW ============

class HealthCheckView(APIView):
    """
    Health check endpoint for monitoring
    """
    
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        """
        Check application health
        """
        from django.db import connection
        from django.core.cache import cache
        
        checks = {
            'status': 'healthy',
            'timestamp': timezone.now().isoformat(),
            'components': {}
        }
        
        # Check database
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            checks['components']['database'] = 'healthy'
        except Exception as e:
            checks['components']['database'] = 'unhealthy'
            checks['status'] = 'degraded'
        
        # Check cache
        try:
            cache.set('health_check', 'test', 1)
            cache.get('health_check')
            checks['components']['cache'] = 'healthy'
        except Exception as e:
            checks['components']['cache'] = 'unhealthy'
            checks['status'] = 'degraded'
        
        # Check AWS Cognito (if configured)
        try:
            # Try to import Cognito client
            from .cognito_client import CognitoClient
            checks['components']['cognito'] = 'configured'
        except Exception as e:
            checks['components']['cognito'] = 'not_configured'
        
        return Response(checks)


# ============ VERSION INFO VIEW ============

class VersionInfoView(APIView):
    """
    Application version information
    """
    
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        """
        Get application version information
        """
        import importlib.metadata
        
        try:
            version = importlib.metadata.version('zeno-backend')
        except:
            version = 'development'
        
        info = {
            'name': 'Zeno Services API',
            'version': version,
            'environment': 'production' if not settings.DEBUG else 'development',
            'timestamp': timezone.now().isoformat(),
            'features': {
                'authentication': 'JWT + Session + Secure Cookies',
                'authorization': 'Role-based access control',
                'storage': 'AWS S3 (if configured)',
                'database': 'PostgreSQL',
                'cache': 'Redis',
                'email_verification': 'AWS Cognito'
            }
        }
        
        return Response(info)


# ============ ERROR HANDLING VIEWS ============

def handler404(request, exception):
    """
    Custom 404 handler
    """
    return Response(
        {
            'detail': 'Resource not found',
            'path': request.path,
            'method': request.method
        },
        status=status.HTTP_404_NOT_FOUND
    )


def handler500(request):
    """
    Custom 500 handler
    """
    logger.error(f"Internal server error: {request.path}")
    
    return Response(
        {
            'detail': 'Internal server error',
            'error_id': str(uuid.uuid4()),
            'timestamp': timezone.now().isoformat()
        },
        status=status.HTTP_500_INTERNAL_SERVER_ERROR
    )


def handler400(request, exception):
    """
    Custom 400 handler
    """
    return Response(
        {
            'detail': 'Bad request',
            'error': str(exception) if str(exception) else 'Invalid request'
        },
        status=status.HTTP_400_BAD_REQUEST
    )


def handler403(request, exception):
    """
    Custom 403 handler
    """
    return Response(
        {
            'detail': 'Permission denied',
            'path': request.path,
            'method': request.method
        },
        status=status.HTTP_403_FORBIDDEN
    )


def handler401(request, exception):
    """
    Custom 401 handler
    """
    return Response(
        {
            'detail': 'Authentication required',
            'path': request.path,
            'method': request.method
        },
        status=status.HTTP_401_UNAUTHORIZED
    )