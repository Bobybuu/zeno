# users/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    # Authentication Views
    CustomTokenObtainPairView,
    CustomTokenRefreshView,
    LogoutView,
    LogoutAllView,
    
    # Registration & Verification Views
    RegisterView,
    VerifyEmailView,
    ResendVerificationEmailView,
    
    # Password Management Views
    PasswordResetView,
    PasswordResetConfirmView,
    ChangePasswordView,
    
    # User Viewsets
    UserViewSet,
    UserProfileViewSet,
    UserSessionViewSet,
    AuditLogViewSet,
    
    # Utility Views
    FileUploadView,
    HealthCheckView,
    VersionInfoView,
    
   
)

# Create a router and register our viewsets
router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'profiles', UserProfileViewSet, basename='profile')
router.register(r'sessions', UserSessionViewSet, basename='session')
router.register(r'audit-logs', AuditLogViewSet, basename='audit-log')

urlpatterns = [
    # ============ API ROUTES ============
    
    # Authentication
    path('auth/login/', CustomTokenObtainPairView.as_view(), name='auth-login'),
    path('auth/token/refresh/', CustomTokenRefreshView.as_view(), name='auth-token-refresh'),
    path('auth/logout/', LogoutView.as_view(), name='auth-logout'),
    path('auth/logout-all/', LogoutAllView.as_view(), name='auth-logout-all'),
    
    # Registration & Verification
    path('auth/register/', RegisterView.as_view(), name='auth-register'),
    path('auth/verify-email/', VerifyEmailView.as_view(), name='auth-verify-email'),
    path('auth/resend-verification/', ResendVerificationEmailView.as_view(), 
         name='auth-resend-verification'),
    
    # Password Management
    path('auth/password/reset/', PasswordResetView.as_view(), name='auth-password-reset'),
    path('auth/password/reset/confirm/', PasswordResetConfirmView.as_view(), 
         name='auth-password-reset-confirm'),
    path('auth/password/change/', ChangePasswordView.as_view(), name='auth-password-change'),
    
    # File Upload
    path('upload/', FileUploadView.as_view(), name='file-upload'),
    
    # Health & Info
    path('health/', HealthCheckView.as_view(), name='health-check'),
    path('version/', VersionInfoView.as_view(), name='version-info'),
    
    # ============ VIEWSET ROUTES ============
    path('', include(router.urls)),
    
    # ============ USER-SPECIFIC ROUTES ============
    # These provide convenient shortcuts to common user actions
    path('me/', UserViewSet.as_view({'get': 'me'}), name='user-me'),
    path('me/update/', UserViewSet.as_view({'put': 'update_me', 'patch': 'update_me'}), 
         name='user-update-me'),
    path('me/profile/', UserViewSet.as_view({'get': 'profile'}), name='user-profile'),
    path('me/profile/update/', UserViewSet.as_view({'put': 'update_profile', 'patch': 'update_profile'}), 
         name='user-profile-update'),
    path('me/sessions/', UserViewSet.as_view({'get': 'sessions'}), name='user-sessions'),
    path('me/audit-logs/', UserViewSet.as_view({'get': 'audit_logs'}), name='user-audit-logs'),
    
    # ============ ADMIN ROUTES ============
    path('dashboard/stats/', UserViewSet.as_view({'get': 'dashboard'}), name='admin-dashboard'),
    path('stats/users/', UserViewSet.as_view({'get': 'stats'}), name='admin-user-stats'),
    
    # ============ DEPRECATED/LEGACY ROUTES ============
    # These are kept for backward compatibility with existing clients
    # You can phase them out gradually as clients update
    
    # Authentication (deprecated)
    path('login/', CustomTokenObtainPairView.as_view(), name='login-legacy'),
    path('logout/', LogoutView.as_view(), name='logout-legacy'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token-refresh-legacy'),
    
    # Registration (deprecated)
    path('register/', RegisterView.as_view(), name='register-legacy'),
    
    # Profile (deprecated)
    path('profile/', UserViewSet.as_view({'get': 'profile'}), name='profile-legacy'),
    path('update-profile/', UserViewSet.as_view({'put': 'update_profile', 'patch': 'update_profile'}), 
         name='update-profile-legacy'),
    
    # Password Management (deprecated)
    path('change-password/', ChangePasswordView.as_view(), name='change-password-legacy'),
    path('forgot-password/', PasswordResetView.as_view(), name='forgot-password-legacy'),
    path('reset-password/', PasswordResetConfirmView.as_view(), name='reset-password-legacy'),
    
    # Health check (deprecated)
    path('health-check/', HealthCheckView.as_view(), name='health-check-legacy'),
    
    # Admin routes (deprecated)
    path('users/', UserViewSet.as_view({'get': 'list'}), name='user-list-legacy'),
    path('users/<uuid:pk>/', UserViewSet.as_view({'get': 'retrieve'}), name='user-detail-legacy'),
    
    # ============ FULLY DEPRECATED ROUTES (to be removed) ============
    # These routes reference views that no longer exist in the new implementation
    # You'll need to either:
    # 1. Create placeholder views that redirect to new endpoints
    # 2. Remove them entirely and update clients
    # 3. Implement them with the new architecture
    
    # path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),  # Replaced by verify-email
    # path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),  # Replaced by resend-verification
    # path('check-auth/', CheckAuthView.as_view(), name='check-auth'),  # Use /me/ endpoint instead
    # path('verify-reset-code/', VerifyResetCodeView.as_view(), name='verify-reset-code'),  # Part of password reset flow
]

# ============ CUSTOM ERROR HANDLERS ============
handler404 = 'users.views.handler404'
handler500 = 'users.views.handler500'
handler400 = 'users.views.handler400'
handler403 = 'users.views.handler403'
handler401 = 'users.views.handler401'