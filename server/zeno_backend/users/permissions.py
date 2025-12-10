"""
Custom permissions for Zeno Application
"""

from rest_framework import permissions


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Object-level permission to only allow owners of an object to edit it.
    """
    
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed to the owner or staff
        if hasattr(obj, 'user'):
            return obj.user == request.user or request.user.is_staff
        elif hasattr(obj, 'owner'):
            return obj.owner == request.user or request.user.is_staff
        elif hasattr(obj, 'created_by'):
            return obj.created_by == request.user or request.user.is_staff
        else:
            return obj == request.user or request.user.is_staff


class IsAdminOrReadOnly(permissions.BasePermission):
    """
    Allows read-only access to all, but write access only to admin users.
    """
    
    def has_permission(self, request, view):
        # Read permissions are allowed to any request
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed to admin users
        return request.user and request.user.is_staff


class IsSuperAdmin(permissions.BasePermission):
    """
    Only allows super admin users.
    """
    
    def has_permission(self, request, view):
        return request.user and request.user.is_superuser


class IsVendorOwner(permissions.BasePermission):
    """
    Only allows vendor owners or admin users.
    """
    
    def has_object_permission(self, request, view, obj):
        # Admin users can do anything
        if request.user.is_staff:
            return True
        
        # Check if user owns the vendor
        if hasattr(obj, 'vendor'):
            return obj.vendor.user == request.user
        elif hasattr(obj, 'user'):
            # For vendor objects themselves
            return obj.user == request.user
        
        return False


class IsCustomer(permissions.BasePermission):
    """
    Only allows customer users.
    """
    
    def has_permission(self, request, view):
        return request.user and request.user.user_type == 'customer'


class IsVendorOrMechanic(permissions.BasePermission):
    """
    Only allows vendor or mechanic users.
    """
    
    def has_permission(self, request, view):
        return request.user and request.user.user_type in ['vendor', 'mechanic']


class HasUserType(permissions.BasePermission):
    """
    Allows access based on user type.
    """
    
    def __init__(self, allowed_types):
        self.allowed_types = allowed_types
    
    def has_permission(self, request, view):
        return request.user and request.user.user_type in self.allowed_types


class IsVerifiedVendor(permissions.BasePermission):
    """
    Only allows verified vendors.
    """
    
    def has_permission(self, request, view):
        if not request.user or request.user.user_type not in ['vendor', 'mechanic']:
            return False
        
        # Check if user has a vendor profile and it's verified
        from .models import Vendor
        try:
            vendor = request.user.vendor_profile
            return vendor.verification_status == 'verified'
        except Vendor.DoesNotExist:
            return False


class IsEmailVerified(permissions.BasePermission):
    """
    Only allows users with verified email.
    """
    
    def has_permission(self, request, view):
        return request.user and request.user.email_verified


class IsAccountActive(permissions.BasePermission):
    """
    Only allows users with active accounts.
    """
    
    def has_permission(self, request, view):
        return request.user and request.user.is_active and not request.user.is_account_locked()