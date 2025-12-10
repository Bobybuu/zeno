"""
Custom filters for Zeno Application
"""

import django_filters
from django.db.models import Q
from .models import User, AuditLog


class UserFilter(django_filters.FilterSet):
    """
    Filter for User model
    """
    
    email = django_filters.CharFilter(lookup_expr='icontains')
    first_name = django_filters.CharFilter(lookup_expr='icontains')
    last_name = django_filters.CharFilter(lookup_expr='icontains')
    phone_number = django_filters.CharFilter(lookup_expr='icontains')
    user_type = django_filters.CharFilter(lookup_expr='exact')
    email_verified = django_filters.BooleanFilter()
    is_active = django_filters.BooleanFilter()
    created_at = django_filters.DateFromToRangeFilter()
    updated_at = django_filters.DateFromToRangeFilter()
    
    search = django_filters.CharFilter(method='filter_search')
    
    class Meta:
        model = User
        fields = {
            'email': ['exact', 'icontains'],
            'first_name': ['exact', 'icontains'],
            'last_name': ['exact', 'icontains'],
            'user_type': ['exact'],
            'email_verified': ['exact'],
            'is_active': ['exact'],
            'created_at': ['gte', 'lte'],
            'updated_at': ['gte', 'lte'],
        }
    
    def filter_search(self, queryset, name, value):
        """
        Search across multiple fields
        """
        return queryset.filter(
            Q(email__icontains=value) |
            Q(first_name__icontains=value) |
            Q(last_name__icontains=value) |
            Q(phone_number__icontains=value) |
            Q(username__icontains=value)
        )


class AuditLogFilter(django_filters.FilterSet):
    """
    Filter for AuditLog model
    """
    
    user = django_filters.CharFilter(field_name='user__email', lookup_expr='icontains')
    action = django_filters.CharFilter(lookup_expr='exact')
    resource_type = django_filters.CharFilter(lookup_expr='exact')
    resource_id = django_filters.UUIDFilter()
    ip_address = django_filters.CharFilter(lookup_expr='exact')
    created_at = django_filters.DateTimeFromToRangeFilter()
    status_code = django_filters.NumberFilter()
    
    class Meta:
        model = AuditLog
        fields = {
            'user': ['exact'],
            'action': ['exact'],
            'resource_type': ['exact'],
            'resource_id': ['exact'],
            'ip_address': ['exact'],
            'created_at': ['gte', 'lte'],
            'status_code': ['gte', 'lte'],
        }