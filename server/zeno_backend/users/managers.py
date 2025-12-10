"""
Custom model managers for Zeno Application
"""

from django.db import models
from django.contrib.auth.models import BaseUserManager
from django.db.models import Q, Count, Avg, Sum, F
from django.utils import timezone
from django.core.exceptions import ObjectDoesNotExist
from django.db.models.query import QuerySet
from typing import Optional, List, Dict, Any
from django.core.exceptions import ValidationError

class ActiveManager(models.Manager):
    """
    Manager for active (non-deleted) records
    """
    
    def get_queryset(self):
        return super().get_queryset().filter(is_deleted=False)
    
    def with_deleted(self):
        """Include deleted records"""
        return super().get_queryset()
    
    def deleted(self):
        """Only deleted records"""
        return super().get_queryset().filter(is_deleted=True)


class UserManager(BaseUserManager):
    """
    Custom manager for User model
    """
    
    def create_user(self, email, password=None, **extra_fields):
        """
        Create and save a regular user with the given email and password.
        """
        if not email:
            raise ValueError('The Email field must be set')
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        
        if password:
            user.set_password(password)
        user.save(using=self._db)
        
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('user_type', 'admin')
        
        return self.create_user(email, password, **extra_fields)
    
    def get_by_natural_key(self, email):
        return self.get(email=email)
    
    def get_active_users(self):
        """Get all active users"""
        return self.get_queryset().filter(is_active=True, is_deleted=False)
    
    def get_by_user_type(self, user_type):
        """Get users by type"""
        return self.get_active_users().filter(user_type=user_type)
    
    def get_customers(self):
        """Get all customers"""
        return self.get_by_user_type('customer')
    
    def get_vendors(self):
        """Get all vendors"""
        return self.get_by_user_type('vendor')
    
    def get_mechanics(self):
        """Get all mechanics"""
        return self.get_by_user_type('mechanic')
    
    def get_admins(self):
        """Get all admin users"""
        return self.get_by_user_type('admin')
    
    def get_super_admins(self):
        """Get all super admin users"""
        return self.get_by_user_type('super_admin')
    
    def get_by_verification_status(self, email_verified=True):
        """Get users by email verification status"""
        return self.get_active_users().filter(email_verified=email_verified)
    
    def get_users_with_profile(self):
        """Get users with associated profiles"""
        return self.get_active_users().filter(profile__isnull=False)
    
    def search_users(self, query: str):
        """
        Search users by email, username, first name, last name, or phone
        """
        return self.get_active_users().filter(
            Q(email__icontains=query) |
            Q(username__icontains=query) |
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query) |
            Q(phone_number__icontains=query)
        ).distinct()
    
    def get_users_by_location(self, city: str = None, state: str = None):
        """Get users by location"""
        queryset = self.get_active_users()
        
        if city:
            queryset = queryset.filter(profile__city__iexact=city)
        
        if state:
            queryset = queryset.filter(profile__state__iexact=state)
        
        return queryset
    
    def get_users_with_active_sessions(self):
        """Get users with active sessions"""
        from .models import UserSession
        active_session_user_ids = UserSession.objects.filter(
            status='active',
            expires_at__gt=timezone.now()
        ).values_list('user_id', flat=True)
        
        return self.get_active_users().filter(id__in=active_session_user_ids)
    
    def get_locked_accounts(self):
        """Get locked user accounts"""
        return self.get_active_users().filter(
            account_locked_until__gt=timezone.now()
        )
    
    def get_users_with_mfa(self):
        """Get users with MFA enabled"""
        return self.get_active_users().filter(mfa_enabled=True)
    
    def bulk_update_last_login(self, user_ids):
        """Bulk update last login for multiple users"""
        return self.get_queryset().filter(id__in=user_ids).update(
            last_login=timezone.now()
        )
    
    def get_user_stats(self):
        """Get user statistics"""
        return self.get_active_users().aggregate(
            total_users=Count('id'),
            verified_users=Count('id', filter=Q(email_verified=True)),
            customer_count=Count('id', filter=Q(user_type='customer')),
            vendor_count=Count('id', filter=Q(user_type='vendor')),
            mechanic_count=Count('id', filter=Q(user_type='mechanic')),
            admin_count=Count('id', filter=Q(user_type='admin')),
            super_admin_count=Count('id', filter=Q(user_type='super_admin')),
            mfa_enabled_count=Count('id', filter=Q(mfa_enabled=True)),
            locked_accounts=Count('id', filter=Q(account_locked_until__gt=timezone.now())),
        )


class VendorManager(ActiveManager):
    """
    Custom manager for Vendor model
    """
    
    def get_queryset(self):
        return super().get_queryset().select_related('user')
    
    def get_verified_vendors(self):
        """Get verified vendors"""
        return self.get_queryset().filter(verification_status='verified')
    
    def get_pending_verification(self):
        """Get vendors pending verification"""
        return self.get_queryset().filter(verification_status='pending')
    
    def get_by_vendor_type(self, vendor_type):
        """Get vendors by type"""
        return self.get_queryset().filter(vendor_type=vendor_type)
    
    def get_gas_stations(self):
        """Get all gas stations"""
        return self.get_by_vendor_type('gas_station')
    
    def get_hospitals(self):
        """Get all hospitals"""
        return self.get_by_vendor_type('hospital')
    
    def get_mechanical_services(self):
        """Get all mechanical service providers"""
        return self.get_by_vendor_type('mechanical_service')
    
    def get_towing_services(self):
        """Get all towing services"""
        return self.get_by_vendor_type('towing_service')
    
    def get_fuel_delivery_services(self):
        """Get all fuel delivery services"""
        return self.get_by_vendor_type('fuel_delivery')
    
    def get_vendors_near_location(self, latitude: float, longitude: float, radius_km: float = 10):
        """
        Get vendors within a certain radius of a location using bounding box approximation
        """
        # Approximate conversion: 1 degree latitude ≈ 111 km
        # 1 degree longitude ≈ 111 km * cos(latitude)
        lat_degrees = radius_km / 111.0
        lng_degrees = radius_km / (111.0 * abs(float(latitude)))
        
        min_lat = latitude - lat_degrees
        max_lat = latitude + lat_degrees
        min_lng = longitude - lng_degrees
        max_lng = longitude + lng_degrees
        
        return self.get_verified_vendors().filter(
            latitude__gte=min_lat,
            latitude__lte=max_lat,
            longitude__gte=min_lng,
            longitude__lte=max_lng
        )
    
    def search_vendors(self, query: str):
        """Search vendors by name, description, or tags"""
        return self.get_verified_vendors().filter(
            Q(vendor_name__icontains=query) |
            Q(description__icontains=query) |
            Q(tags__contains=[query])
        ).distinct()
    
    def get_vendors_by_rating(self, min_rating: float = 4.0):
        """Get vendors with minimum rating"""
        return self.get_verified_vendors().filter(average_rating__gte=min_rating)
    
    def get_open_now(self):
        """Get vendors that are currently open"""
        open_vendors = []
        for vendor in self.get_verified_vendors():
            if vendor.is_open_now():
                open_vendors.append(vendor.id)
        
        return self.get_queryset().filter(id__in=open_vendors)
    
    def get_24_hour_vendors(self):
        """Get 24-hour vendors"""
        return self.get_verified_vendors().filter(is_24_hours=True)
    
    def get_vendors_with_emergency_service(self):
        """Get vendors that accept emergency calls"""
        return self.get_verified_vendors().filter(accepts_emergency_calls=True)
    
    def get_top_rated_vendors(self, limit: int = 10):
        """Get top rated vendors"""
        return self.get_verified_vendors().order_by('-average_rating', '-total_orders')[:limit]
    
    def get_top_performing_vendors(self, limit: int = 10):
        """Get top performing vendors by revenue"""
        return self.get_verified_vendors().order_by('-total_revenue', '-total_orders')[:limit]
    
    def get_vendors_by_city(self, city: str):
        """Get vendors by city"""
        return self.get_verified_vendors().filter(city__iexact=city)
    
    def get_vendor_stats(self, vendor_type: str = None):
        """Get vendor statistics"""
        queryset = self.get_verified_vendors()
        
        if vendor_type:
            queryset = queryset.filter(vendor_type=vendor_type)
        
        return queryset.aggregate(
            total_vendors=Count('id'),
            total_revenue=Sum('total_revenue'),
            total_orders=Sum('total_orders'),
            avg_rating=Avg('average_rating'),
            open_now=Count('id', filter=Q(is_24_hours=True))
        )
    
    def bulk_update_verification(self, vendor_ids, status, verified_by):
        """Bulk update vendor verification status"""
        from django.utils import timezone
        
        return self.get_queryset().filter(id__in=vendor_ids).update(
            verification_status=status,
            verified_by=verified_by,
            verified_at=timezone.now()
        )


class ServiceManager(ActiveManager):
    """
    Custom manager for Service model
    """
    
    def get_queryset(self):
        return super().get_queryset().select_related('vendor')
    
    def get_active_services(self):
        """Get active services"""
        return self.get_queryset().filter(
            status='active',
            is_available=True,
            vendor__verification_status='verified',
            vendor__is_deleted=False
        )
    
    def get_by_service_type(self, service_type):
        """Get services by type"""
        return self.get_active_services().filter(service_type=service_type)
    
    def get_gas_services(self):
        """Get gas delivery and refill services"""
        return self.get_active_services().filter(
            service_type__in=['gas_delivery', 'gas_refill']
        )
    
    def get_oxygen_services(self):
        """Get oxygen refill services"""
        return self.get_by_service_type('oxygen_refill')
    
    def get_roadside_services(self):
        """Get all roadside assistance services"""
        return self.get_active_services().filter(
            service_type__in=[
                'mechanical_repair',
                'fuel_delivery',
                'towing',
                'battery_jumpstart',
                'tire_change',
                'lockout_service'
            ]
        )
    
    def get_services_near_location(self, latitude: float, longitude: float, radius_km: float = 10):
        """
        Get services within a certain radius of a location
        """
        from math import radians, sin, cos, sqrt, atan2
        
        # Get all services and filter by distance in Python
        # For production, use PostGIS or database-specific geospatial queries
        services_nearby = []
        
        for service in self.get_active_services():
            vendor = service.vendor
            if vendor.latitude and vendor.longitude:
                # Haversine formula
                R = 6371  # Earth's radius in km
                
                lat1 = radians(float(vendor.latitude))
                lon1 = radians(float(vendor.longitude))
                lat2 = radians(latitude)
                lon2 = radians(longitude)
                
                dlat = lat2 - lat1
                dlon = lon2 - lon1
                
                a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
                c = 2 * atan2(sqrt(a), sqrt(1-a))
                distance_km = R * c
                
                if distance_km <= radius_km:
                    # Also check service radius if specified
                    if service.service_radius_km:
                        if distance_km <= float(service.service_radius_km):
                            services_nearby.append(service.id)
                    else:
                        services_nearby.append(service.id)
        
        return self.get_queryset().filter(id__in=services_nearby)
    
    def get_services_by_vendor(self, vendor_id):
        """Get services by vendor"""
        return self.get_active_services().filter(vendor_id=vendor_id)
    
    def get_available_now(self):
        """Get services available right now"""
        from datetime import datetime
        now = timezone.now()
        current_time = now.time()
        current_day = now.weekday()
        
        # Get services without time restrictions
        always_available = self.get_active_services().filter(
            available_from__isnull=True,
            available_to__isnull=True
        )
        
        # Get services with time restrictions that match current time
        time_restricted = self.get_active_services().filter(
            available_from__isnull=False,
            available_to__isnull=False,
            available_days__contains=[current_day],
            available_from__lte=current_time,
            available_to__gte=current_time
        )
        
        return always_available | time_restricted
    
    def get_services_by_price_range(self, min_price: float = 0, max_price: float = None):
        """Get services within price range"""
        queryset = self.get_active_services().filter(price__gte=min_price)
        
        if max_price:
            queryset = queryset.filter(price__lte=max_price)
        
        return queryset
    
    def get_popular_services(self, limit: int = 10):
        """Get most popular services by bookings"""
        return self.get_active_services().order_by('-total_bookings', '-average_rating')[:limit]
    
    def get_top_rated_services(self, limit: int = 10):
        """Get top rated services"""
        return self.get_active_services().filter(
            total_bookings__gt=0,
            average_rating__gt=0
        ).order_by('-average_rating', '-total_bookings')[:limit]
    
    def search_services(self, query: str):
        """Search services by name, description, or vendor"""
        return self.get_active_services().filter(
            Q(service_name__icontains=query) |
            Q(description__icontains=query) |
            Q(detailed_description__icontains=query) |
            Q(vendor__vendor_name__icontains=query)
        ).distinct()
    
    def get_service_stats(self, service_type: str = None):
        """Get service statistics"""
        queryset = self.get_active_services()
        
        if service_type:
            queryset = queryset.filter(service_type=service_type)
        
        return queryset.aggregate(
            total_services=Count('id'),
            total_bookings=Sum('total_bookings'),
            avg_price=Avg('price'),
            avg_rating=Avg('average_rating'),
            available_now=Count('id', filter=Q(is_available=True))
        )
    
    def bulk_update_availability(self, service_ids, is_available):
        """Bulk update service availability"""
        return self.get_queryset().filter(id__in=service_ids).update(
            is_available=is_available,
            updated_at=timezone.now()
        )


class GasCylinderManager(models.Manager):
    """
    Custom manager for GasCylinder model
    """
    
    def get_queryset(self):
        return super().get_queryset().select_related('vendor')
    
    def get_available_cylinders(self):
        """Get available gas cylinders"""
        return self.get_queryset().filter(
            is_available=True,
            stock_quantity__gt=F('reserved_quantity'),
            vendor__verification_status='verified',
            vendor__is_deleted=False
        )
    
    def get_by_gas_type(self, gas_type):
        """Get cylinders by gas type"""
        return self.get_available_cylinders().filter(gas_type=gas_type)
    
    def get_by_cylinder_size(self, cylinder_size):
        """Get cylinders by size"""
        return self.get_available_cylinders().filter(cylinder_size=cylinder_size)
    
    def get_lpg_cylinders(self):
        """Get LPG cylinders"""
        return self.get_by_gas_type('lpg')
    
    def get_oxygen_cylinders(self):
        """Get oxygen cylinders"""
        return self.get_by_gas_type('oxygen')
    
    def get_cylinders_near_location(self, latitude: float, longitude: float, radius_km: float = 10):
        """Get cylinders near location"""
        from .models import Vendor
        
        # Get vendors near location
        vendors_nearby = Vendor.objects.get_vendors_near_location(
            latitude, longitude, radius_km
        )
        
        return self.get_available_cylinders().filter(
            vendor__in=vendors_nearby
        )
    
    def get_cylinders_by_price_range(self, min_price: float = 0, max_price: float = None):
        """Get cylinders within price range"""
        queryset = self.get_available_cylinders().filter(price_per_unit__gte=min_price)
        
        if max_price:
            queryset = queryset.filter(price_per_unit__lte=max_price)
        
        return queryset
    
    def get_low_stock_cylinders(self):
        """Get cylinders that need restocking"""
        return self.get_queryset().filter(
            stock_quantity__lte=F('minimum_stock_level')
        )
    
    def get_expiring_inspections(self, days: int = 30):
        """Get cylinders with inspections expiring soon"""
        from datetime import timedelta
        expiry_date = timezone.now().date() + timedelta(days=days)
        
        return self.get_queryset().filter(
            next_inspection_date__lte=expiry_date,
            next_inspection_date__gte=timezone.now().date()
        )
    
    def bulk_update_stock(self, cylinder_data):
        """Bulk update cylinder stock"""
        from django.db import transaction
        
        with transaction.atomic():
            for cylinder_id, quantity in cylinder_data.items():
                self.get_queryset().filter(id=cylinder_id).update(
                    stock_quantity=F('stock_quantity') + quantity,
                    updated_at=timezone.now()
                )


class UserSessionManager(models.Manager):
    """
    Custom manager for UserSession model
    """
    
    def get_active_sessions(self):
        """Get active sessions"""
        return self.get_queryset().filter(
            status='active',
            expires_at__gt=timezone.now()
        )
    
    def get_expired_sessions(self):
        """Get expired sessions"""
        return self.get_queryset().filter(
            expires_at__lte=timezone.now()
        ).exclude(status='expired')
    
    def get_revoked_sessions(self):
        """Get revoked sessions"""
        return self.get_queryset().filter(status='revoked')
    
    def get_suspicious_sessions(self):
        """Get suspicious sessions"""
        return self.get_queryset().filter(status='suspicious')
    
    def get_sessions_by_user(self, user_id):
        """Get sessions by user"""
        return self.get_queryset().filter(user_id=user_id)
    
    def get_sessions_by_device(self, device_type: str):
        """Get sessions by device type"""
        device_map = {
            'mobile': 'is_mobile',
            'tablet': 'is_tablet',
            'desktop': 'is_desktop'
        }
        
        if device_type not in device_map:
            return self.none()
        
        return self.get_queryset().filter(**{device_map[device_type]: True})
    
    def get_sessions_by_ip(self, ip_address: str):
        """Get sessions by IP address"""
        return self.get_queryset().filter(ip_address=ip_address)
    
    def cleanup_expired_sessions(self):
        """Mark expired sessions as expired"""
        expired = self.get_expired_sessions()
        expired.update(status='expired')
        return expired.count()
    
    def revoke_all_user_sessions(self, user_id, reason='logout_all'):
        """Revoke all sessions for a user"""
        active_sessions = self.get_active_sessions().filter(user_id=user_id)
        revoked_count = active_sessions.update(
            status='revoked',
            revocation_reason=reason,
            revoked_at=timezone.now()
        )
        return revoked_count
    
    def get_session_stats(self):
        """Get session statistics"""
        return self.get_queryset().aggregate(
            total_sessions=Count('id'),
            active_sessions=Count('id', filter=Q(status='active', expires_at__gt=timezone.now())),
            expired_sessions=Count('id', filter=Q(status='expired')),
            revoked_sessions=Count('id', filter=Q(status='revoked')),
            suspicious_sessions=Count('id', filter=Q(status='suspicious')),
            mobile_sessions=Count('id', filter=Q(is_mobile=True)),
            desktop_sessions=Count('id', filter=Q(is_desktop=True)),
            tablet_sessions=Count('id', filter=Q(is_tablet=True)),
        )


class AuditLogManager(models.Manager):
    """
    Custom manager for AuditLog model
    """
    
    def get_by_action(self, action: str):
        """Get logs by action type"""
        return self.get_queryset().filter(action=action)
    
    def get_by_resource(self, resource_type: str, resource_id=None):
        """Get logs by resource"""
        queryset = self.get_queryset().filter(resource_type=resource_type)
        
        if resource_id:
            queryset = queryset.filter(resource_id=resource_id)
        
        return queryset
    
    def get_by_user(self, user_id):
        """Get logs by user"""
        return self.get_queryset().filter(user_id=user_id)
    
    def get_by_session(self, session_id):
        """Get logs by session"""
        return self.get_queryset().filter(user_session_id=session_id)
    
    def get_by_ip(self, ip_address: str):
        """Get logs by IP address"""
        return self.get_queryset().filter(ip_address=ip_address)
    
    def get_recent_logs(self, hours: int = 24):
        """Get recent logs within specified hours"""
        from datetime import timedelta
        time_threshold = timezone.now() - timedelta(hours=hours)
        
        return self.get_queryset().filter(created_at__gte=time_threshold)
    
    def get_failed_actions(self):
        """Get failed actions (status code >= 400)"""
        return self.get_queryset().filter(status_code__gte=400)
    
    def get_slow_requests(self, threshold_ms: float = 1000):
        """Get slow requests"""
        return self.get_queryset().filter(
            duration_ms__gte=threshold_ms,
            duration_ms__isnull=False
        )
    
    def get_audit_stats(self, hours: int = 24):
        """Get audit statistics"""
        recent_logs = self.get_recent_logs(hours)
        
        return {
            'total_actions': recent_logs.count(),
            'by_action': dict(recent_logs.values_list('action').annotate(
                count=Count('id')
            ).order_by('-count')),
            'by_resource': dict(recent_logs.values_list('resource_type').annotate(
                count=Count('id')
            ).order_by('-count')),
            'failed_actions': recent_logs.filter(status_code__gte=400).count(),
            'avg_duration': recent_logs.aggregate(
                avg=Avg('duration_ms')
            )['avg'] or 0,
        }
    
    def cleanup_old_logs(self, days: int = 90):
        """Delete logs older than specified days"""
        from datetime import timedelta
        cutoff_date = timezone.now() - timedelta(days=days)
        
        deleted_count, _ = self.get_queryset().filter(
            created_at__lt=cutoff_date
        ).delete()
        
        return deleted_count