"""
Signal handlers for Zeno Application - Compatible with Django LocMemCache
"""

import logging

from django.core.cache import cache
from django.db import transaction
from django.db.models.signals import m2m_changed, post_delete, post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone

from .models import (
    AuditLog,
    GasCylinder,
    Service,
    User,
    UserProfile,
    UserSession,
    Vendor,
)

logger = logging.getLogger(__name__)


# ============ USER SIGNALS ============

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    Create a UserProfile automatically when a new User is created
    """
    if created and not instance.is_superuser:
        try:
            with transaction.atomic():
                UserProfile.objects.get_or_create(user=instance)
                logger.info(f"Created user profile for {instance.email}")
                
                # Clear user cache
                cache_key = f"user_{instance.id}_profile"
                cache.delete(cache_key)
                
        except Exception as e:
            logger.error(f"Error creating user profile for {instance.email}: {str(e)}")


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """
    Save the UserProfile when User is saved
    """
    try:
        if hasattr(instance, 'profile'):
            instance.profile.save()
            logger.debug(f"Saved user profile for {instance.email}")
    except Exception as e:
        logger.error(f"Error saving user profile for {instance.email}: {str(e)}")


@receiver(pre_save, sender=User)
def user_pre_save_handler(sender, instance, **kwargs):
    """
    Handle user pre-save operations
    """
    # Log email changes
    if instance.pk:
        try:
            original = User.objects.get(pk=instance.pk)
            if original.email != instance.email:
                logger.info(f"User {instance.id} changed email from {original.email} to {instance.email}")
                
                # Create audit log for email change
                AuditLog.objects.create(
                    user=instance,
                    action='update',
                    resource_type='user',
                    resource_id=instance.id,
                    old_data={'email': original.email},
                    new_data={'email': instance.email},
                    changes={'email': {'from': original.email, 'to': instance.email}},
                    ip_address='127.0.0.1',
                    request_path='/api/users/update/',
                    request_method='PUT'
                )
        except User.DoesNotExist:
            pass
    
    # Ensure email is lowercase
    if instance.email:
        instance.email = instance.email.lower()
    
    # Set username from email if not provided
    if not instance.username and instance.email:
        instance.username = instance.email.split('@')[0]


@receiver(post_save, sender=User)
def user_post_save_handler(sender, instance, created, **kwargs):
    """
    Handle user post-save operations - Fixed for LocMemCache
    """
    if created:
        # Log user creation
        try:
            AuditLog.objects.create(
                user=instance,
                action='create',
                resource_type='user',
                resource_id=instance.id,
                new_data={'email': instance.email, 'user_type': instance.user_type},
                ip_address='127.0.0.1',
                request_path='/api/users/register/',
                request_method='POST'
            )
            
            logger.info(f"New user created: {instance.email} ({instance.user_type})")
        except Exception as e:
            logger.error(f"Error creating audit log for new user: {e}")
        
        # Clear cache - Compatible with LocMemCache
        try:
            # Clear specific cache keys instead of using delete_pattern
            cache_keys_to_delete = [
                'total_users_count',
                'user_stats_active',
                'user_stats_by_type',
                'user_stats_total',
                f'user_{instance.id}_details',
                f'user_{instance.id}_profile_cache'
            ]
            
            for key in cache_keys_to_delete:
                cache.delete(key)
            
            # Clear all cache if we can't target specific patterns
            # cache.clear()  # Uncomment if you want to clear ALL cache
            
        except Exception as e:
            logger.warning(f"Cache clearing failed for new user: {e}")
            # Ignore cache errors for now


@receiver(post_delete, sender=User)
def user_post_delete_handler(sender, instance, **kwargs):
    """
    Handle user deletion - Fixed for LocMemCache
    """
    # Create audit log for user deletion
    try:
        AuditLog.objects.create(
            user=None,  # System action
            action='delete',
            resource_type='user',
            resource_id=instance.id,
            old_data={'email': instance.email, 'user_type': instance.user_type},
            ip_address='127.0.0.1',
            request_path=f'/api/users/{instance.id}/',
            request_method='DELETE'
        )
        
        logger.info(f"User deleted: {instance.email}")
    except Exception as e:
        logger.error(f"Error creating audit log for deleted user: {e}")
    
    # Clear cache - Compatible with LocMemCache
    try:
        # Clear specific user-related cache
        cache_keys_to_delete = [
            'total_users_count',
            'user_stats_active',
            'user_stats_by_type',
            'user_stats_total',
            f'user_{instance.id}_details',
            f'user_{instance.id}_profile_cache',
            f'user_{instance.id}_sessions'
        ]
        
        for key in cache_keys_to_delete:
            cache.delete(key)
            
        # Clear all cache as fallback
        # cache.clear()
        
    except Exception as e:
        logger.warning(f"Cache clearing failed for deleted user: {e}")


# ============ VENDOR SIGNALS ============

@receiver(post_save, sender=Vendor)
def vendor_post_save_handler(sender, instance, created, **kwargs):
    """
    Handle vendor post-save operations - Fixed for LocMemCache
    """
    if created:
        # Log vendor creation
        try:
            AuditLog.objects.create(
                user=instance.user,
                action='create',
                resource_type='vendor',
                resource_id=instance.id,
                new_data={
                    'vendor_name': instance.vendor_name,
                    'vendor_type': instance.vendor_type,
                    'verification_status': instance.verification_status
                },
                ip_address='127.0.0.1',
                request_path='/api/vendors/register/',
                request_method='POST'
            )
            
            logger.info(f"New vendor created: {instance.vendor_name} ({instance.vendor_type})")
        except Exception as e:
            logger.error(f"Error creating audit log for new vendor: {e}")
    
    # Update user type if needed
    try:
        if instance.user.user_type != 'vendor' and instance.user.user_type != 'mechanic':
            instance.user.user_type = 'vendor' if instance.vendor_type != 'mechanical_service' else 'mechanic'
            instance.user.save(update_fields=['user_type'])
    except Exception as e:
        logger.error(f"Error updating user type for vendor: {e}")
    
    # Clear cache - Compatible with LocMemCache
    try:
        cache_keys_to_delete = [
            f'vendor_{instance.id}_details',
            f'vendor_{instance.id}_services',
            f'vendor_{instance.id}_stats',
            'vendor_stats_total',
            'vendor_stats_by_type',
            'vendor_stats_verified',
            'vendors_list_all',
            'vendors_list_active'
        ]
        
        for key in cache_keys_to_delete:
            cache.delete(key)
            
        # Clear location-based cache by clearing all for now
        # cache.clear()
        
    except Exception as e:
        logger.warning(f"Cache clearing failed for vendor: {e}")


@receiver(pre_save, sender=Vendor)
def vendor_pre_save_handler(sender, instance, **kwargs):
    """
    Handle vendor pre-save operations
    """
    # Track verification status changes
    if instance.pk:
        try:
            original = Vendor.objects.get(pk=instance.pk)
            if original.verification_status != instance.verification_status:
                logger.info(
                    f"Vendor {instance.vendor_name} verification status changed "
                    f"from {original.verification_status} to {instance.verification_status}"
                )
                
                # Create audit log
                AuditLog.objects.create(
                    user=instance.verified_by,
                    action='verify' if instance.verification_status == 'verified' else 'update',
                    resource_type='vendor',
                    resource_id=instance.id,
                    old_data={'verification_status': original.verification_status},
                    new_data={'verification_status': instance.verification_status},
                    changes={'verification_status': {
                        'from': original.verification_status,
                        'to': instance.verification_status
                    }},
                    ip_address='127.0.0.1',
                    request_path=f'/api/vendors/{instance.id}/verify/',
                    request_method='PUT'
                )
        except Vendor.DoesNotExist:
            pass
        except Exception as e:
            logger.error(f"Error in vendor_pre_save_handler: {e}")


@receiver(post_delete, sender=Vendor)
def vendor_post_delete_handler(sender, instance, **kwargs):
    """
    Handle vendor deletion - Fixed for LocMemCache
    """
    # Create audit log
    try:
        AuditLog.objects.create(
            user=instance.user,
            action='delete',
            resource_type='vendor',
            resource_id=instance.id,
            old_data={'vendor_name': instance.vendor_name, 'vendor_type': instance.vendor_type},
            ip_address='127.0.0.1',
            request_path=f'/api/vendors/{instance.id}/',
            request_method='DELETE'
        )
        
        logger.info(f"Vendor deleted: {instance.vendor_name}")
    except Exception as e:
        logger.error(f"Error creating audit log for deleted vendor: {e}")
    
    # Clear cache - Compatible with LocMemCache
    try:
        cache_keys_to_delete = [
            f'vendor_{instance.id}_details',
            f'vendor_{instance.id}_services',
            f'vendor_{instance.id}_stats',
            'vendor_stats_total',
            'vendor_stats_by_type',
            'vendors_list_all',
            f'user_{instance.user_id}_vendor_profile'
        ]
        
        for key in cache_keys_to_delete:
            cache.delete(key)
            
        # Clear all cache as fallback
        # cache.clear()
        
    except Exception as e:
        logger.warning(f"Cache clearing failed for deleted vendor: {e}")


# ============ SERVICE SIGNALS ============

@receiver(post_save, sender=Service)
def service_post_save_handler(sender, instance, created, **kwargs):
    """
    Handle service post-save operations - Fixed for LocMemCache
    """
    if created:
        # Log service creation
        try:
            AuditLog.objects.create(
                user=instance.vendor.user,
                action='create',
                resource_type='service',
                resource_id=instance.id,
                new_data={
                    'service_name': instance.service_name,
                    'service_type': instance.service_type,
                    'price': str(instance.price),
                    'vendor': str(instance.vendor_id)
                },
                ip_address='127.0.0.1',
                request_path='/api/services/create/',
                request_method='POST'
            )
            
            logger.info(
                f"New service created: {instance.service_name} "
                f"for vendor {instance.vendor.vendor_name}"
            )
        except Exception as e:
            logger.error(f"Error creating audit log for new service: {e}")
    
    # Clear cache - Compatible with LocMemCache
    try:
        cache_keys_to_delete = [
            f'service_{instance.id}_details',
            f'service_{instance.id}_availability',
            f'vendor_{instance.vendor_id}_services',
            f'vendor_{instance.vendor_id}_services_list',
            'service_stats_total',
            'service_stats_by_type',
            'service_stats_active',
            'services_list_all',
            'services_list_active'
        ]
        
        for key in cache_keys_to_delete:
            cache.delete(key)
            
        # Clear location-based cache
        # cache.clear()
        
    except Exception as e:
        logger.warning(f"Cache clearing failed for service: {e}")


@receiver(pre_save, sender=Service)
def service_pre_save_handler(sender, instance, **kwargs):
    """
    Handle service pre-save operations
    """
    # Generate service code if not provided
    if not instance.service_code:
        try:
            from django.utils.crypto import get_random_string
            prefix = instance.service_type[:3].upper()
            random_part = get_random_string(6, 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789')
            instance.service_code = f"{prefix}-{random_part}"
        except Exception as e:
            logger.error(f"Error generating service code: {e}")
    
    # Track price changes
    if instance.pk:
        try:
            original = Service.objects.get(pk=instance.pk)
            if original.price != instance.price:
                logger.info(
                    f"Service {instance.service_name} price changed "
                    f"from {original.price} to {instance.price}"
                )
                
                # Create audit log
                AuditLog.objects.create(
                    user=instance.vendor.user,
                    action='update',
                    resource_type='service',
                    resource_id=instance.id,
                    old_data={'price': str(original.price)},
                    new_data={'price': str(instance.price)},
                    changes={'price': {
                        'from': str(original.price),
                        'to': str(instance.price)
                    }},
                    ip_address='127.0.0.1',
                    request_path=f'/api/services/{instance.id}/',
                    request_method='PUT'
                )
        except Service.DoesNotExist:
            pass
        except Exception as e:
            logger.error(f"Error tracking service price change: {e}")


@receiver(post_delete, sender=Service)
def service_post_delete_handler(sender, instance, **kwargs):
    """
    Handle service deletion - Fixed for LocMemCache
    """
    # Create audit log
    try:
        AuditLog.objects.create(
            user=instance.vendor.user,
            action='delete',
            resource_type='service',
            resource_id=instance.id,
            old_data={
                'service_name': instance.service_name,
                'service_type': instance.service_type,
                'vendor': str(instance.vendor_id)
            },
            ip_address='127.0.0.1',
            request_path=f'/api/services/{instance.id}/',
            request_method='DELETE'
        )
        
        logger.info(f"Service deleted: {instance.service_name}")
    except Exception as e:
        logger.error(f"Error creating audit log for deleted service: {e}")
    
    # Clear cache - Compatible with LocMemCache
    try:
        cache_keys_to_delete = [
            f'service_{instance.id}_details',
            f'service_{instance.id}_availability',
            f'vendor_{instance.vendor_id}_services',
            f'vendor_{instance.vendor_id}_services_list',
            'service_stats_total',
            'service_stats_by_type',
            'services_list_all'
        ]
        
        for key in cache_keys_to_delete:
            cache.delete(key)
            
    except Exception as e:
        logger.warning(f"Cache clearing failed for deleted service: {e}")


# ============ GAS CYLINDER SIGNALS ============

@receiver(post_save, sender=GasCylinder)
def gas_cylinder_post_save_handler(sender, instance, created, **kwargs):
    """
    Handle gas cylinder post-save operations - Fixed for LocMemCache
    """
    if created:
        try:
            logger.info(
                f"New gas cylinder added: {instance.get_gas_type_display()} "
                f"{instance.get_cylinder_size_display()} for {instance.vendor.vendor_name}"
            )
        except Exception as e:
            logger.error(f"Error logging new gas cylinder: {e}")
    
    # Update cache - Compatible with LocMemCache
    try:
        cache_keys_to_delete = [
            f'vendor_{instance.vendor_id}_cylinders_{instance.gas_type}',
            f'vendor_{instance.vendor_id}_cylinders_all',
            f'vendor_{instance.vendor_id}_inventory',
            f'cylinder_{instance.id}_details'
        ]
        
        for key in cache_keys_to_delete:
            cache.delete(key)
            
        # Clear location-based cache
        # cache.clear()
        
    except Exception as e:
        logger.warning(f"Cache clearing failed for gas cylinder: {e}")


@receiver(pre_save, sender=GasCylinder)
def gas_cylinder_pre_save_handler(sender, instance, **kwargs):
    """
    Handle gas cylinder pre-save operations
    """
    # Generate SKU if not provided
    if not instance.sku:
        try:
            from django.utils.crypto import get_random_string
            gas_code = instance.gas_type[:3].upper()
            size_code = instance.cylinder_size.upper().replace('KG', '').replace('L', '')
            vendor_code = str(instance.vendor_id)[:8]
            random_part = get_random_string(4, '23456789')
            instance.sku = f"{gas_code}-{size_code}-{vendor_code}-{random_part}"
        except Exception as e:
            logger.error(f"Error generating SKU: {e}")
    
    # Validate stock levels
    try:
        if instance.stock_quantity < 0:
            instance.stock_quantity = 0
        
        if instance.reserved_quantity > instance.stock_quantity:
            instance.reserved_quantity = instance.stock_quantity
    except Exception as e:
        logger.error(f"Error validating stock levels: {e}")


@receiver(post_delete, sender=GasCylinder)
def gas_cylinder_post_delete_handler(sender, instance, **kwargs):
    """
    Handle gas cylinder deletion - Fixed for LocMemCache
    """
    try:
        logger.info(f"Gas cylinder deleted: {instance.sku}")
    except Exception as e:
        logger.error(f"Error logging gas cylinder deletion: {e}")
    
    # Clear cache - Compatible with LocMemCache
    try:
        cache_keys_to_delete = [
            f'vendor_{instance.vendor_id}_cylinders_{instance.gas_type}',
            f'vendor_{instance.vendor_id}_cylinders_all',
            f'vendor_{instance.vendor_id}_inventory',
            f'cylinder_{instance.id}_details'
        ]
        
        for key in cache_keys_to_delete:
            cache.delete(key)
            
    except Exception as e:
        logger.warning(f"Cache clearing failed for deleted gas cylinder: {e}")


# ============ USER SESSION SIGNALS ============

@receiver(post_save, sender=UserSession)
def user_session_post_save_handler(sender, instance, created, **kwargs):
    """
    Handle user session post-save operations
    """
    if created:
        try:
            logger.info(
                f"New session created for user {instance.user.email} "
                f"from IP {instance.ip_address}"
            )
        except Exception as e:
            logger.error(f"Error logging new session: {e}")
    
    # Update user's last login if this is a new session
    if created and instance.status == 'active':
        try:
            instance.user.last_login = timezone.now()
            instance.user.save(update_fields=['last_login'])
        except Exception as e:
            logger.error(f"Error updating last login: {e}")


@receiver(pre_save, sender=UserSession)
def user_session_pre_save_handler(sender, instance, **kwargs):
    """
    Handle user session pre-save operations
    """
    # Set device type flags
    try:
        user_agent = instance.user_agent or ''
        user_agent_lower = user_agent.lower()
        
        instance.is_mobile = any(device in user_agent_lower for device in ['mobile', 'android', 'iphone'])
        instance.is_tablet = any(device in user_agent_lower for device in ['tablet', 'ipad'])
        instance.is_desktop = not (instance.is_mobile or instance.is_tablet)
    except Exception as e:
        logger.error(f"Error setting device type flags: {e}")
        instance.is_mobile = False
        instance.is_tablet = False
        instance.is_desktop = True
    
    # Hash refresh token for storage
    if instance.refresh_token_hash:
        try:
            import hashlib
            instance.refresh_token_hash = hashlib.sha256(
                instance.refresh_token_hash.encode()
            ).hexdigest()
        except Exception as e:
            logger.error(f"Error hashing refresh token: {e}")


# ============ CACHE INVALIDATION SIGNALS ============

@receiver(post_save)
@receiver(post_delete)
def clear_model_cache(sender, **kwargs):
    """
    Generic cache clearing for all models - Compatible with LocMemCache
    """
    # Skip for certain models
    if sender in [AuditLog, UserSession]:
        return
    
    try:
        # Clear specific cache keys based on model type
        if sender == User:
            cache_keys = [
                'total_users_count',
                'user_stats_active',
                'user_stats_by_type',
                'user_stats_total',
                'users_list_all',
                'users_list_active'
            ]
            for key in cache_keys:
                cache.delete(key)
                
        elif sender == Vendor:
            cache_keys = [
                'vendor_stats_total',
                'vendor_stats_by_type',
                'vendor_stats_verified',
                'vendors_list_all',
                'vendors_list_active',
                'vendors_list_verified'
            ]
            for key in cache_keys:
                cache.delete(key)
                
        elif sender == Service:
            cache_keys = [
                'service_stats_total',
                'service_stats_by_type',
                'service_stats_active',
                'services_list_all',
                'services_list_active'
            ]
            for key in cache_keys:
                cache.delete(key)
                
        # For other models, we'll clear all cache to be safe
        # You can add more specific model handling here
        
        # Fallback: Clear all cache for unknown models
        # cache.clear()  # Uncomment if you want to clear ALL cache on any model change
        
    except Exception as e:
        logger.warning(f"Cache clearing failed in clear_model_cache: {e}")
        # Don't raise the exception, just log it


# ============ BULK OPERATION SIGNALS ============

@receiver(m2m_changed)
def m2m_changed_handler(sender, instance, action, **kwargs):
    """
    Handle many-to-many relationship changes - Compatible with LocMemCache
    """
    if action in ['post_add', 'post_remove', 'post_clear']:
        try:
            # Clear cache when m2m relationships change
            model_name = instance.__class__.__name__.lower()
            
            # Clear specific instance cache
            cache.delete(f"{model_name}_{instance.id}_details")
            cache.delete(f"{model_name}_{instance.id}_relations")
            
            # Clear list cache for this model type
            cache.delete(f"{model_name}s_list_all")
            cache.delete(f"{model_name}s_list_active")
            
        except Exception as e:
            logger.warning(f"Cache clearing failed in m2m_changed_handler: {e}")


# ============ ERROR HANDLING ============

def handle_signal_error(signal, sender, **kwargs):
    """
    Global error handler for signals
    """
    try:
        exception = kwargs.get('exception', 'Unknown error')
        logger.error(
            f"Error in signal handler for {sender.__name__ if sender else 'unknown'}: "
            f"{str(exception)}"
        )
    except Exception as e:
        # Even the error handler can fail, so be extra safe
        print(f"Critical error in handle_signal_error: {e}")


# Connect error handler
from django.core.signals import got_request_exception

got_request_exception.connect(handle_signal_error)


# ============ SIGNAL REGISTRATION ============

def ready():
    """
    Import this function in apps.py to connect all signals
    """
    # Signals are connected via @receiver decorators
    pass