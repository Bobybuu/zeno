"""
Admin configurations for Zeno Application
"""

from datetime import timedelta

from django.contrib import admin
from django.contrib.admin import SimpleListFilter
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import Group
from django.db.models import Avg, Count, Q, Sum
from django.urls import reverse
from django.utils import timezone
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from .models import (
    AuditLog,
    GasCylinder,
    Service,
    ServiceAddon,
    ServiceArea,
    User,
    UserProfile,
    UserSession,
    Vendor,
)

# ============ CUSTOM ADMIN FILTERS ============

class UserTypeFilter(SimpleListFilter):
    """Filter users by type"""
    title = _('User Type')
    parameter_name = 'user_type'
    
    def lookups(self, request, model_admin):
        return User.UserType.choices
    
    def queryset(self, request, queryset):
        if self.value():
            return queryset.filter(user_type=self.value())
        return queryset


class VerificationStatusFilter(SimpleListFilter):
    """Filter vendors by verification status"""
    title = _('Verification Status')
    parameter_name = 'verification_status'
    
    def lookups(self, request, model_admin):
        return Vendor.VerificationStatus.choices
    
    def queryset(self, request, queryset):
        if self.value():
            return queryset.filter(verification_status=self.value())
        return queryset


class ServiceTypeFilter(SimpleListFilter):
    """Filter services by type"""
    title = _('Service Type')
    parameter_name = 'service_type'
    
    def lookups(self, request, model_admin):
        return Service.ServiceType.choices
    
    def queryset(self, request, queryset):
        if self.value():
            return queryset.filter(service_type=self.value())
        return queryset


class GasTypeFilter(SimpleListFilter):
    """Filter gas cylinders by type"""
    title = _('Gas Type')
    parameter_name = 'gas_type'
    
    def lookups(self, request, model_admin):
        return GasCylinder.GasType.choices
    
    def queryset(self, request, queryset):
        if self.value():
            return queryset.filter(gas_type=self.value())
        return queryset


class ActiveSessionFilter(SimpleListFilter):
    """Filter user sessions by activity"""
    title = _('Session Status')
    parameter_name = 'session_status'
    
    def lookups(self, request, model_admin):
        return [
            ('active', _('Active')),
            ('expired', _('Expired')),
            ('revoked', _('Revoked')),
            ('suspicious', _('Suspicious')),
        ]
    
    def queryset(self, request, queryset):
        now = timezone.now()
        if self.value() == 'active':
            return queryset.filter(status='active', expires_at__gt=now)
        elif self.value() == 'expired':
            return queryset.filter(
                Q(status='expired') | Q(expires_at__lte=now)
            )
        elif self.value() == 'revoked':
            return queryset.filter(status='revoked')
        elif self.value() == 'suspicious':
            return queryset.filter(status='suspicious')
        return queryset


# ============ INLINE ADMIN CLASSES ============

class UserProfileInline(admin.StackedInline):
    """Inline admin for UserProfile"""
    model = UserProfile
    can_delete = False
    verbose_name_plural = _('Profile')
    fieldsets = (
        (_('Contact Information'), {
            'fields': ('alternative_phone', 'emergency_contact_name', 'emergency_contact_phone')
        }),
        (_('Address Information'), {
            'fields': ('address_line1', 'address_line2', 'city', 'state', 'country', 'postal_code')
        }),
        (_('Business Information'), {
            'fields': ('business_name', 'business_registration_number', 'tax_id', 'business_description'),
            'classes': ('collapse',)
        }),
        (_('Statistics'), {
            'fields': ('average_rating', 'total_ratings', 'completed_orders'),
            'classes': ('collapse',)
        }),
        (_('Preferences'), {
            'fields': ('preferred_language', 'currency'),
            'classes': ('collapse',)
        }),
        (_('Personal Information'), {
            'fields': ('date_of_birth', 'gender'),
            'classes': ('collapse',)
        }),
    )
    readonly_fields = ('average_rating', 'total_ratings', 'completed_orders')


class ServiceInline(admin.TabularInline):
    """Inline admin for Services"""
    model = Service
    extra = 0
    fields = ('service_name', 'service_type', 'price', 'is_available', 'status')
    readonly_fields = ('service_name', 'service_type', 'price', 'is_available', 'status')
    can_delete = False
    show_change_link = True
    
    def has_add_permission(self, request, obj):
        return False


class GasCylinderInline(admin.TabularInline):
    """Inline admin for Gas Cylinders"""
    model = GasCylinder
    extra = 0
    fields = ('gas_type', 'cylinder_size', 'stock_quantity', 'price_per_unit', 'is_available')
    readonly_fields = ('gas_type', 'cylinder_size', 'stock_quantity', 'price_per_unit', 'is_available')
    can_delete = False
    show_change_link = True
    
    def has_add_permission(self, request, obj):
        return False


class ServiceAddonInline(admin.TabularInline):
    """Inline admin for Service Addons"""
    model = ServiceAddon
    extra = 1
    fields = ('name', 'description', 'price', 'is_available', 'sort_order')


class ServiceAreaInline(admin.TabularInline):
    """Inline admin for Service Areas"""
    model = ServiceArea
    extra = 1
    fields = ('area_name', 'polygon_coordinates', 'is_active')


# ============ ADMIN CLASSES ============

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Admin interface for User model"""
    
    list_display = (
        'email', 'get_full_name', 'user_type', 'email_verified',
        'is_active', 'last_login', 'created_at'
    )
    
    list_filter = (
        UserTypeFilter, 'is_active', 'email_verified', 'is_staff', 'is_superuser',
        'mfa_enabled', ('created_at', admin.DateFieldListFilter)
    )
    
    search_fields = ('email', 'first_name', 'last_name', 'phone_number', 'username')
    
    ordering = ('-created_at',)
    
    readonly_fields = (
        'last_login', 'date_joined', 'created_at', 'updated_at',
        'last_password_change', 'failed_login_attempts', 'account_locked_until', 'mfa_secret'
    )
    
    fieldsets = (
        (None, {
            'fields': ('email', 'password')
        }),
        (_('Personal Info'), {
            'fields': ('first_name', 'last_name', 'username', 'phone_number')
        }),
        (_('Account Type'), {
            'fields': ('user_type', 'cognito_user_id', 'email_verified')
        }),
        (_('Location & Profile'), {
            'fields': ('location', 'profile_picture')
        }),
        (_('Security'), {
            'fields': ('mfa_enabled',  'failed_login_attempts', 
                      'account_locked_until', 'last_login_ip', 'current_login_ip')
        }),
        (_('Session & Tokens'), {
            'fields': ('session_key', 'session_expiry',  
                      ),
            'classes': ('collapse',)
        }),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser',
                      'groups', 'user_permissions'),
            'classes': ('collapse',)
        }),
        (_('Preferences'), {
            'fields': ('preferences', 'notification_settings'),
            'classes': ('collapse',)
        }),
        (_('Important Dates'), {
            'fields': ('last_login', 'date_joined', 'created_at', 'updated_at',
                      'last_password_change'),
            'classes': ('collapse',)
        }),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'user_type'),
        }),
    )
    
    inlines = [UserProfileInline]
    
    actions = ['activate_users', 'deactivate_users', 'verify_emails', 'lock_accounts']
    
    def get_full_name(self, obj):
        return obj.get_full_name()
    get_full_name.short_description = _('Full Name')
    get_full_name.admin_order_field = 'first_name'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('profile')
    
    def activate_users(self, request, queryset):
        """Activate selected users"""
        updated = queryset.update(is_active=True)
        self.message_user(request, f'{updated} users activated.')
    activate_users.short_description = _('Activate selected users')
    
    def deactivate_users(self, request, queryset):
        """Deactivate selected users"""
        updated = queryset.update(is_active=False)
        self.message_user(request, f'{updated} users deactivated.')
    deactivate_users.short_description = _('Deactivate selected users')
    
    def verify_emails(self, request, queryset):
        """Mark selected users as email verified"""
        updated = queryset.update(email_verified=True)
        self.message_user(request, f'{updated} users marked as email verified.')
    verify_emails.short_description = _('Mark as email verified')
    
    def lock_accounts(self, request, queryset):
        """Lock selected accounts for 30 minutes"""
        from django.utils import timezone
        lock_until = timezone.now() + timedelta(minutes=30)
        updated = queryset.update(account_locked_until=lock_until)
        self.message_user(request, f'{updated} accounts locked for 30 minutes.')
    lock_accounts.short_description = _('Lock selected accounts')


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """Admin interface for UserProfile"""
    
    list_display = ('user_email', 'business_name', 'city', 'country', 'average_rating')
    list_filter = ('country', 'city', 'gender')
    search_fields = ('user__email', 'business_name', 'city', 'emergency_contact_name')
    readonly_fields = ('user_email', 'average_rating', 'total_ratings', 'completed_orders')
    
    fieldsets = (
        (_('User Information'), {
            'fields': ('user_email',)
        }),
        (_('Contact Information'), {
            'fields': ('alternative_phone', 'emergency_contact_name', 'emergency_contact_phone')
        }),
        (_('Address Information'), {
            'fields': ('address_line1', 'address_line2', 'city', 'state', 'country', 'postal_code')
        }),
        (_('Business Information'), {
            'fields': ('business_name', 'business_registration_number', 'tax_id', 'business_description')
        }),
        (_('Statistics'), {
            'fields': ('average_rating', 'total_ratings', 'completed_orders')
        }),
        (_('Preferences'), {
            'fields': ('preferred_language', 'currency')
        }),
        (_('Personal Information'), {
            'fields': ('date_of_birth', 'gender')
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = _('User Email')
    user_email.admin_order_field = 'user__email'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')


@admin.register(Vendor)
class VendorAdmin(admin.ModelAdmin):
    """Admin interface for Vendor model"""
    
    list_display = (
        'vendor_name', 'vendor_type', 'verification_status',
        'city', 'average_rating', 'total_orders', 'is_24_hours'
    )
    
    list_filter = (
        VerificationStatusFilter, 'vendor_type', 'is_24_hours',
        'accepts_emergency_calls', ('verified_at', admin.DateFieldListFilter)
    )
    
    search_fields = (
        'vendor_name', 'contact_person', 'contact_email',
        'contact_phone', 'city', 'state'
    )
    
    readonly_fields = (
        'average_rating', 'total_ratings', 'total_orders', 'total_revenue',
        'verified_at', 'created_at', 'updated_at'
    )
    
    fieldsets = (
        (_('Basic Information'), {
            'fields': ('vendor_name', 'vendor_type', 'user')
        }),
        (_('Contact Information'), {
            'fields': ('contact_person', 'contact_email', 'contact_phone', 'website')
        }),
        (_('Address Information'), {
            'fields': ('address_line1', 'address_line2', 'city', 'state', 
                      'country', 'postal_code', 'latitude', 'longitude')
        }),
        (_('Business Information'), {
            'fields': ('business_registration_number', 'tax_id', 
                      'license_number', 'license_expiry')
        }),
        (_('Verification'), {
            'fields': ('verification_status', 'verification_documents', 
                      'verified_by', 'verified_at')
        }),
        (_('Operational Information'), {
            'fields': ('opening_hours', 'is_24_hours', 'accepts_emergency_calls')
        }),
        (_('Statistics'), {
            'fields': ('average_rating', 'total_ratings', 'total_orders', 'total_revenue')
        }),
        (_('Media & Branding'), {
            'fields': ('logo', 'banner_image', 'gallery_images'),
            'classes': ('collapse',)
        }),
        (_('Additional Information'), {
            'fields': ('description', 'tags', 'amenities'),
            'classes': ('collapse',)
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    inlines = [ServiceInline, GasCylinderInline, ServiceAreaInline]
    
    actions = ['verify_vendors', 'suspend_vendors', 'export_vendor_data']
    
    def verify_vendors(self, request, queryset):
        """Verify selected vendors"""
        from django.utils import timezone
        updated = queryset.update(
            verification_status='verified',
            verified_by=request.user,
            verified_at=timezone.now()
        )
        self.message_user(request, f'{updated} vendors verified.')
    verify_vendors.short_description = _('Verify selected vendors')
    
    def suspend_vendors(self, request, queryset):
        """Suspend selected vendors"""
        updated = queryset.update(verification_status='suspended')
        self.message_user(request, f'{updated} vendors suspended.')
    suspend_vendors.short_description = _('Suspend selected vendors')
    
    def export_vendor_data(self, request, queryset):
        """Export vendor data to CSV"""
        import csv

        from django.http import HttpResponse
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="vendors.csv"'
        
        writer = csv.writer(response)
        writer.writerow([
            'Vendor Name', 'Type', 'Status', 'City', 'Contact Person',
            'Phone', 'Email', 'Rating', 'Total Orders'
        ])
        
        for vendor in queryset:
            writer.writerow([
                vendor.vendor_name,
                vendor.get_vendor_type_display(),
                vendor.get_verification_status_display(),
                vendor.city,
                vendor.contact_person,
                vendor.contact_phone,
                vendor.contact_email,
                vendor.average_rating,
                vendor.total_orders
            ])
        
        return response
    export_vendor_data.short_description = _('Export selected vendors to CSV')
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user', 'verified_by')


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    """Admin interface for Service model"""
    
    list_display = (
        'service_name', 'vendor_link', 'service_type', 'price',
        'is_available', 'total_bookings', 'average_rating'
    )
    
    list_filter = (
        ServiceTypeFilter, 'status', 'is_available',
        ('vendor__vendor_type', admin.RelatedOnlyFieldListFilter)
    )
    
    search_fields = ('service_name', 'service_code', 'description', 'vendor__vendor_name')
    
    readonly_fields = (
        'service_code', 'total_bookings', 'average_rating',
        'created_at', 'updated_at'
    )
    
    fieldsets = (
        (_('Basic Information'), {
            'fields': ('service_name', 'service_type', 'service_code', 'vendor')
        }),
        (_('Service Details'), {
            'fields': ('description', 'detailed_description')
        }),
        (_('Pricing'), {
            'fields': ('price', 'currency', 'is_price_negotiable', 'minimum_price')
        }),
        (_('Service Attributes'), {
            'fields': ('estimated_duration_minutes', 'service_radius_km')
        }),
        (_('Availability'), {
            'fields': ('status', 'is_available', 'available_from', 
                      'available_to', 'available_days')
        }),
        (_('Requirements & Constraints'), {
            'fields': ('requirements', 'constraints'),
            'classes': ('collapse',)
        }),
        (_('Media'), {
            'fields': ('service_images',),
            'classes': ('collapse',)
        }),
        (_('Statistics'), {
            'fields': ('total_bookings', 'average_rating')
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    inlines = [ServiceAddonInline]
    
    actions = ['activate_services', 'deactivate_services', 'update_prices']
    
    def vendor_link(self, obj):
        """Display vendor as link"""
        url = reverse('admin:users_vendor_change', args=[obj.vendor.id])
        return format_html('<a href="{}">{}</a>', url, obj.vendor.vendor_name)
    vendor_link.short_description = _('Vendor')
    vendor_link.admin_order_field = 'vendor__vendor_name'
    
    def activate_services(self, request, queryset):
        """Activate selected services"""
        updated = queryset.update(status='active', is_available=True)
        self.message_user(request, f'{updated} services activated.')
    activate_services.short_description = _('Activate selected services')
    
    def deactivate_services(self, request, queryset):
        """Deactivate selected services"""
        updated = queryset.update(status='inactive', is_available=False)
        self.message_user(request, f'{updated} services deactivated.')
    deactivate_services.short_description = _('Deactivate selected services')
    
    def update_prices(self, request, queryset):
        """Update prices by percentage"""
        from django.http import HttpResponseRedirect
        from django.urls import reverse
        
        # Redirect to custom form
        ids = ','.join(str(obj.id) for obj in queryset)
        return HttpResponseRedirect(
            reverse('admin:update_service_prices') + f'?ids={ids}'
        )
    update_prices.short_description = _('Update prices for selected services')
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('vendor')


@admin.register(GasCylinder)
class GasCylinderAdmin(admin.ModelAdmin):
    """Admin interface for GasCylinder model"""
    
    list_display = (
        'sku', 'vendor_link', 'gas_type', 'cylinder_size',
        'stock_quantity', 'available_quantity', 'price_per_unit', 'is_available'
    )
    
    list_filter = (
        GasTypeFilter, 'cylinder_size', 'is_available',
        ('last_inspection_date', admin.DateFieldListFilter)
    )
    
    search_fields = ('sku', 'brand', 'vendor__vendor_name', 'certification_number')
    
    readonly_fields = (
        'sku', 'available_quantity', 'created_at', 'updated_at'
    )
    
    fieldsets = (
        (_('Basic Information'), {
            'fields': ('vendor', 'gas_type', 'cylinder_size', 'sku')
        }),
        (_('Inventory'), {
            'fields': ('stock_quantity', 'reserved_quantity', 'available_quantity',
                      'minimum_stock_level', 'maximum_stock_level')
        }),
        (_('Pricing'), {
            'fields': ('price_per_unit', 'deposit_amount', 'refill_price')
        }),
        (_('Details'), {
            'fields': ('brand', 'weight_kg', 'volume_liters')
        }),
        (_('Safety & Compliance'), {
            'fields': ('last_inspection_date', 'next_inspection_date', 'certification_number')
        }),
        (_('Status'), {
            'fields': ('is_available',)
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['restock_cylinders', 'mark_for_inspection', 'export_inventory']
    
    def vendor_link(self, obj):
        """Display vendor as link"""
        url = reverse('admin:users_vendor_change', args=[obj.vendor.id])
        return format_html('<a href="{}">{}</a>', url, obj.vendor.vendor_name)
    vendor_link.short_description = _('Vendor')
    vendor_link.admin_order_field = 'vendor__vendor_name'
    
    def available_quantity(self, obj):
        return obj.available_quantity
    available_quantity.short_description = _('Available')
    available_quantity.admin_order_field = 'stock_quantity'
    
    def restock_cylinders(self, request, queryset):
        """Restock selected cylinders"""
        from django.http import HttpResponseRedirect
        from django.urls import reverse
        
        ids = ','.join(str(obj.id) for obj in queryset)
        return HttpResponseRedirect(
            reverse('admin:restock_cylinders') + f'?ids={ids}'
        )
    restock_cylinders.short_description = _('Restock selected cylinders')
    
    def mark_for_inspection(self, request, queryset):
        """Mark cylinders for inspection"""
        from django.utils import timezone
        next_month = timezone.now() + timedelta(days=30)
        updated = queryset.update(next_inspection_date=next_month.date())
        self.message_user(request, f'{updated} cylinders marked for inspection next month.')
    mark_for_inspection.short_description = _('Mark for inspection')
    
    def export_inventory(self, request, queryset):
        """Export inventory data to CSV"""
        import csv

        from django.http import HttpResponse
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="gas_inventory.csv"'
        
        writer = csv.writer(response)
        writer.writerow([
            'SKU', 'Vendor', 'Gas Type', 'Cylinder Size', 'Stock',
            'Reserved', 'Available', 'Price', 'Last Inspection'
        ])
        
        for cylinder in queryset:
            writer.writerow([
                cylinder.sku,
                cylinder.vendor.vendor_name,
                cylinder.get_gas_type_display(),
                cylinder.get_cylinder_size_display(),
                cylinder.stock_quantity,
                cylinder.reserved_quantity,
                cylinder.available_quantity,
                cylinder.price_per_unit,
                cylinder.last_inspection_date
            ])
        
        return response
    export_inventory.short_description = _('Export inventory to CSV')
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('vendor')


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    """Admin interface for UserSession model"""
    
    list_display = (
        'user_email', 'session_key_short', 'status',
        'device_type', 'ip_address', 'login_at', 'expires_at'
    )
    
    list_filter = (
        ActiveSessionFilter, 'status', 'is_mobile', 'is_tablet', 'is_desktop',
        ('login_at', admin.DateFieldListFilter)
    )
    
    search_fields = ('user__email', 'session_key', 'ip_address', 'user_agent')
    
    readonly_fields = (
        'session_key', 'refresh_token_hash', 'device_info', 'location_info',
        'login_at', 'last_activity_at', 'expires_at', 'revoked_at',
        'created_at', 'updated_at'
    )
    
    fieldsets = (
        (_('Session Information'), {
            'fields': ('user', 'session_key', 'refresh_token_hash', 'status')
        }),
        (_('Device & Location'), {
            'fields': ('user_agent', 'device_info', 'location_info',
                      'ip_address', 'is_mobile', 'is_tablet', 'is_desktop')
        }),
        (_('Timing'), {
            'fields': ('login_at', 'last_activity_at', 'expires_at',
                      'revoked_at', 'revocation_reason')
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['revoke_sessions', 'cleanup_expired_sessions']
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = _('User')
    user_email.admin_order_field = 'user__email'
    
    def session_key_short(self, obj):
        return obj.session_key[:20] + '...' if len(obj.session_key) > 20 else obj.session_key
    session_key_short.short_description = _('Session Key')
    
    def device_type(self, obj):
        if obj.is_mobile:
            return 'Mobile'
        elif obj.is_tablet:
            return 'Tablet'
        elif obj.is_desktop:
            return 'Desktop'
        return 'Unknown'
    device_type.short_description = _('Device')
    
    def revoke_sessions(self, request, queryset):
        """Revoke selected sessions"""
        from django.utils import timezone
        updated = queryset.update(
            status='revoked',
            revoked_at=timezone.now(),
            revocation_reason='Admin action'
        )
        self.message_user(request, f'{updated} sessions revoked.')
    revoke_sessions.short_description = _('Revoke selected sessions')
    
    def cleanup_expired_sessions(self, request, queryset):
        """Mark expired sessions as expired"""
        now = timezone.now()
        expired = queryset.filter(expires_at__lte=now).exclude(status='expired')
        updated = expired.update(status='expired')
        self.message_user(request, f'{updated} sessions marked as expired.')
    cleanup_expired_sessions.short_description = _('Cleanup expired sessions')
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Admin interface for AuditLog model"""
    
    list_display = (
    'action', 'resource_type', 'user_email',
    'ip_address', 'created_at', 'status_code' 
)
    list_filter = (
        'action', 'resource_type', 'status_code',
        ('created_at', admin.DateFieldListFilter)
    )
    
    search_fields = (
        'user__email', 'resource_type', 'action',
        'ip_address', 'request_path'
    )
    
    readonly_fields = (
        'action', 'resource_type', 'resource_id', 'user',
        'user_session', 'old_data', 'new_data', 'changes',
        'ip_address', 'user_agent', 'request_path', 'request_method',
        'status_code', 'error_message', 'duration_ms', 
    )
    
    fieldsets = (
        (_('Action Details'), {
            'fields': ('action', 'resource_type', 'resource_id')
        }),
        (_('User Information'), {
            'fields': ('user', 'user_session')
        }),
        (_('Data Changes'), {
            'fields': ('old_data', 'new_data', 'changes'),
            'classes': ('collapse',)
        }),
        (_('Request Context'), {
            'fields': ('ip_address', 'user_agent', 'request_path', 'request_method')
        }),
        (_('Response Information'), {
            'fields': ('status_code', 'error_message', 'duration_ms')
        }),
        (_('Timing'), {
            'fields': ('timestamp',),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['export_audit_logs', 'cleanup_old_logs']
    
    def user_email(self, obj):
        return obj.user.email if obj.user else 'System'
    user_email.short_description = _('User')
    user_email.admin_order_field = 'user__email'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser
    
    def export_audit_logs(self, request, queryset):
        """Export audit logs to CSV"""
        import csv

        from django.http import HttpResponse
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="audit_logs.csv"'
        
        writer = csv.writer(response)
        writer.writerow([
            'Timestamp', 'Action', 'Resource Type', 'User',
            'IP Address', 'Status Code', 'Request Path'
        ])
        
        for log in queryset:
            writer.writerow([
                log.timestamp,
                log.action,
                log.resource_type,
                log.user.email if log.user else 'System',
                log.ip_address,
                log.status_code,
                log.request_path
            ])
        
        return response
    export_audit_logs.short_description = _('Export selected logs to CSV')
    
    def cleanup_old_logs(self, request, queryset):
        """Delete logs older than 90 days"""
        from datetime import timedelta

        from django.utils import timezone
        
        cutoff_date = timezone.now() - timedelta(days=90)
        old_logs = queryset.filter(timestamp__lt=cutoff_date)
        deleted_count, _ = old_logs.delete()
        
        self.message_user(
            request,
            f'{deleted_count} logs older than 90 days deleted.'
        )
    cleanup_old_logs.short_description = _('Cleanup logs older than 90 days')


# ============ ADMIN SITE CONFIGURATION ============

class ZenoAdminSite(admin.AdminSite):
    """Custom admin site for Zeno"""
    
    site_header = _('Zeno Services Administration')
    site_title = _('Zeno Admin')
    index_title = _('Dashboard')
    
    def get_app_list(self, request):
        """
        Customize the app list ordering
        """
        app_list = super().get_app_list(request)
        
        # Reorder apps
        ordered_apps = []
        for app in app_list:
            if app['app_label'] == 'users':
                ordered_apps.insert(0, app)  # Users first
            elif app['app_label'] == 'vendors':
                ordered_apps.append(app)
            elif app['app_label'] == 'services':
                ordered_apps.append(app)
            else:
                ordered_apps.append(app)
        
        return ordered_apps


# ============ REGISTER MODELS ============

# Note: Unregister default Group if not needed
# admin.site.unregister(Group)

# Register additional models if not already registered
admin.site.register(ServiceAddon)
admin.site.register(ServiceArea)


# ============ CUSTOM ADMIN VIEWS ============

from django import forms
from django.contrib import messages
from django.shortcuts import render
from django.urls import path


class PriceUpdateForm(forms.Form):
    """Form for updating service prices"""
    percentage_change = forms.DecimalField(
        label='Percentage Change',
        help_text='Enter positive number to increase, negative to decrease',
        min_value=-100,
        max_value=100,
        decimal_places=2
    )


def update_service_prices_view(request):
    """Custom view for updating service prices"""
    service_ids = request.GET.get('ids', '').split(',')
    services = Service.objects.filter(id__in=service_ids)
    
    if request.method == 'POST':
        form = PriceUpdateForm(request.POST)
        if form.is_valid():
            percentage = form.cleaned_data['percentage_change']
            factor = 1 + (percentage / 100)
            
            updated_count = 0
            for service in services:
                old_price = service.price
                new_price = old_price * factor
                service.price = new_price
                service.save()
                updated_count += 1
            
            messages.success(
                request,
                f'Updated prices for {updated_count} services by {percentage}%'
            )
            
            # Redirect back to services admin
            from django.urls import reverse
            return redirect(reverse('admin:users_service_changelist'))
    else:
        form = PriceUpdateForm()
    
    context = {
        'title': 'Update Service Prices',
        'form': form,
        'services': services,
        'service_count': services.count(),
    }
    
    return render(request, 'admin/update_service_prices.html', context)


# Add custom views to admin
admin_site = admin.site
