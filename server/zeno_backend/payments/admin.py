# payments/admin.py
from django.contrib import admin
from .models import Payment, MpesaConfiguration

@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ['id', 'order', 'amount', 'payment_method', 'status', 'created_at']
    list_filter = ['status', 'payment_method', 'created_at']
    search_fields = ['order__id', 'mpesa_receipt_number', 'phone_number']
    readonly_fields = ['created_at', 'updated_at', 'transaction_date']
    
    def has_add_permission(self, request):
        return False  # Payments should only be created through the API

@admin.register(MpesaConfiguration)
class MpesaConfigurationAdmin(admin.ModelAdmin):
    list_display = ['environment', 'shortcode', 'callback_url', 'is_active']
    list_editable = ['is_active']
    
    def has_add_permission(self, request):
        # Only allow one active configuration
        if MpesaConfiguration.objects.filter(is_active=True).exists():
            return False
        return True