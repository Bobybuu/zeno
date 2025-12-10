# orders/admin.py
from django.contrib import admin
from .models import Order, OrderTracking, Cart, CartItem, OrderItem

@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ['id', 'customer', 'vendor', 'order_type', 'total_amount', 'status', 'payment_status', 'created_at']
    list_filter = ['status', 'payment_status', 'order_type', 'delivery_type', 'created_at']
    search_fields = ['customer__email', 'vendor__business_name', 'delivery_address']
    readonly_fields = ['created_at', 'updated_at', 'confirmed_at', 'completed_at']
    actions = ['mark_as_completed', 'mark_as_cancelled']
    
    def mark_as_completed(self, request, queryset):
        queryset.update(status='completed')
    mark_as_completed.short_description = "Mark selected orders as completed"
    
    def mark_as_cancelled(self, request, queryset):
        queryset.update(status='cancelled')
    mark_as_cancelled.short_description = "Mark selected orders as cancelled"

@admin.register(OrderTracking)
class OrderTrackingAdmin(admin.ModelAdmin):
    list_display = ['order', 'status', 'created_at']
    list_filter = ['status', 'created_at']
    readonly_fields = ['created_at']
    search_fields = ['order__id', 'note']

@admin.register(Cart)
class CartAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'item_count', 'total_amount', 'created_at']
    list_filter = ['created_at']
    readonly_fields = ['created_at', 'updated_at']
    search_fields = ['user__email', 'user__username']

@admin.register(CartItem)
class CartItemAdmin(admin.ModelAdmin):
    list_display = ['id', 'cart', 'item_type', 'item_name', 'quantity', 'unit_price', 'total_price', 'added_at']
    list_filter = ['item_type', 'added_at']
    readonly_fields = ['added_at']
    search_fields = ['cart__user__email', 'service__name', 'gas_product__name']

@admin.register(OrderItem)
class OrderItemAdmin(admin.ModelAdmin):
    list_display = ['id', 'order', 'item_type', 'item_name', 'quantity', 'unit_price', 'total_price']
    list_filter = ['item_type']
    search_fields = ['order__id', 'service__name', 'gas_product__name']

    def item_name(self, obj):
        if obj.service:
            return obj.service.name
        elif obj.gas_product:
            return obj.gas_product.name
        return "Unknown Item"
    item_name.short_description = 'Item Name'