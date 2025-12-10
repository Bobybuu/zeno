# vendors/admin.py
from django.contrib import admin
from .models import Vendor, GasProduct, GasProductImage, GasPriceHistory, VendorReview, OperatingHours

@admin.register(Vendor)
class VendorAdmin(admin.ModelAdmin):
    list_display = ['business_name', 'business_type', 'city', 'is_verified', 'is_active', 'total_gas_products']
    list_filter = ['business_type', 'city', 'is_verified', 'is_active']
    search_fields = ['business_name', 'city', 'contact_number']
    readonly_fields = ['average_rating', 'total_reviews', 'created_at', 'updated_at']

@admin.register(GasProduct)
class GasProductAdmin(admin.ModelAdmin):
    list_display = ['name', 'vendor', 'gas_type', 'cylinder_size', 'price_with_cylinder', 'price_without_cylinder', 'stock_quantity', 'is_available']
    list_filter = ['gas_type', 'cylinder_size', 'is_available', 'vendor__business_name']
    search_fields = ['name', 'vendor__business_name', 'brand']
    readonly_fields = ['created_at', 'updated_at']
    actions = ['mark_as_featured', 'update_stock']

    def mark_as_featured(self, request, queryset):
        queryset.update(featured=True)
    mark_as_featured.short_description = "Mark selected products as featured"

    def update_stock(self, request, queryset):
        # Custom stock update action
        pass

admin.site.register(GasProductImage)
admin.site.register(GasPriceHistory)
admin.site.register(VendorReview)
admin.site.register(OperatingHours)