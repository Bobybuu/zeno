# services/admin.py
from django.contrib import admin
from .models import ServiceCategory, Service, ServiceImage

@admin.register(ServiceCategory)
class ServiceCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'description']
    list_filter = ['name']
    search_fields = ['name']

@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ['name', 'vendor', 'category', 'price', 'available']
    list_filter = ['category', 'available', 'vendor__business_type']
    search_fields = ['name', 'vendor__business_name']
    readonly_fields = ['created_at', 'updated_at']

admin.site.register(ServiceImage)