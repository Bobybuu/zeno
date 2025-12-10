# services/serializers.py
from rest_framework import serializers
from .models import ServiceCategory, Service, ServiceImage

class ServiceImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceImage
        fields = ['id', 'image', 'is_primary']

class ServiceSerializer(serializers.ModelSerializer):
    images = ServiceImageSerializer(many=True, read_only=True)
    vendor_name = serializers.CharField(source='vendor.business_name', read_only=True)
    vendor_type = serializers.CharField(source='vendor.business_type', read_only=True)
    vendor_contact = serializers.CharField(source='vendor.contact_number', read_only=True)
    vendor_address = serializers.CharField(source='vendor.address', read_only=True)
    vendor_latitude = serializers.DecimalField(source='vendor.latitude', read_only=True, max_digits=9, decimal_places=6)
    vendor_longitude = serializers.DecimalField(source='vendor.longitude', read_only=True, max_digits=9, decimal_places=6)
    
    class Meta:
        model = Service
        fields = [
            'id', 'vendor', 'vendor_name', 'vendor_type', 'vendor_contact', 
            'vendor_address', 'vendor_latitude', 'vendor_longitude',
            'category', 'name', 'description', 'price', 'available', 
            'images', 'created_at'
        ]

class ServiceCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceCategory
        fields = ['id', 'name', 'description', 'icon']

class ServiceCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = ['category', 'name', 'description', 'price', 'available']