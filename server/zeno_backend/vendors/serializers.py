# vendors/serializers.py
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.db import models
from .models import Vendor, VendorReview, OperatingHours, GasProduct, GasProductImage, GasPriceHistory

User = get_user_model()

class GasProductImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = GasProductImage
        fields = ['id', 'image', 'alt_text', 'is_primary', 'created_at']
        read_only_fields = ['id', 'created_at']

class GasPriceHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = GasPriceHistory
        fields = ['id', 'price_with_cylinder', 'price_without_cylinder', 'effective_date', 'created_at']
        read_only_fields = ['id', 'created_at']

class GasProductListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for product listings"""
    vendor_name = serializers.CharField(source='vendor.business_name', read_only=True)
    in_stock = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = GasProduct
        fields = [
            'id', 'name', 'gas_type', 'cylinder_size', 'vendor_name',
            'price_with_cylinder', 'price_without_cylinder', 'in_stock',
            'is_available', 'featured'
        ]

class GasProductSerializer(serializers.ModelSerializer):
    images = GasProductImageSerializer(many=True, read_only=True)
    price_history = GasPriceHistorySerializer(many=True, read_only=True)
    vendor_name = serializers.CharField(source='vendor.business_name', read_only=True)
    vendor_city = serializers.CharField(source='vendor.city', read_only=True)
    
    # Computed fields
    in_stock = serializers.BooleanField(read_only=True)
    low_stock = serializers.BooleanField(read_only=True)
    cylinder_deposit = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    
    class Meta:
        model = GasProduct
        fields = [
            'id', 'vendor', 'vendor_name', 'vendor_city', 'name', 'gas_type', 
            'cylinder_size', 'brand', 'price_with_cylinder', 'price_without_cylinder',
            'cylinder_deposit', 'stock_quantity', 'min_stock_alert', 'description',
            'ingredients', 'safety_instructions', 'is_available', 'is_active',
            'featured', 'in_stock', 'low_stock', 'images', 'price_history',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['vendor', 'created_at', 'updated_at', 'cylinder_deposit']

class GasProductCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = GasProduct
        fields = [
            'name', 'gas_type', 'cylinder_size', 'brand', 'price_with_cylinder',
            'price_without_cylinder', 'stock_quantity', 'min_stock_alert', 'description',
            'ingredients', 'safety_instructions', 'featured'
        ]
    
    def validate(self, data):
        # Validate that price_with_cylinder is greater than price_without_cylinder
        price_with = data.get('price_with_cylinder')
        price_without = data.get('price_without_cylinder')
        
        if price_with and price_without and price_with <= price_without:
            raise serializers.ValidationError({
                'price_with_cylinder': 'Price with cylinder must be greater than price without cylinder'
            })
        
        return data

class GasProductUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = GasProduct
        fields = [
            'name', 'brand', 'price_with_cylinder', 'price_without_cylinder',
            'stock_quantity', 'min_stock_alert', 'description', 'ingredients',
            'safety_instructions', 'is_active', 'featured'
        ]
    
    def update(self, instance, validated_data):
        # Create price history if prices changed
        price_changed = (
            'price_with_cylinder' in validated_data and 
            validated_data['price_with_cylinder'] != instance.price_with_cylinder
        ) or (
            'price_without_cylinder' in validated_data and 
            validated_data['price_without_cylinder'] != instance.price_without_cylinder
        )
        
        if price_changed:
            GasPriceHistory.objects.create(
                product=instance,
                price_with_cylinder=instance.price_with_cylinder,
                price_without_cylinder=instance.price_without_cylinder
            )
        
        return super().update(instance, validated_data)

class GasProductStockUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = GasProduct
        fields = ['stock_quantity', 'min_stock_alert']

class OperatingHoursSerializer(serializers.ModelSerializer):
    class Meta:
        model = OperatingHours
        fields = ['id', 'day', 'opening_time', 'closing_time', 'is_closed']

class VendorReviewSerializer(serializers.ModelSerializer):
    customer_name = serializers.CharField(source='customer.get_full_name', read_only=True)
    customer_username = serializers.CharField(source='customer.username', read_only=True)
    
    class Meta:
        model = VendorReview
        fields = ['id', 'customer', 'customer_name', 'customer_username', 'rating', 'comment', 'created_at']
        read_only_fields = ['customer', 'created_at']

class VendorLocationSerializer(serializers.ModelSerializer):
    """Minimal serializer for map displays"""
    class Meta:
        model = Vendor
        fields = ['id', 'business_name', 'latitude', 'longitude', 'city', 'address']

class VendorWithProductsSerializer(serializers.ModelSerializer):
    """Serializer for vendor detail page with products"""
    gas_products = GasProductListSerializer(many=True, read_only=True)
    
    class Meta:
        model = Vendor
        fields = [
            'id', 'business_name', 'business_type', 'description', 'address',
            'city', 'contact_number', 'average_rating', 'delivery_radius_km',
            'delivery_fee', 'gas_products', 'operating_hours'
        ]

class VendorListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for vendor listings"""
    gas_products_count = serializers.SerializerMethodField()  # ✅ FIXED: Use SerializerMethodField
    
    class Meta:
        model = Vendor
        fields = [
            'id', 'business_name', 'business_type', 'city', 'address',
            'contact_number', 'average_rating', 'total_reviews', 'is_verified',
            'gas_products_count', 'delivery_radius_km', 'delivery_fee'
        ]
    
    def get_gas_products_count(self, obj):
        # ✅ FIXED: Return integer count instead of QuerySet
        return obj.gas_products.count()

class VendorDashboardSerializer(serializers.ModelSerializer):
    """Serializer for vendor dashboard with product statistics"""
    total_products = serializers.SerializerMethodField()  # ✅ FIXED: Use SerializerMethodField
    available_products = serializers.SerializerMethodField()
    low_stock_products = serializers.SerializerMethodField()
    out_of_stock_products = serializers.SerializerMethodField()
    
    class Meta:
        model = Vendor
        fields = [
            'id', 'business_name', 'total_products', 'available_products',
            'low_stock_products', 'out_of_stock_products', 'average_rating',
            'total_reviews', 'is_verified'
        ]
    
    def get_total_products(self, obj):
        # ✅ FIXED: Return integer count instead of QuerySet
        return obj.gas_products.count()
    
    def get_available_products(self, obj):
        return obj.gas_products.filter(stock_quantity__gt=0, is_active=True).count()
    
    def get_low_stock_products(self, obj):
        return obj.gas_products.filter(
            stock_quantity__gt=0, 
            stock_quantity__lte=models.F('min_stock_alert'),
            is_active=True
        ).count()
    
    def get_out_of_stock_products(self, obj):
        return obj.gas_products.filter(stock_quantity=0, is_active=True).count()

class VendorSerializer(serializers.ModelSerializer):
    operating_hours = OperatingHoursSerializer(many=True, read_only=True)
    reviews = VendorReviewSerializer(many=True, read_only=True)
    owner_name = serializers.CharField(source='user.get_full_name', read_only=True)
    owner_email = serializers.CharField(source='user.email', read_only=True)
    
    # Gas products related fields - ✅ FIXED: Use SerializerMethodField for counts
    gas_products = GasProductListSerializer(many=True, read_only=True)
    total_gas_products = serializers.SerializerMethodField()
    available_gas_products = serializers.SerializerMethodField()
    
    class Meta:
        model = Vendor
        fields = [
            'id', 'user', 'owner_name', 'owner_email', 'business_name', 'business_type',
            'description', 'latitude', 'longitude', 'address', 'city', 'country',
            'contact_number', 'email', 'website', 'opening_hours', 'is_verified',
            'is_active', 'average_rating', 'total_reviews', 'operating_hours',
            'reviews', 'delivery_radius_km', 'min_order_amount', 'delivery_fee',
            'gas_products', 'total_gas_products', 'available_gas_products',
            'created_at'
        ]
        read_only_fields = [
            'user', 'average_rating', 'total_reviews', 'is_verified',
            'total_gas_products', 'available_gas_products'
        ]
    
    def get_total_gas_products(self, obj):
        # ✅ FIXED: Return integer count instead of QuerySet
        return obj.gas_products.count()
    
    def get_available_gas_products(self, obj):
        # ✅ FIXED: Return integer count instead of QuerySet
        return obj.gas_products.filter(stock_quantity__gt=0, is_active=True).count()

class VendorCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor
        fields = [
            'business_name', 'business_type', 'description', 'latitude', 'longitude',
            'address', 'city', 'country', 'contact_number', 'email', 'website',
            'delivery_radius_km', 'min_order_amount', 'delivery_fee'
        ]

class VendorUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor
        fields = [
            'business_name', 'description', 'latitude', 'longitude', 'address',
            'city', 'contact_number', 'email', 'website', 'opening_hours',
            'delivery_radius_km', 'min_order_amount', 'delivery_fee'
        ]

# Optional: Serializers for specific use cases
class VendorMinimalSerializer(serializers.ModelSerializer):
    """Minimal serializer for basic vendor info - useful for testing"""
    class Meta:
        model = Vendor
        fields = [
            'id', 'business_name', 'business_type', 'description',
            'latitude', 'longitude', 'address', 'city', 'country',
            'contact_number', 'email', 'is_verified', 'is_active',
            'average_rating', 'total_reviews'
        ]

class GasProductDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for individual gas product pages"""
    vendor_name = serializers.CharField(source='vendor.business_name', read_only=True)
    vendor_address = serializers.CharField(source='vendor.address', read_only=True)
    vendor_contact = serializers.CharField(source='vendor.contact_number', read_only=True)
    vendor_city = serializers.CharField(source='vendor.city', read_only=True)
    in_stock = serializers.BooleanField(read_only=True)
    low_stock = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = GasProduct
        fields = [
            'id', 'name', 'gas_type', 'cylinder_size', 'brand',
            'price_with_cylinder', 'price_without_cylinder', 'stock_quantity',
            'min_stock_alert', 'description', 'ingredients', 'safety_instructions',
            'is_available', 'is_active', 'featured', 'in_stock', 'low_stock',
            'vendor_name', 'vendor_address', 'vendor_contact', 'vendor_city',
            'created_at', 'updated_at'
        ]